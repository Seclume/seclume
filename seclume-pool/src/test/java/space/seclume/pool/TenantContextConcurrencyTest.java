package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CyclicBarrier;
import java.util.stream.LongStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import space.seclume.SessionContext;

/**
 * A tenant's session context - what a row-level security policy filters by -
 * on a pool that several requests borrow from at once, each for another
 * tenant. The promises, checked on every borrow of every thread:
 *
 * <ul>
 *   <li>a borrowed connection carries the borrower's tenant, and nothing
 *       else: not the tenant of the request before, not a value the request
 *       before set itself;</li>
 *   <li>no connection is held by two borrowers at once;</li>
 *   <li>a connection whose reset was refused is never lent again - it may
 *       still hold the tenant before;</li>
 *   <li>a connection that cannot take a context is not lent at all.</li>
 * </ul>
 *
 * <p>The server is a stub that keeps the context as a server would, and a
 * reset that clears it - and refuses now and then. Thread scheduling is not
 * reproducible; the seed fixes the choices. {@code -Dseclume.pool.tenant.seeds=N}
 * runs more.
 */
@Timeout(300)
class TenantContextConcurrencyTest {

    private static final int BORROWERS = 6;
    private static final int BORROWS = 200;
    private static final String TENANT = "app.tenant_id";

    static LongStream seeds() {
        return LongStream.range(0, Long.getLong("seclume.pool.tenant.seeds", 12));
    }

    /** A reset that clears the context - and refuses when told to. */
    private static final class ClearingReset implements space.seclume.SessionReset {
        final StubDataSource.StubConnection stub;
        volatile boolean refuse;
        volatile boolean refused;

        ClearingReset(StubDataSource.StubConnection stub) {
            this.stub = stub;
        }

        @Override
        public boolean sessionStateChanged() {
            // As a driver does: it saw the context go out.
            return !stub.context.isEmpty();
        }

        @Override
        public boolean resetSessionState() {
            if (refuse) {
                refused = true;
                return false;
            }
            stub.context.clear();
            return true;
        }
    }

    @ParameterizedTest(name = "seed {0}")
    @MethodSource("seeds")
    void everyBorrowCarriesItsOwnTenantAndNoOneElses(long seed) throws Exception {
        StubDataSource source = new StubDataSource();
        Map<StubDataSource.StubConnection, ClearingReset> resets = new ConcurrentHashMap<>();
        source.beforeReturn((StubDataSource.StubConnection newest) -> {
            newest.takesContext = true;
            ClearingReset reset = new ClearingReset(newest);
            newest.sessionReset = reset;
            resets.put(newest, reset);
        });
        ThreadLocal<String> tenant = new ThreadLocal<>();
        PoolSettings settings = new PoolSettings();
        settings.setName("tenants");
        settings.setMaximumPoolSize(1 + (int) (seed % 3));
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofSeconds(30));
        settings.setShutdownTimeout(Duration.ZERO);
        settings.setSessionContext(() -> tenant.get() == null ? Map.of() : Map.of(TENANT, tenant.get()));

        List<String> violations = Collections.synchronizedList(new ArrayList<>());
        Map<StubDataSource.StubConnection, Thread> holders = new ConcurrentHashMap<>();
        CyclicBarrier start = new CyclicBarrier(BORROWERS);
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            List<Thread> threads = new ArrayList<>();
            for (int t = 0; t < BORROWERS; t++) {
                int borrower = t;
                Random random = new Random(seed * 31 + t);
                threads.add(Thread.ofPlatform().start(() -> {
                    try {
                        start.await();
                        for (int i = 0; i < BORROWS && violations.isEmpty(); i++) {
                            // Now and then a request without a tenant: it must get none.
                            String mine = random.nextInt(5) == 0 ? null
                                    : "tenant-" + borrower + "-" + i;
                            if (mine == null) {
                                tenant.remove();
                            } else {
                                tenant.set(mine);
                            }
                            borrowOnce(pool, mine, random, holders, resets, violations);
                        }
                    } catch (Throwable e) {
                        violations.add("borrower " + borrower + ": " + e);
                    } finally {
                        tenant.remove();
                    }
                }));
            }
            for (Thread thread : threads) {
                thread.join();
            }
        }
        assertEquals(List.of(), violations.stream().limit(5).toList(), "seed " + seed);
        for (ClearingReset reset : resets.values()) {
            if (reset.refused) {
                assertTrue(reset.stub.closed.get(), "seed " + seed + ": a refused reset's "
                        + "connection was left open");
            }
        }
    }

    private static void borrowOnce(SeclumePool pool, String mine, Random random,
                                   Map<StubDataSource.StubConnection, Thread> holders,
                                   Map<StubDataSource.StubConnection, ClearingReset> resets,
                                   List<String> violations) throws SQLException {
        try (Connection connection = pool.getConnection()) {
            if (random.nextInt(4) == 0) {
                return;                // a request that runs nothing - its context goes all the same
            }
            StubDataSource.StubConnection stub =
                    connection.unwrap(StubDataSource.StubContext.class).stub();
            Thread before = holders.putIfAbsent(stub, Thread.currentThread());
            if (before != null) {
                violations.add(mine + ": the connection is held by " + before.getName() + " too");
                return;
            }
            try {
                ClearingReset reset = resets.get(stub);
                if (reset != null && reset.refused) {
                    violations.add(mine + ": lent a connection whose reset was refused");
                }
                Map<String, String> context = Map.copyOf(stub.context);
                if (!context.equals(mine == null ? Map.of() : Map.of(TENANT, mine))) {
                    violations.add(mine + ": borrowed with " + context);
                }
                // What a request may set itself; it must not reach the next one.
                if (random.nextInt(3) == 0) {
                    connection.unwrap(SessionContext.class)
                            .setSessionContext("app.user", "user-of-" + borrowerName());
                }
                if (reset != null && random.nextInt(25) == 0) {
                    reset.refuse = true;
                }
                if (random.nextInt(4) == 0) {
                    Thread.onSpinWait();
                }
            } finally {
                holders.remove(stub);
            }
        }
    }

    private static String borrowerName() {
        return Thread.currentThread().getName();
    }

    @Test
    void aConnectionThatCannotTakeAContextIsNotLent() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = new PoolSettings();
        settings.setName("no-context");
        settings.setMaximumPoolSize(1);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofMillis(200));
        settings.setShutdownTimeout(Duration.ZERO);
        settings.setSessionContext(() -> Map.of(TENANT, "42"));
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            assertThrows(SQLException.class, pool::getConnection);
            assertTrue(source.handedOut().stream().allMatch(stub -> stub.closed.get()),
                    "a connection without the tenant's context was kept");
        }
    }

    @Test
    void aBorrowWithoutATenantCarriesNoneLeftOverFromOneThatRanNothing() throws Exception {
        StubDataSource source = new StubDataSource();
        source.beforeReturn((StubDataSource.StubConnection newest) -> {
            newest.takesContext = true;
            newest.sessionReset = new ClearingReset(newest);
        });
        ThreadLocal<String> tenant = new ThreadLocal<>();
        PoolSettings settings = new PoolSettings();
        settings.setName("then-none");
        settings.setMaximumPoolSize(1);
        settings.setMinimumIdle(0);
        settings.setShutdownTimeout(Duration.ZERO);
        settings.setSessionContext(() -> tenant.get() == null ? Map.of() : Map.of(TENANT, tenant.get()));
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            tenant.set("7");
            try (Connection first = pool.getConnection()) {
                // Nothing run: the context went out all the same, and is reset all the same.
                assertTrue(!first.isClosed());
                assertEquals(Map.of(TENANT, "7"), source.handedOut().get(0).context);
            }
            assertEquals(Map.of(), source.handedOut().get(0).context,
                    "returned with the tenant still set");
            tenant.remove();
            try (Connection second = pool.getConnection()) {
                StubDataSource.StubConnection stub =
                        second.unwrap(StubDataSource.StubContext.class).stub();
                assertEquals(Map.of(), stub.context, "the tenant before was still set");
                assertEquals(Set.of(stub), Set.copyOf(source.handedOut()), "one connection, reused");
            }
        }
    }
}
