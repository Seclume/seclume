package space.seclume.r2dbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.PrintWriter;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import reactor.core.publisher.Mono;
import reactor.util.context.Context;
import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;

/**
 * Under R2DBC the pool's session-context supplier was asked on whichever
 * thread borrowed: the subscriber's when a connection was free, a thread of
 * the pool's when it had to wait. Neither sees the Reactor context, where a
 * reactive application keeps its tenant - the same request had it at low load
 * and lost it under load. A ReactiveSessionContext is resolved on the
 * subscriber and handed to the pool by name, on both paths.
 */
@Timeout(30)
class ReactiveSessionContextTest {

    /** Every setSessionContext the driver was asked for, as name=value. */
    private final List<String> set = new CopyOnWriteArrayList<>();

    private final space.seclume.SessionContext writer =
            (name, value) -> set.add(name + "=" + value);

    private Connection connection() {
        DatabaseMetaData meta = (DatabaseMetaData) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[] {DatabaseMetaData.class},
                (self, method, args) -> switch (method.getName()) {
                    case "getDatabaseProductName" -> "PostgreSQL";
                    case "getDatabaseProductVersion" -> "17.0";
                    default -> defaultFor(method.getReturnType());
                });
        return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[] {Connection.class}, (self, method, args) -> switch (method.getName()) {
                    case "isWrapperFor" -> args[0] == space.seclume.SessionContext.class;
                    case "unwrap" -> args[0] == space.seclume.SessionContext.class ? writer : null;
                    case "isValid", "getAutoCommit" -> true;
                    case "isClosed" -> false;
                    case "getTransactionIsolation" -> Connection.TRANSACTION_READ_COMMITTED;
                    case "getMetaData" -> meta;
                    case "hashCode" -> System.identityHashCode(self);
                    case "equals" -> self == args[0];
                    default -> defaultFor(method.getReturnType());
                });
    }

    private static Object defaultFor(Class<?> type) {
        if (type == boolean.class) {
            return false;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        return null;
    }

    private DataSource source() {
        return new DataSource() {
            @Override
            public Connection getConnection() {
                return connection();
            }

            @Override
            public Connection getConnection(String user, String password) {
                throw new UnsupportedOperationException();
            }

            @Override
            public PrintWriter getLogWriter() {
                return null;
            }

            @Override
            public void setLogWriter(PrintWriter out) {
            }

            @Override
            public void setLoginTimeout(int seconds) {
            }

            @Override
            public int getLoginTimeout() {
                return 0;
            }

            @Override
            public Logger getParentLogger() {
                return Logger.getGlobal();
            }

            @Override
            public <T> T unwrap(Class<T> type) {
                return null;
            }

            @Override
            public boolean isWrapperFor(Class<?> type) {
                return false;
            }
        };
    }

    private static final ReactiveSessionContext FROM_REACTOR = () -> Mono.deferContextual(
            view -> Mono.just(Map.of("app.tenant_id", view.<String>get("tenant"))));

    private static io.r2dbc.spi.Connection borrow(SeclumeConnectionFactory factory, String tenant) {
        return factory.create().contextWrite(Context.of("tenant", tenant)).block();
    }

    private static void close(io.r2dbc.spi.Connection connection) {
        Mono.from(connection.close()).block();
    }

    @Test
    void theTenantComesFromTheReactorContextOnBothPaths() throws Exception {
        AtomicInteger threadAsked = new AtomicInteger();
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(1);
        settings.setConnectionTimeout(Duration.ofSeconds(10));
        settings.setValidationBypassWindow(Duration.ofMinutes(5));
        settings.setSessionContext(() -> {
            threadAsked.incrementAndGet();
            return Map.of("app.tenant_id", "whoever-the-thread-was");
        });
        try (SeclumePool pool = new SeclumePool(source(), settings)) {
            SeclumeConnectionFactory factory = SeclumeConnectionFactory.over(pool, "postgresql")
                    .withSessionContext(FROM_REACTOR);

            close(borrow(factory, "acme"));                    // free: the subscriber's thread

            io.r2dbc.spi.Connection held = borrow(factory, "globex");
            Mono<io.r2dbc.spi.Connection> waiting = factory.create()
                    .contextWrite(Context.of("tenant", "initech"));
            var later = waiting.toFuture();                     // waits: the pool's thread
            Thread.sleep(200);
            close(held);
            close(later.get());

            assertEquals(List.of("app.tenant_id=acme", "app.tenant_id=globex",
                    "app.tenant_id=initech"), set);
            assertEquals(0, threadAsked.get(), "the thread's supplier was asked");
        }
    }

    @Test
    void aContextThatFailsTakesNoConnection() throws Exception {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(1);
        settings.setConnectionTimeout(Duration.ofSeconds(2));
        try (SeclumePool pool = new SeclumePool(source(), settings)) {
            SeclumeConnectionFactory factory = SeclumeConnectionFactory.over(pool, "postgresql")
                    .withSessionContext(() -> Mono.error(new IllegalStateException("no tenant")));
            assertThrows(IllegalStateException.class, () -> factory.create().block());
            SeclumeConnectionFactory plain = SeclumeConnectionFactory.over(pool, "postgresql");
            close(plain.create().block());                      // the one connection is still there
        }
    }
}
