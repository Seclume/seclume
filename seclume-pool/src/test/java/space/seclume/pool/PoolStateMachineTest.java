package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.stream.LongStream;

import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import space.seclume.SessionReset;

/**
 * The pool driven through random sequences of what applications and servers
 * do - borrow, use, return, leave statements open, break, refuse a reset,
 * answer a reset late, suspend, resume - with its promises checked after
 * every step:
 * <ul>
 *   <li>no connection is lent while the reset of its last use is unconfirmed;</li>
 *   <li>a connection whose reset was refused is never lent again;</li>
 *   <li>no connection is lent to two holders at once;</li>
 *   <li>{@code activeCount()} is the number of handles held;</li>
 *   <li>every connection is closed once the pool is.</li>
 * </ul>
 *
 * <p>Each seed is one reproducible sequence; a failure names the seed and the
 * steps that led to it. {@code -Dseclume.pool.stateMachine.seeds=N} runs more
 * of them, as the nightly fuzz job does.
 */
@Timeout(120)
class PoolStateMachineTest {

    private static final int STEPS = 400;

    static LongStream seeds() {
        return LongStream.range(0, Long.getLong("seclume.pool.stateMachine.seeds", 150));
    }

    /** A reset whose answer, refusal and timing the sequence decides. */
    private static final class ModelReset implements SessionReset {
        boolean owed;
        boolean answered;
        boolean refuseNext;
        boolean cannotReset;
        boolean refused;
        int settled;

        @Override
        public boolean sessionStateChanged() {
            return false;
        }

        @Override
        public boolean resetSessionState() {
            if (cannotReset) {
                return false;
            }
            owed = true;
            answered = false;
            return true;
        }

        @Override
        public boolean resetOwed() {
            return owed;
        }

        @Override
        public boolean resetAnswered() {
            return !owed || answered;
        }

        @Override
        public void settleReset() throws SQLException {
            if (!owed) {
                return;
            }
            owed = false;
            settled++;
            if (refuseNext) {
                refused = true;
                throw new SQLException("the reset was refused", "08006");
            }
        }
    }

    @ParameterizedTest(name = "seed {0}")
    @MethodSource("seeds")
    void thePromisesHoldWhateverHappens(long seed) throws Exception {
        Random random = new Random(seed);
        int size = 1 + random.nextInt(4);
        StubDataSource source = new StubDataSource();
        Map<StubDataSource.StubConnection, ModelReset> resets = new LinkedHashMap<>();
        source.beforeReturn((StubDataSource.StubConnection newest) -> {
            ModelReset reset = new ModelReset();
            newest.sessionReset = reset;
            resets.put(newest, reset);
        });

        PoolSettings settings = new PoolSettings();
        settings.setName("state-machine");
        settings.setMaximumPoolSize(size);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofMillis(50));
        settings.setShutdownTimeout(Duration.ZERO);

        List<String> trail = new ArrayList<>();
        Map<Connection, StubDataSource.StubConnection> held = new LinkedHashMap<>();
        Set<StubDataSource.StubConnection> everRefused = new HashSet<>();
        SeclumePool pool = new SeclumePool(source, settings);
        try {
            for (int step = 0; step < STEPS; step++) {
                int action = random.nextInt(100);
                if (action < 30) {
                    borrow(pool, source, held, resets, everRefused, trail, size);
                } else if (action < 45 && !held.isEmpty()) {
                    Connection handle = pick(random, held);
                    try (Statement statement = handle.createStatement()) {
                        trail.add("use " + id(held.get(handle)));
                        assertFalse(statement.isClosed());
                    } catch (SQLException brokenAlready) {
                        trail.add("use failed " + id(held.get(handle)));
                    }
                } else if (action < 50 && !held.isEmpty()) {
                    Connection handle = pick(random, held);
                    try {
                        handle.createStatement();     // and never closed
                        trail.add("leave a statement open " + id(held.get(handle)));
                    } catch (SQLException brokenAlready) {
                        trail.add("open failed " + id(held.get(handle)));
                    }
                } else if (action < 72 && !held.isEmpty()) {
                    Connection handle = pick(random, held);
                    StubDataSource.StubConnection physical = held.remove(handle);
                    trail.add("return " + id(physical));
                    handle.close();
                } else if (action < 76 && !held.isEmpty()) {
                    Connection handle = pick(random, held);
                    StubDataSource.StubConnection physical = held.get(handle);
                    physical.broken = true;
                    trail.add("break " + id(physical));
                } else if (action < 86 && !resets.isEmpty()) {
                    ModelReset reset = pickReset(random, resets);
                    reset.answered = true;
                    trail.add("an answer arrives");
                } else if (action < 90 && !resets.isEmpty()) {
                    pickReset(random, resets).refuseNext = true;
                    trail.add("the next reset of one will be refused");
                } else if (action < 92 && !resets.isEmpty()) {
                    pickReset(random, resets).cannotReset = true;
                    trail.add("one cannot reset any more");
                } else if (action < 94) {
                    pool.suspend();
                    trail.add("suspend");
                } else if (action < 97) {
                    pool.resume();
                    trail.add("resume");
                } else {
                    trail.add("idle");
                }
                for (Map.Entry<StubDataSource.StubConnection, ModelReset> e : resets.entrySet()) {
                    if (e.getValue().refused) {
                        everRefused.add(e.getKey());
                    }
                }
                check(pool, held, trail, seed);
            }
            for (Connection handle : new ArrayList<>(held.keySet())) {
                handle.close();
            }
            held.clear();
            check(pool, held, trail, seed);
        } catch (AssertionError | Exception e) {
            throw new AssertionError("seed " + seed + ", pool of " + size + ", after: "
                    + String.join(", ", tail(trail)), e);
        } finally {
            pool.close();
        }
        for (StubDataSource.StubConnection physical : source.handedOut()) {
            assertTrue(physical.closed.get(), "seed " + seed
                    + ": a connection outlived the pool");
        }
    }

    private static void borrow(SeclumePool pool, StubDataSource source,
                               Map<Connection, StubDataSource.StubConnection> held,
                               Map<StubDataSource.StubConnection, ModelReset> resets,
                               Set<StubDataSource.StubConnection> everRefused,
                               List<String> trail, int size) throws Exception {
        if (held.size() >= size) {
            return;                                       // would only time out
        }
        Connection handle;
        try {
            handle = pool.getConnection();
        } catch (SQLException exhausted) {
            trail.add("borrow refused: " + exhausted.getSQLState());
            return;
        }
        Connection delegate = ((PooledConnection) handle).delegate();
        StubDataSource.StubConnection physical = null;
        for (StubDataSource.StubConnection candidate : source.handedOut()) {
            if (candidate.proxy == delegate) {
                physical = candidate;
            }
        }
        if (physical == null) {
            fail("a connection the source never opened was lent");
        }
        trail.add("borrow " + id(physical));
        ModelReset reset = resets.get(physical);
        assertFalse(reset.owed, "lent while the reset of its last use was unconfirmed");
        assertFalse(everRefused.contains(physical) || reset.refused,
                "lent again after its reset was refused");
        assertFalse(physical.closed.get(), "a closed connection was lent");
        assertFalse(held.containsValue(physical), "lent to two holders at once");
        held.put(handle, physical);
    }

    private static void check(SeclumePool pool, Map<Connection, ?> held, List<String> trail,
                              long seed) {
        assertEquals(held.size(), pool.activeCount(), "activeCount is not the handles held");
    }

    private static Connection pick(Random random, Map<Connection, ?> held) {
        // In the order borrowed - a seed has to replay the same choices.
        List<Connection> handles = new ArrayList<>(held.keySet());
        return handles.get(random.nextInt(handles.size()));
    }

    private static ModelReset pickReset(Random random,
                                        Map<StubDataSource.StubConnection, ModelReset> resets) {
        List<ModelReset> all = new ArrayList<>(resets.values());
        return all.get(random.nextInt(all.size()));
    }

    private static String id(StubDataSource.StubConnection physical) {
        return physical == null ? "?" : "#" + Integer.toHexString(
                System.identityHashCode(physical));
    }

    private static List<String> tail(List<String> trail) {
        return trail.subList(Math.max(0, trail.size() - 25), trail.size());
    }
}
