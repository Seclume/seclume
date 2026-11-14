package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.Test;

/**
 * Every listener hears every event, also when there are several.
 *
 * <p>With one listener the pool calls it directly; from two on, through
 * {@link Listeners}. That fan-out lost {@code opened} and {@code released}
 * under mutation testing without a test noticing (run 43416680859) - a
 * metrics listener next to a tracing one would have counted no openings and
 * no hold times.
 */
class PoolListenersTest {

    private static final class Heard implements PoolListener {
        final List<String> events = new CopyOnWriteArrayList<>();

        @Override
        public void acquired(long waitedNanos) {
            events.add("acquired");
            assertTrue(waitedNanos >= 0, "a wait is never negative: " + waitedNanos);
        }

        @Override
        public void released(long heldNanos) {
            events.add("released");
            assertTrue(heldNanos >= 0, "a hold is never negative: " + heldNanos);
        }

        @Override
        public void opened(long tookNanos) {
            events.add("opened");
            assertTrue(tookNanos >= 0, "an opening never takes negative time: " + tookNanos);
        }
    }

    private static PoolSettings settings() {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(1);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofSeconds(2));
        settings.setShutdownTimeout(Duration.ZERO);
        return settings;
    }

    @Test
    void twoListenersBothHearOpeningsBorrowsAndReturns() throws SQLException {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings())) {
            Heard metrics = new Heard();
            Heard tracing = new Heard();
            pool.listen(metrics);
            pool.listen(tracing);
            try (Connection connection = pool.getConnection();
                    java.sql.Statement statement = connection.createStatement()) {
                assertTrue(statement != null, "the borrower uses the connection");
            }
            for (Heard heard : List.of(metrics, tracing)) {
                assertTrue(heard.events.contains("opened"), heard.events.toString());
                assertTrue(heard.events.contains("acquired"), heard.events.toString());
                assertTrue(heard.events.contains("released"), heard.events.toString());
            }
            assertEquals(metrics.events, tracing.events, "the same events, in the same order");

            pool.unlisten(tracing);
            int before = tracing.events.size();
            pool.getConnection().close();
            assertEquals(before, tracing.events.size(), "a listener removed hears nothing more");
            assertTrue(metrics.events.size() > before, "the other one still does");
        }
    }
}
