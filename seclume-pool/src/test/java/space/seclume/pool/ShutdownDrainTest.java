package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Closing on SIGTERM, in order: nothing new is lent, idle connections go at
 * once, borrowed ones get until the drain time to come back, and only the
 * stragglers are cut.
 */
@Timeout(30)
class ShutdownDrainTest {

    @Test
    void aBorrowedConnectionThatComesBackInTimeIsNotCut() throws Exception {
        StubDataSource source = new StubDataSource();
        SeclumePool pool = new SeclumePool(source, settings(2));
        Connection busy = pool.getConnection();
        pool.getConnection().close();                       // one idle beside it
        CompletableFuture<Void> job = CompletableFuture.runAsync(() -> {
            sleep(300);                                     // the job finishes its work
            try {
                busy.close();
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        });
        long start = System.nanoTime();
        pool.close(Duration.ofSeconds(5));
        long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        job.join();
        assertTrue(took >= 250, "close did not wait for the borrowed connection: " + took + " ms");
        assertTrue(took < 3000, "close waited past the return: " + took + " ms");
        assertEquals(0, pool.statistics().total(), pool.statistics().toString());
    }

    @Test
    void aStragglerIsCutWhenTheDrainIsOver() throws Exception {
        StubDataSource source = new StubDataSource();
        SeclumePool pool = new SeclumePool(source, settings(1));
        Connection forgotten = pool.getConnection();
        long start = System.nanoTime();
        pool.close(Duration.ofMillis(400));
        long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        assertTrue(took >= 350 && took < 3000, "the drain was not bounded: " + took + " ms");
        assertEquals(0, pool.statistics().total(), pool.statistics().toString());
        assertTrue(forgotten.isClosed(), "the straggler was left open");
    }

    @Test
    void aWaitingBorrowerIsToldAtOnceAndNothingNewIsOpened() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings(1);
        settings.setConnectionTimeout(Duration.ofSeconds(20));
        SeclumePool pool = new SeclumePool(source, settings);
        Connection busy = pool.getConnection();
        CompletableFuture<Throwable> waiter = CompletableFuture.supplyAsync(() -> {
            try {
                pool.getConnection().close();
                return null;
            } catch (SQLException e) {
                return e;
            }
        });
        sleep(200);                                         // the waiter is parked
        CompletableFuture<Void> closing = CompletableFuture.runAsync(
                () -> pool.close(Duration.ofSeconds(5)));
        Throwable told = waiter.get(3, TimeUnit.SECONDS);
        assertTrue(told instanceof SQLException && told.getMessage().contains("closed"),
                "the waiter was not told the pool is closed: " + told);
        busy.close();
        closing.get(5, TimeUnit.SECONDS);
        assertEquals(1, source.openedCount(), "a connection was opened while closing");
        assertThrows(SQLException.class, pool::getConnection);
    }

    @Test
    void theDefaultDrainIsTenSeconds() {
        assertEquals(Duration.ofSeconds(10), new PoolSettings().getShutdownTimeout());
        assertFalse(new PoolSettings().getShutdownTimeout().isZero());
    }

    private static PoolSettings settings(int size) {
        PoolSettings settings = new PoolSettings();
        settings.setName("drain");
        settings.setMaximumPoolSize(size);
        return settings;
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
