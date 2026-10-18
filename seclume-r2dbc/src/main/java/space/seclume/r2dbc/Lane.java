package space.seclume.r2dbc;

import java.sql.SQLException;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;

import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

/**
 * One connection's calls, one after the other, on a virtual thread of its own.
 *
 * <p>A JDBC connection is used by one thread at a time, and R2DBC asks for
 * nothing else: the next statement waits for the last result to be consumed.
 * So every call of a connection is a task on its lane, run in the order it
 * was subscribed to. The blocking read of an answer blocks a virtual thread,
 * not a carrier: the reactive application's few threads stay free.
 *
 * <p>The lane is also the quiet point a session can be handed over at: a
 * task on it is the only thing touching the connection while it runs.
 */
final class Lane implements AutoCloseable {

    /** A call that returns nothing and may throw what JDBC throws. */
    @FunctionalInterface
    interface SqlWork {
        void run() throws SQLException;
    }

    /**
     * The tasks, run one after the other by whichever virtual thread is
     * draining them - started when work arrives, gone when there is none.
     *
     * <p>Not an executor service per connection: a pooled connection is
     * borrowed for one statement and given back, and an executor, its thread
     * and a scheduler made and torn down per borrow cost more than the
     * statement. Two objects instead, and a virtual thread only while there
     * is something to do. The order is the queue's, and one drainer at a time
     * is the flag's - so the JDBC connection still sees one caller after the
     * other, each task's effects visible to the next through the queue.
     */
    private final ConcurrentLinkedQueue<Runnable> tasks = new ConcurrentLinkedQueue<>();
    private final AtomicBoolean draining = new AtomicBoolean();
    final Scheduler scheduler = Schedulers.fromExecutor(this::enqueue);

    private void enqueue(Runnable task) {
        if (closed) {
            throw new RejectedExecutionException("this connection is closed");
        }
        tasks.add(task);
        if (draining.compareAndSet(false, true)) {
            Thread.ofVirtual().name("seclume-r2dbc").start(this::drain);
        }
    }

    private void drain() {
        while (true) {
            Runnable task;
            while ((task = tasks.poll()) != null) {
                try {
                    task.run();
                } catch (RuntimeException | Error failure) {
                    // Reactor's tasks report their own failures; nothing
                    // reaches here that a subscriber has not been told of.
                }
            }
            draining.set(false);
            // A task added between the last poll and the flag would wait
            // for ever - unless whoever sees it takes the drain back up.
            if (tasks.isEmpty() || !draining.compareAndSet(false, true)) {
                return;
            }
        }
    }

    private volatile boolean closed;

    /**
     * {@code work} on this lane, its JDBC failure as R2DBC's. On a closed
     * lane, a failure at once: its thread is gone, and a task handed to it
     * would never run - a subscriber waiting for ever.
     */
    <T> Mono<T> call(Callable<T> work) {
        return Mono.defer(() -> closed ? Mono.<T>error(closedConnection())
                : Mono.fromCallable(work).subscribeOn(scheduler).onErrorMap(Errors::translate));
    }

    Mono<Void> run(SqlWork work) {
        return call(() -> {
            work.run();
            return null;
        });
    }

    boolean isClosed() {
        return closed;
    }

    private static io.r2dbc.spi.R2dbcNonTransientResourceException closedConnection() {
        return new io.r2dbc.spi.R2dbcNonTransientResourceException("this connection is closed",
                "08003");
    }

    @Override
    public void close() {
        closed = true;
        scheduler.dispose();
    }
}
