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
 * One connection's calls, one after the other, on a thread of the driver's.
 *
 * <p>A JDBC connection is used by one thread at a time, and R2DBC asks for
 * nothing else: the next statement waits for the last result to be consumed.
 * So every call of a connection is a task on its lane, run in the order it
 * was subscribed to. The blocking read of an answer blocks a thread of the
 * driver's, never one of the reactive application's few.
 *
 * <p><b>Which thread.</b> A platform thread from a small shared set, and a
 * virtual one when the set is in use. A virtual thread that blocks on a
 * socket parks, the JDK's poller waits for the answer in its stead and wakes
 * it onto a carrier - two more hand-overs per answer than a platform thread
 * blocked in the kernel, which the kernel wakes itself. One statement through
 * R2DBC under JFR: {@code ForkJoinPool.deactivate} was 55 % of the samples,
 * carriers parked and woken around every round trip. The set is bounded
 * ({@link #PLATFORM_THREADS}): a lane holds its thread only while it has work,
 * so a pool of connections needs as many as it has connections busy at once,
 * and past the bound the lane is virtual as before.
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

    /**
     * How many platform threads the lanes share - {@code
     * seclume.r2dbc.platformThreads}, 128 unless set; 0 runs every lane on a
     * virtual thread.
     */
    static final int PLATFORM_THREADS = Math.max(0,
            Integer.getInteger("seclume.r2dbc.platformThreads", 128));

    /**
     * The shared platform threads: none until the first lane has work, each
     * one gone after a minute without any. A hand-over to a thread waiting
     * for work, never a queue - a task that finds every one of them busy runs
     * on a virtual thread at once rather than waiting behind another lane.
     */
    private static final java.util.concurrent.ThreadPoolExecutor PLATFORM =
            PLATFORM_THREADS == 0 ? null : platformThreads();

    private static java.util.concurrent.ThreadPoolExecutor platformThreads() {
        java.util.concurrent.ThreadPoolExecutor threads = new java.util.concurrent.ThreadPoolExecutor(
                0, PLATFORM_THREADS, 60, java.util.concurrent.TimeUnit.SECONDS,
                new java.util.concurrent.SynchronousQueue<>(),
                // A lane thread serves every subscriber after the one whose task
                // started it: an InheritableThreadLocal of that one - a tenant, a
                // principal, a transaction - would be every later one's.
                Thread.ofPlatform().name("seclume-r2dbc-", 0).daemon(true)
                        .inheritInheritableThreadLocals(false).factory(),
                (task, full) -> Thread.ofVirtual().name("seclume-r2dbc")
                        .inheritInheritableThreadLocals(false).start(task));
        return threads;
    }

    /** Where blocking work with no lane of its own waits: a borrow from a full pool. */
    static final Scheduler WAITING = Schedulers.fromExecutor(
            task -> Thread.ofVirtual().name("seclume-r2dbc-borrow")
                    .inheritInheritableThreadLocals(false).start(task));
    private final AtomicBoolean draining = new AtomicBoolean();
    final Scheduler scheduler = Schedulers.fromExecutor(this::enqueue);

    /**
     * The statements results still hold. A result cancelled after its first
     * row - {@code next()} - closes its statement in a task of its own, and a
     * {@code usingWhen}'s {@code Connection.close()} can be queued before it:
     * the pool then found the statement open on every return and counted a
     * leak. The connection closes what is left here before it goes.
     */
    private final java.util.Set<java.sql.Statement> open =
            java.util.concurrent.ConcurrentHashMap.newKeySet();

    void opened(java.sql.Statement statement) {
        open.add(statement);
    }

    void closed(java.sql.Statement statement) {
        open.remove(statement);
    }

    /** On the lane, before the connection closes: what no result closed yet. */
    void closeOpenStatements() {
        for (java.sql.Statement statement : open) {
            try {
                statement.close();
            } catch (java.sql.SQLException ignored) {
                // closed either way, with the connection
            }
        }
        open.clear();
    }

    private void enqueue(Runnable task) {
        if (closed) {
            throw new RejectedExecutionException("this connection is closed");
        }
        tasks.add(task);
        if (draining.compareAndSet(false, true)) {
            if (PLATFORM != null) {
                PLATFORM.execute(this::drain);
            } else {
                Thread.ofVirtual().name("seclume-r2dbc").inheritInheritableThreadLocals(false)
                        .start(this::drain);
            }
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

    /**
     * {@code work} on a virtual thread rather than the lane's: for the first
     * call of a lane, the borrow, which may wait for a pool with nothing free.
     * Five hundred requests waiting on a pool of sixteen would otherwise hold
     * the shared platform threads while doing nothing - and the busy lanes
     * after them would find none. Nothing else runs on a lane before its
     * borrow has returned, so the order is the same.
     */
    <T> Mono<T> callWaiting(Callable<T> work) {
        return Mono.defer(() -> closed ? Mono.<T>error(closedConnection())
                : Mono.fromCallable(work).subscribeOn(WAITING).onErrorMap(Errors::translate));
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
