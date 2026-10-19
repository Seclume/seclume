package space.seclume.mongodb.reactive;

import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

import com.mongodb.client.MongoCursor;

/**
 * How a call of the sync driver becomes a publisher.
 *
 * <p>The sync driver blocks; a publisher must not block whoever subscribes or
 * requests. So each subscription has one worker, a virtual thread started
 * right after {@code onSubscribe}. A cursor is opened at once - so that a
 * command the server refuses is an {@code onError} even before anything is
 * asked for (rules 1.4, 1.9) - and read one document per unit of demand; a
 * single call (an insert, a count) waits for the first request.
 * Every signal comes from that one thread, so they never overlap (Reactive
 * Streams rule 1.3); {@code request} only adds demand and wakes it, from any
 * thread. A request for zero or fewer is an error (3.9), demand saturates at
 * {@code Long.MAX_VALUE} (3.17), and {@code cancel} stops the worker and
 * closes the cursor - killing it on the server.
 */
final class Publishers {

    private Publishers() {
    }

    /** One value - or none, if the call returns null - then completion. */
    static <T> Publisher<T> single(Callable<T> call) {
        return subscriber -> subscribe(subscriber, emit -> {
            if (!emit.awaitDemand()) {
                return;
            }
            T value = call.call();
            if (value != null) {
                emit.next(value);
            }
        });
    }

    /** No value: the call, then completion. */
    static Publisher<Void> run(Runnable call) {
        return subscriber -> subscribe(subscriber, emit -> {
            if (emit.awaitDemand()) {
                call.run();
            }
        });
    }

    /** A cursor's documents, as many as are asked for at a time. */
    static <T> Publisher<T> many(Supplier<MongoCursor<T>> open) {
        return subscriber -> subscribe(subscriber, emit -> {
            try (MongoCursor<T> cursor = open.get()) {
                emit.onCancel(cursor::close);
                while (emit.awaitDemand() && cursor.hasNext()) {
                    T next = cursor.next();
                    if (!emit.next(next)) {
                        return;
                    }
                }
            }
        });
    }

    /** The elements of a list the call returns, as many as are asked for at a time. */
    static <T> Publisher<T> list(Callable<java.util.List<T>> call) {
        return subscriber -> subscribe(subscriber, emit -> {
            for (T next : call.call()) {
                if (!emit.awaitDemand() || !emit.next(next)) {
                    return;
                }
            }
        });
    }

    /** What a worker does: emit values while the subscriber wants them. */
    @FunctionalInterface
    private interface Work<T> {
        void run(Worker<T> emit) throws Exception;
    }

    private static <T> void subscribe(Subscriber<? super T> subscriber, Work<T> work) {
        if (subscriber == null) {
            throw new NullPointerException("the subscriber is null (Reactive Streams 1.9)");
        }
        Worker<T> worker = new Worker<>(subscriber, work);
        subscriber.onSubscribe(worker);
        worker.start();
    }

    private static final class Worker<T> implements Subscription {
        private final Subscriber<? super T> subscriber;
        private final Work<T> work;
        private final AtomicLong demand = new AtomicLong();
        private final AtomicBoolean started = new AtomicBoolean();
        private final ReentrantLock lock = new ReentrantLock();
        private final Condition wanted = lock.newCondition();
        private volatile boolean cancelled;
        private volatile IllegalArgumentException badRequest;
        private volatile Runnable onCancel;
        private volatile Thread thread;

        Worker(Subscriber<? super T> subscriber, Work<T> work) {
            this.subscriber = subscriber;
            this.work = work;
        }

        @Override
        public void request(long n) {
            if (cancelled) {
                return;
            }
            if (n <= 0) {
                badRequest = new IllegalArgumentException("request(" + n + "): demand has to "
                        + "be positive (Reactive Streams 3.9)");
            } else {
                demand.getAndUpdate(d -> d + n < 0 ? Long.MAX_VALUE : d + n);
            }
            wake();
        }

        void start() {
            if (started.compareAndSet(false, true)) {
                thread = Thread.ofVirtual().name("seclume-mongodb-reactive").start(this::work);
            }
        }

        @Override
        public void cancel() {
            cancelled = true;
            wake();
            Thread running = thread;
            if (running != null && running != Thread.currentThread()) {
                // A tailable cursor waits on the server for data: the interrupt
                // ends that wait, and the connection with it.
                running.interrupt();
            }
        }

        private void wake() {
            lock.lock();
            try {
                wanted.signalAll();
            } finally {
                lock.unlock();
            }
        }

        void onCancel(Runnable action) {
            onCancel = action;
        }

        /** Waits until something is asked for; false when the subscription is over. */
        boolean awaitDemand() throws InterruptedException {
            lock.lock();
            try {
                while (demand.get() == 0 && !cancelled && badRequest == null) {
                    wanted.await();
                }
            } finally {
                lock.unlock();
            }
            return !cancelled && badRequest == null;
        }

        /** Hands one value on; false when the subscription is over. */
        boolean next(T value) {
            if (cancelled || badRequest != null) {
                return false;
            }
            subscriber.onNext(value);
            demand.getAndUpdate(d -> d == Long.MAX_VALUE ? d : d - 1);
            return true;
        }

        private void work() {
            try {
                work.run(this);
                finish(null);
            } catch (Throwable failed) {
                finish(failed);
            }
        }

        private void finish(Throwable failed) {
            if (badRequest != null) {
                cancelled = true;
                subscriber.onError(badRequest);
                return;
            }
            if (cancelled) {
                Runnable action = onCancel;
                if (action != null) {
                    try {
                        action.run();
                    } catch (RuntimeException ignored) {
                        // the cursor is given up either way
                    }
                }
                return;
            }
            cancelled = true;
            if (failed != null) {
                subscriber.onError(failed);
            } else {
                subscriber.onComplete();
            }
        }
    }
}
