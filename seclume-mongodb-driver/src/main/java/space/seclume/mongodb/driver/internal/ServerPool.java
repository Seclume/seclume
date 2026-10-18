package space.seclume.mongodb.driver.internal;

import java.util.ArrayDeque;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import org.bson.BsonDocument;

import com.mongodb.MongoInterruptedException;
import com.mongodb.MongoTimeoutException;
import com.mongodb.ServerAddress;

import space.seclume.mongodb.MongoUrl;

/**
 * The connections to one server: idle sessions, a maximum, a wait with a
 * deadline.
 *
 * <p>{@link #clear} starts a new generation: the idle connections are closed
 * at once and a borrowed one as it comes back - after a network error or a
 * server that went down, a connection of the old generation is not trusted
 * again (the connection monitoring and pooling specification's "clear").
 *
 * <p>A borrower leaves nothing on a connection that the next one could see:
 * a logical session travels with each command as its {@code lsid}, not with
 * the connection, and so does a transaction.
 */
public final class ServerPool implements AutoCloseable {

    private final MongoUrl url;
    private final ServerAddress address;
    private final int maxSize;
    private final long maxWaitMillis;
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition returned = lock.newCondition();
    private final ArrayDeque<Pooled> idle = new ArrayDeque<>();
    private int open;
    private int generation;
    private boolean closed;

    private record Pooled(MongoSession session, int generation) {
    }

    ServerPool(MongoUrl url, ServerAddress address, int maxSize, long maxWaitMillis) {
        this.url = url;
        this.address = address;
        this.maxSize = maxSize;
        this.maxWaitMillis = maxWaitMillis;
    }

    public ServerAddress address() {
        return address;
    }

    /** Runs one command on a pooled connection; no retry, no selection - see {@link Topology}. */
    BsonDocument run(String db, BsonDocument command, String sequenceId,
            List<? extends BsonDocument> sequence) {
        Pooled pooled = borrow();
        try {
            return pooled.session().command(db, command, sequenceId, sequence);
        } finally {
            giveBack(pooled);
        }
    }

    /** A new connection, for the monitor: it is not the pool's. */
    MongoSession openOwn() {
        return MongoSession.open(url, address.getHost(), address.getPort());
    }

    private Pooled borrow() {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(maxWaitMillis);
        int born;
        lock.lock();
        try {
            while (true) {
                if (closed) {
                    throw new IllegalStateException("the client is closed");
                }
                Pooled pooled = idle.pollFirst();
                if (pooled != null) {
                    if (!pooled.session().isClosed() && pooled.generation() == generation) {
                        return pooled;
                    }
                    open--;
                    pooled.session().close();
                    continue;
                }
                if (open < maxSize) {
                    open++;
                    born = generation;
                    break;
                }
                long left = deadline - System.nanoTime();
                if (left <= 0) {
                    throw new MongoTimeoutException("no connection to " + address + " within "
                            + maxWaitMillis + " ms: all " + maxSize + " are in use");
                }
                try {
                    returned.awaitNanos(left);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new MongoInterruptedException("interrupted while waiting for a "
                            + "connection", e);
                }
            }
        } finally {
            lock.unlock();
        }
        try {
            return new Pooled(openOwn(), born);
        } catch (RuntimeException e) {
            lock.lock();
            try {
                open--;
                returned.signal();
            } finally {
                lock.unlock();
            }
            throw e;
        }
    }

    private void giveBack(Pooled pooled) {
        lock.lock();
        try {
            if (closed || pooled.session().isClosed() || pooled.generation() != generation) {
                open--;
                pooled.session().close();
            } else {
                idle.addFirst(pooled);
            }
            returned.signal();
        } finally {
            lock.unlock();
        }
    }

    /** Distrusts every connection there is now: see the class comment. */
    void clear() {
        lock.lock();
        try {
            generation++;
            for (Pooled pooled : idle) {
                pooled.session().close();
                open--;
            }
            idle.clear();
            returned.signalAll();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void close() {
        lock.lock();
        try {
            closed = true;
            for (Pooled pooled : idle) {
                pooled.session().close();
                open--;
            }
            idle.clear();
            returned.signalAll();
        } finally {
            lock.unlock();
        }
    }
}
