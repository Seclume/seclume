package space.seclume.mongodb.driver.internal;

import java.util.ArrayDeque;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import org.bson.BsonDocument;

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientException;
import com.mongodb.MongoInterruptedException;
import com.mongodb.MongoTimeoutException;
import com.mongodb.ServerAddress;

import space.seclume.mongodb.MongoUrl;

/**
 * The server a client talks to and its connections: one server so far
 * (a standalone or a single mongos); replica sets and server selection follow.
 *
 * <p>The pool is deliberately plain - idle sessions, a maximum, a wait with a
 * deadline - because a borrower leaves nothing on a connection yet: no
 * logical session, no transaction, and a cursor is not bound to the
 * connection that opened it. When sessions arrive, the reset on return comes
 * with them.
 */
public final class Cluster implements AutoCloseable {

    private static final int DEFAULT_MAX_POOL = 100;
    private static final long DEFAULT_MAX_WAIT_MILLIS = 120_000;

    private final MongoUrl url;
    private final ServerAddress address;
    private final int maxSize;
    private final long maxWaitMillis;
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition returned = lock.newCondition();
    private final ArrayDeque<MongoSession> idle = new ArrayDeque<>();
    private int open;
    private boolean closed;
    private volatile Limits limits;

    private Cluster(MongoUrl url, ServerAddress address, int maxSize, long maxWaitMillis) {
        this.url = url;
        this.address = address;
        this.maxSize = maxSize;
        this.maxWaitMillis = maxWaitMillis;
    }

    /** No connection is opened here, as with the official driver: the first command opens one. */
    public static Cluster of(MongoUrl url) {
        ConnectionString options = new ConnectionString(url.driverConnectionString());
        if (options.isSrvProtocol() || options.getHosts().size() > 1
                || options.getRequiredReplicaSetName() != null) {
            throw new MongoClientException("seclume's MongoDB driver connects to one server "
                    + "so far - a standalone or one mongos; a replica set, several hosts or "
                    + "mongodb+srv:// need the official driver with seclume-mongodb for now");
        }
        if (options.getCompressorList() != null && !options.getCompressorList().isEmpty()) {
            throw new MongoClientException("compression is not supported by seclume's MongoDB "
                    + "driver; remove 'compressors' from the URL");
        }
        Integer max = options.getMaxConnectionPoolSize();
        Integer wait = options.getMaxWaitTime();
        return new Cluster(url, new ServerAddress(url.host(), url.port()),
                max == null || max == 0 ? DEFAULT_MAX_POOL : max,
                wait == null ? DEFAULT_MAX_WAIT_MILLIS : wait);
    }

    public ServerAddress address() {
        return address;
    }

    /** Runs a command on a pooled connection. */
    public BsonDocument command(String db, BsonDocument command) {
        return command(db, command, null, null);
    }

    public BsonDocument command(String db, BsonDocument command, String sequenceId,
            List<? extends BsonDocument> sequence) {
        MongoSession session = borrow();
        try {
            return session.command(db, command, sequenceId, sequence);
        } finally {
            giveBack(session);
        }
    }

    /**
     * The limits and the kind of the server, from the {@code hello} of the
     * first connection; a connection is opened for it if there is none yet.
     */
    public Limits limits() {
        Limits known = limits;
        if (known != null) {
            return known;
        }
        giveBack(borrow());
        return limits;
    }

    /**
     * @param kind {@code mongos}, {@code primary}, {@code secondary} or
     *             {@code standalone}, as the server's {@code hello} says
     */
    public record Limits(int maxBsonObjectSize, int maxMessageSize, int maxWriteBatchSize,
                         int minWireVersion, int maxWireVersion, String kind, String setName) {

        static Limits of(MongoSession session) {
            BsonDocument hello = session.helloReply();
            String kind;
            if ("isdbgrid".equals(hello.getString("msg", new org.bson.BsonString(""))
                    .getValue())) {
                kind = "mongos";
            } else if (hello.containsKey("setName")) {
                kind = hello.getBoolean("isWritablePrimary", org.bson.BsonBoolean.FALSE)
                        .getValue() ? "primary" : "secondary";
            } else {
                kind = "standalone";
            }
            return new Limits(session.maxBsonObjectSize(), session.maxMessageSize(),
                    session.maxWriteBatchSize(),
                    hello.getNumber("minWireVersion", new org.bson.BsonInt32(0)).intValue(),
                    session.maxWireVersion(), kind,
                    hello.containsKey("setName") ? hello.getString("setName").getValue()
                            : null);
        }
    }

    private MongoSession borrow() {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(maxWaitMillis);
        lock.lock();
        try {
            while (true) {
                if (closed) {
                    throw new IllegalStateException("the client is closed");
                }
                MongoSession session = idle.pollFirst();
                if (session != null) {
                    if (!session.isClosed()) {
                        return session;
                    }
                    open--;
                    continue;
                }
                if (open < maxSize) {
                    open++;
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
            MongoSession session = MongoSession.open(url, address.getHost(), address.getPort());
            limits = Limits.of(session);
            return session;
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

    private void giveBack(MongoSession session) {
        lock.lock();
        try {
            if (closed || session.isClosed()) {
                open--;
                session.close();
            } else {
                idle.addFirst(session);
            }
            returned.signal();
        } finally {
            lock.unlock();
        }
    }

    /** Closes the idle connections now and each borrowed one as it comes back. */
    @Override
    public void close() {
        lock.lock();
        try {
            closed = true;
            for (MongoSession session : idle) {
                session.close();
                open--;
            }
            idle.clear();
            returned.signalAll();
        } finally {
            lock.unlock();
        }
    }
}
