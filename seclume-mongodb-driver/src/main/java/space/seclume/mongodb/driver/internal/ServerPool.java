package space.seclume.mongodb.driver.internal;

import java.util.ArrayDeque;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import org.bson.BsonDocument;
import org.bson.BsonValue;

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
 *
 * <p>Behind a load balancer ({@code loadBalanced=true}) one address is many
 * servers: each connection reaches the one the balancer chose, named by the
 * {@code serviceId} of its {@code hello}. A cursor or a transaction lives on
 * that server only, so it keeps its connection - {@link #pin} - and an error
 * distrusts only the connections to the same service, not the others (the
 * load balancer specification).
 */
public final class ServerPool implements AutoCloseable {

    private final MongoUrl url;
    private final ServerAddress address;
    private final int maxSize;
    private final long maxWaitMillis;
    private final long maxIdleNanos;
    private final long maxLifeNanos;
    private final boolean loadBalanced;
    /** Behind a load balancer: each service's generation, cleared one by one. */
    private final java.util.Map<BsonValue, Integer> serviceGenerations = new java.util.HashMap<>();
    /** The newest {@code hello} a connection answered - the limits, the session support. */
    private volatile BsonDocument lastHello;
    /** Not null for a pinned view: the one connection it runs on, and who lent it. */
    private final Pooled only;
    private final ServerPool lender;
    private int holders;
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition returned = lock.newCondition();
    private final ArrayDeque<Pooled> idle = new ArrayDeque<>();
    private int open;
    private int generation;
    private boolean closed;

    /** A connection, the generation it belongs to, when it was opened and last given back. */
    private record Pooled(MongoSession session, int generation, int serviceGeneration,
                          long bornNanos, long returnedNanos) {

        Pooled returned() {
            return new Pooled(session, generation, serviceGeneration, bornNanos,
                    System.nanoTime());
        }

        BsonValue serviceId() {
            return session.helloReply().get("serviceId");
        }
    }

    /**
     * @param maxIdleMillis  {@code maxIdleTimeMS}: an idle connection older than this is
     *                       closed rather than lent; 0 for no limit
     * @param maxLifeMillis  {@code maxLifeTimeMS}: the same from when it was opened
     */
    ServerPool(MongoUrl url, ServerAddress address, int maxSize, long maxWaitMillis,
            long maxIdleMillis, long maxLifeMillis) {
        this(url, address, maxSize, maxWaitMillis, maxIdleMillis, maxLifeMillis, false);
    }

    /** @param loadBalanced the address is a load balancer: see the class comment */
    ServerPool(MongoUrl url, ServerAddress address, int maxSize, long maxWaitMillis,
            long maxIdleMillis, long maxLifeMillis, boolean loadBalanced) {
        this.url = url;
        this.address = address;
        this.maxSize = maxSize;
        this.maxWaitMillis = maxWaitMillis;
        this.maxIdleNanos = TimeUnit.MILLISECONDS.toNanos(maxIdleMillis);
        this.maxLifeNanos = TimeUnit.MILLISECONDS.toNanos(maxLifeMillis);
        this.loadBalanced = loadBalanced;
        this.only = null;
        this.lender = null;
    }

    private ServerPool(ServerPool lender, Pooled only) {
        this.url = lender.url;
        this.address = lender.address;
        this.maxSize = 1;
        this.maxWaitMillis = lender.maxWaitMillis;
        this.maxIdleNanos = 0;
        this.maxLifeNanos = 0;
        this.loadBalanced = true;
        this.only = only;
        this.lender = lender;
        this.holders = 1;
    }

    private boolean usable(Pooled pooled) {
        long now = System.nanoTime();
        return !pooled.session().isClosed() && pooled.generation() == generation
                && pooled.serviceGeneration() == serviceGeneration(pooled.serviceId())
                && (maxIdleNanos == 0 || now - pooled.returnedNanos() < maxIdleNanos)
                && (maxLifeNanos == 0 || now - pooled.bornNanos() < maxLifeNanos);
    }

    /** Under the lock; 0 for a service never cleared, and for every connection not behind a balancer. */
    private int serviceGeneration(BsonValue serviceId) {
        return serviceId == null ? 0 : serviceGenerations.getOrDefault(serviceId, 0);
    }

    public ServerAddress address() {
        return address;
    }

    /**
     * Behind a load balancer: one connection of this pool, kept for whatever
     * must stay on the server behind it - a cursor, a transaction. The view
     * runs every command on that connection and gives it back when the last
     * holder {@link #release releases} it. Elsewhere this pool itself, as
     * every connection to the address reaches the same server.
     */
    ServerPool pin() {
        if (!loadBalanced || only != null) {
            return this;
        }
        return new ServerPool(this, borrow());
    }

    /** Whether this is one connection held for a cursor or a transaction; see {@link #pin}. */
    boolean pinned() {
        return only != null;
    }

    /** One more holder of a pinned connection; nothing for a pool. */
    void retain() {
        if (only == null) {
            return;
        }
        lock.lock();
        try {
            if (holders == 0) {
                throw new IllegalStateException("the pinned connection was given back already");
            }
            holders++;
        } finally {
            lock.unlock();
        }
    }

    /** A holder is done; the last one gives the connection back. Nothing for a pool. */
    public void release() {
        if (only == null) {
            return;
        }
        boolean last;
        lock.lock();
        try {
            if (holders == 0) {
                return;
            }
            last = --holders == 0;
        } finally {
            lock.unlock();
        }
        if (last) {
            lender.giveBack(only);
        }
    }

    /** The {@code hello} of the newest connection; one is opened if there is none yet. */
    BsonDocument hello() {
        if (only != null) {
            return only.session().helloReply();
        }
        if (lastHello == null) {
            giveBack(borrow());
        }
        return lastHello;
    }

    /** Runs one command on a pooled connection; no retry, no selection - see {@link Topology}. */
    BsonDocument run(String db, BsonDocument command, String sequenceId,
            List<? extends BsonDocument> sequence) {
        if (only != null) {
            // A cursor and the transaction it was opened in may share the
            // connection; one command at a time goes over it.
            lock.lock();
            try {
                if (holders == 0) {
                    throw new IllegalStateException("the pinned connection was given back "
                            + "already");
                }
                return runOn(only.session(), db, command, sequenceId, sequence);
            } finally {
                lock.unlock();
            }
        }
        Pooled pooled = borrow();
        try {
            return runOn(pooled.session(), db, command, sequenceId, sequence);
        } finally {
            giveBack(pooled);
        }
    }

    private static BsonDocument runOn(MongoSession session, String db, BsonDocument command,
            String sequenceId, List<? extends BsonDocument> sequence) {
        int before = session.networkTimeout();
        boolean bounded = Deadline.active();
        try {
            if (bounded) {
                // No longer than the operation has left; at least a millisecond,
                // since 0 would mean no limit at all.
                long left = Math.max(1, Deadline.remainingMillis());
                int limit = (int) Math.min(Integer.MAX_VALUE, left);
                session.networkTimeout(before > 0 ? Math.min(before, limit) : limit);
            }
            return session.command(db, command, sequenceId, sequence);
        } finally {
            if (bounded && !session.isClosed()) {
                session.networkTimeout(before);
            }
        }
    }

    /** A write with no reply asked for; see {@link MongoSession#send}. */
    void send(String db, BsonDocument command, String sequenceId,
            List<? extends BsonDocument> sequence) {
        if (only != null) {
            lock.lock();
            try {
                only.session().send(db, command, sequenceId, sequence);
                return;
            } finally {
                lock.unlock();
            }
        }
        Pooled pooled = borrow();
        try {
            pooled.session().send(db, command, sequenceId, sequence);
        } finally {
            giveBack(pooled);
        }
    }

    /** A new connection, for the monitor: it is not the pool's. */
    MongoSession openOwn() {
        MongoSession session = MongoSession.open(url, address.getHost(), address.getPort(),
                loadBalanced);
        lastHello = session.helloReply();
        return session;
    }

    private Pooled borrow() {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(
                Deadline.bounded(maxWaitMillis));
        int born;
        lock.lock();
        try {
            while (true) {
                if (closed) {
                    throw new IllegalStateException("the client is closed");
                }
                Pooled pooled = idle.pollFirst();
                if (pooled != null) {
                    if (usable(pooled)) {
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
                    MongoTimeoutException none = new MongoTimeoutException("no connection to "
                            + address + " within " + maxWaitMillis + " ms: all " + maxSize
                            + " are in use");
                    if (Deadline.active() && Deadline.remainingMillis() == 0) {
                        throw Deadline.expired("waiting for a connection", none);
                    }
                    throw none;
                }
                try {
                    if (returned.awaitNanos(left) <= 0) {
                        continue;                      // the deadline: the loop says so
                    }
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
            long now = System.nanoTime();
            MongoSession opened = openOwn();
            int serviceBorn;
            lock.lock();
            try {
                serviceBorn = serviceGeneration(opened.helloReply().get("serviceId"));
            } finally {
                lock.unlock();
            }
            return new Pooled(opened, born, serviceBorn, now, now);
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
            if (closed || pooled.session().isClosed() || pooled.generation() != generation
                    || pooled.serviceGeneration() != serviceGeneration(pooled.serviceId())) {
                open--;
                pooled.session().close();
            } else {
                idle.addFirst(pooled.returned());
            }
            returned.signal();
        } finally {
            lock.unlock();
        }
    }

    /**
     * An idle connection taken out of the pool, which no longer counts it:
     * a session between two commands, to be described or handed over (see
     * {@link MongoSession#detach}). {@code null} when none is idle.
     */
    public MongoSession takeIdle() {
        lock.lock();
        try {
            while (!idle.isEmpty()) {
                Pooled pooled = idle.pollFirst();
                open--;
                if (usable(pooled)) {
                    returned.signal();
                    return pooled.session();
                }
                pooled.session().close();
            }
            return null;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Takes a logged-in session into the pool - one {@link MongoSession#resume}
     * made - as an idle connection of the current generation. Refused when the
     * pool is full or closed; the session is then the caller's to close.
     */
    public boolean adopt(MongoSession session) {
        lock.lock();
        try {
            if (closed || open >= maxSize || session.isClosed()) {
                return false;
            }
            open++;
            long now = System.nanoTime();
            idle.addFirst(new Pooled(session, generation,
                    serviceGeneration(session.helloReply().get("serviceId")), now, now));
            returned.signal();
            return true;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Distrusts every connection there is now: see the class comment. A
     * pinned view clears the connections to its own service only.
     */
    void clear() {
        if (only != null) {
            lender.clear(only.serviceId());
            return;
        }
        if (loadBalanced) {
            // Behind a balancer an error without a service says nothing about
            // the others; only the connection that failed is not used again.
            return;
        }
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

    /** Behind a load balancer: the connections to one service, as the class comment says. */
    private void clear(BsonValue serviceId) {
        if (serviceId == null) {
            return;
        }
        lock.lock();
        try {
            serviceGenerations.merge(serviceId, 1, Integer::sum);
            for (java.util.Iterator<Pooled> it = idle.iterator(); it.hasNext(); ) {
                Pooled pooled = it.next();
                if (serviceId.equals(pooled.serviceId())) {
                    it.remove();
                    pooled.session().close();
                    open--;
                }
            }
            returned.signalAll();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void close() {
        if (only != null) {
            release();
            return;
        }
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
