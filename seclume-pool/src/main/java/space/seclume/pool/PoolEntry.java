package space.seclume.pool;

import java.sql.Connection;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A connection in the pool, together with what the pool needs to know about it.
 *
 * <p>The state is an {@link AtomicReference}, not a {@code synchronized} block:
 * a housekeeping thread can withdraw an idle connection exactly when it manages
 * to move it from {@code IDLE} to {@code RESERVED} - and loses the race cleanly
 * when an application has just taken it. A monitor would not only be slower
 * here, it would pin a virtual thread to its carrier.
 */
final class PoolEntry {

    enum State {
        /** Sits in the pool and can be handed out. */
        IDLE,
        /** Is currently borrowed. */
        IN_USE,
        /** Belongs to housekeeping - being checked or closed. */
        RESERVED,
        /** Is closed; this entry does not come back. */
        CLOSED
    }

    /**
     * Not final: a connection that breaks while it is borrowed is replaced
     * underneath the entry - see {@code PooledConnection}. Everything the pool
     * counts about this entry stays; only the socket is a different one.
     */
    private volatile Connection connection;
    private final long createdAt = System.nanoTime();
    /**
     * When the credential this connection was opened with stops working, as a
     * {@code nanoTime} deadline, or {@link Long#MAX_VALUE} for a password that
     * does not expire.
     *
     * <p>A deadline rather than an {@code Instant} because it is read on the
     * borrow path: a long comparison costs nothing, and {@code Instant.now()}
     * on every handout would be a clock call in the hot loop for a question
     * whose answer changes once an hour.
     *
     * <p>Set when the entry is created and again when its connection is
     * rebuilt - both go through the secret source, so both get whatever
     * credential is current.
     */
    private volatile long credentialDeadline = Long.MAX_VALUE;
    /**
     * A fresh entry starts <b>reserved</b>, not free.
     *
     * <p>Since the pool has no separate list of free connections and reads the
     * state instead, an entry becomes visible to everyone the moment it enters
     * the inventory. Starting it as free would mean a second thread could
     * claim it in the gap before the opener marks it as its own - the same
     * connection handed to two callers. Whoever creates it says afterwards
     * what it is: {@code IN_USE} for a borrow, {@code IDLE} for stock.
     */
    private final AtomicReference<State> state = new AtomicReference<>(State.RESERVED);

    private volatile long lastUsedAt = System.nanoTime();
    private volatile long borrowedAt;
    /**
     * Where the connection was borrowed from - only set when leak detection is
     * on. A stack trace per borrow would otherwise cost more than the whole
     * handout does.
     */
    private volatile Throwable borrowTrace;
    /** Set by a rotation: this one is not handed out again. */
    private volatile boolean retiring;

    /**
     * The state the connection was in when it was opened.
     *
     * <p>Read <b>once</b>, not on every handout. That is not thrift: pgjdbc
     * answers {@code getTransactionIsolation} with a query to the server, so
     * asking per borrow cost a full round trip - sixty microseconds where the
     * whole handout should be a fraction of one. The values cannot change
     * behind the pool's back either, because every change goes through the
     * wrapper and is undone on return.
     */
    private final boolean initialAutoCommit;
    private final boolean initialReadOnly;
    private final int initialIsolation;

    PoolEntry(Connection connection) throws java.sql.SQLException {
        this.connection = connection;
        this.initialAutoCommit = connection.getAutoCommit();
        this.initialReadOnly = connection.isReadOnly();
        this.initialIsolation = connection.getTransactionIsolation();
    }

    boolean initialAutoCommit() {
        return initialAutoCommit;
    }

    boolean initialReadOnly() {
        return initialReadOnly;
    }

    int initialIsolation() {
        return initialIsolation;
    }

    /** The statements this connection keeps between borrows, or {@code null}. */
    private StatementCache statements;

    StatementCache statements(int capacity) {
        if (capacity <= 0) {
            return null;
        }
        if (statements == null) {
            statements = new StatementCache(capacity);
        }
        return statements;
    }

    /** Gives the cached statements up - the connection is going. */
    void closeStatements() {
        if (statements != null) {
            statements.closeAll();
            statements = null;
        }
    }

    Connection connection() {
        return connection;
    }

    /**
     * Puts a freshly opened connection in place of the broken one.
     *
     * <p>The cached statements go with the old one: a plan lives in the session
     * that was just lost, and a handle to it is nothing but a way to find that
     * out later and in a worse place.
     *
     * @return the old connection, for the caller to close
     */
    Connection replaceConnection(Connection fresh) {
        closeStatements();
        Connection old = connection;
        connection = fresh;
        return old;
    }

    State state() {
        return state.get();
    }

    boolean compareAndSet(State expected, State next) {
        return state.compareAndSet(expected, next);
    }

    void set(State next) {
        state.set(next);
    }

    long ageNanos(long now) {
        return now - createdAt;
    }

    /** @see #credentialDeadline */
    void credentialDeadline(long nanoTimeDeadline) {
        this.credentialDeadline = nanoTimeDeadline;
    }

    /** Whether the credential behind this connection has lapsed, or is about to. */
    boolean credentialLapsed(long now) {
        return credentialDeadline != Long.MAX_VALUE && now - credentialDeadline >= 0;
    }

    /** When it was last handed back - the ordering the pool hands out by. */
    long lastUsedAt() {
        return lastUsedAt;
    }

    long idleNanos(long now) {
        return now - lastUsedAt;
    }

    long borrowedNanos(long now) {
        return now - borrowedAt;
    }

    /**
     * Notes when this went out - and only then, when somebody is watching.
     *
     * <p>The timestamp exists for the leak detection alone, so with that
     * switched off it is not taken: reading the clock is one of the few things
     * a borrow does at all, and on Windows it is a call into the kernel.
     *
     * @param now   the current time, or 0 when nobody needs it
     * @param trace where the borrow happened, or {@code null}
     */
    void markBorrowed(long now, Throwable trace) {
        this.borrowedAt = now;
        this.borrowTrace = trace;
    }

    void markReturned() {
        this.lastUsedAt = System.nanoTime();
        this.borrowTrace = null;
    }

    /**
     * Marks this connection as not to be reused - it goes when it comes back.
     *
     * <p>Used by a secret rotation: a connection that stands was opened with
     * the old password, and although it keeps working, it is not what the
     * application asked for any more.
     */
    void retireOnReturn() {
        this.retiring = true;
    }

    boolean isRetiringOnReturn() {
        return retiring;
    }

    Throwable borrowTrace() {
        return borrowTrace;
    }

    /** No content, only state - a pool dump may give nothing away. */
    @Override
    public String toString() {
        return "PoolEntry[state=" + state.get() + "]";
    }
}
