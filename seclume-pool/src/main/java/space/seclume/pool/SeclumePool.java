package space.seclume.pool;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLTransientConnectionException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.locks.LockSupport;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.Supplier;
import java.util.logging.Logger;

import javax.sql.DataSource;

/**
 * The connection pool.
 *
 * <p>It takes a {@link DataSource} and turns it into one that reuses
 * connections. What the underlying {@code DataSource} does to open a connection
 * - in particular where it gets its password from - is none of the pool's
 * business. It holds no secret and knows none; a reconnect is simply another
 * call to {@code getConnection()}, and if the secret source fails, the connect
 * fails. There is no cached way out - that would be a password on the heap,
 * which is exactly what this library is built against.
 *
 * <p><b>Fit for virtual threads.</b> That is not a passing remark but the
 * reason behind several design decisions:
 *
 * <ul>
 *   <li>No {@code synchronized} around blocking calls. A virtual thread that
 *       blocks inside a monitor sticks to its carrier thread and takes it
 *       along - with a thousand waiting requests the carrier pool is empty
 *       although nobody is computing.</li>
 *   <li>No {@code ThreadLocal} cache for recently used connections. With
 *       platform threads that is a trick that saves lookups; with millions of
 *       virtual threads it is a memory leak with a hit rate near zero.</li>
 *   <li>Handing out touches no lock and no shared counter: a thread hashes
 *       to a slot, takes the connection out of it with one
 *       {@code compareAndSet}, and is done. Waiting - only when nothing is
 *       free - parks with a deadline and is woken by whoever returns one.</li>
 * </ul>
 *
 * <p><b>Where the free connections live.</b> In an array of slots, not in a
 * queue, and with room to spare - four slots per connection. The reason is
 * measured, not assumed: a {@code ConcurrentLinkedDeque} put 72 percent of the
 * running time into itself because eight threads wrote the same head pointer;
 * an array in which every thread starts at a slot of its own brought a borrow
 * from 64 microseconds down to a quarter of one. The starting slot comes from
 * a hash of the thread id - no per-thread storage, so it behaves the same for
 * eight platform threads and for a million virtual ones.
 *
 * <p>A thread parks a connection at its own slot, so it tends to find the same
 * one again, and the slots nobody touches grow old and run into the idle
 * timeout - which is what lets the pool shrink under light load.
 */
public final class SeclumePool implements DataSource, AutoCloseable {

    /** Longest a waiting thread parks before it looks again by itself. */
    private static final long PARK_NANOS = 2_000_000L;

    /** How much room the free slots get per connection, to spread the hashes. */
    private static final int SLOTS_PER_CONNECTION = 4;

    /**
     * The number of slots - a power of two, and that is not cosmetic.
     *
     * <p>Picking a slot means taking a hash modulo the size, and a modulo by
     * anything else is an integer division: thirty cycles on the hottest path
     * the pool has, twice per borrow. With a power of two it is one AND.
     */
    private static int slotCount(int maximumPoolSize) {
        int wanted = maximumPoolSize * SLOTS_PER_CONNECTION;
        int size = 1;
        while (size < wanted) {
            size <<= 1;
        }
        return size;
    }

    private final DataSource source;
    private final PoolSettings settings;

    /**
     * The free connections - as slots in one array, not as a queue.
     *
     * <p>Three shapes were measured here, and the difference is not small.
     * A {@link java.util.concurrent.ConcurrentLinkedDeque} put <b>72 percent</b>
     * of the running time into itself: every thread writes the same head
     * pointer, and the cache line travels between the cores. Reading the state
     * out of the entries instead spread the writes, but made borrowing walk
     * over sixteen objects lying all over the heap - sixteen cache misses.
     *
     * <p>This array holds nothing but references, and taking one out is a
     * single {@code compareAndSet} on an element rather than on a shared head.
     *
     * <p><b>The slots are strided, and that is not decoration.</b> With
     * compressed references sixteen of them fit into one cache line, so
     * neighbouring slots are the same line as far as the hardware is
     * concerned: every {@code compareAndSet} by any thread invalidates it for
     * all the others. Giving each slot a line of its own is worth a factor of
     * two on a bare borrow-and-return - measured, see {@link #STRIDE}. The
     * comment that used to stand here claimed that more slots than connections
     * already bought each thread a line nobody else wants. It did not: more
     * slots on the same line are still the same line.
     *
     * <p>Scanning from the front keeps the low slots warm, so the ones at the
     * back run into the idle timeout and the pool can shrink.
     */
    private final java.util.concurrent.atomic.AtomicReferenceArray<PoolEntry> free;
    /** The number of usable slots minus one - the mask that replaces the modulo. */
    private final int slotMask;

    /**
     * How far apart two slots sit, in array elements.
     *
     * <p>A cache line is 64 bytes and a compressed reference is 4, so sixteen
     * of them share one. At a stride of sixteen each slot owns its line and
     * two threads working on different slots stop fighting over it.
     *
     * <p>The array pays for it in memory - sixteen times the references, which
     * for a pool of sixteen connections is a few kilobytes - and that is the
     * whole cost.
     */
    private static final int STRIDE = 16;

    /** Turns a slot number into its index in the strided array. */
    private int indexOf(int slot) {
        return (slot & slotMask) * STRIDE;
    }


    /** Every live entry - free or borrowed; for housekeeping and shutdown. */
    private final CopyOnWriteArrayList<PoolEntry> entries = new CopyOnWriteArrayList<>();
    /** This many connections may exist; every <b>connection</b> holds one. */
    private final Semaphore permits;
    /** Who is waiting for one to come back - only touched when none is free. */
    private final java.util.Queue<Thread> waiters = new ConcurrentLinkedQueue<>();
    /** How many of them there are - read on every return, written almost never. */
    private final java.util.concurrent.atomic.AtomicInteger waiting =
            new java.util.concurrent.atomic.AtomicInteger();

    /**
     * Statistics - as {@link LongAdder}, not {@link AtomicLong}.
     *
     * <p>A counter that eight threads increment on every borrow is one cache
     * line that travels between eight cores. {@code LongAdder} keeps a cell
     * per core and adds them up only when somebody asks - which is once a
     * minute for metrics, not a million times a second on the hot path.
     */
    private final LongAdder borrowed = new LongAdder();
    private final LongAdder created = new LongAdder();
    private final LongAdder retired = new LongAdder();
    private final LongAdder renewed = new LongAdder();
    private final LongAdder timeouts = new LongAdder();
    private final LongAdder leaksReported = new LongAdder();
    /** How often the secret was rotated - see {@link #rotateSecret}. */
    private volatile long rotation;

    private final Thread housekeeper;
    private volatile boolean closed;

    public SeclumePool(DataSource source, PoolSettings settings) {
        this.source = source;
        this.settings = settings;
        this.permits = new Semaphore(settings.getMaximumPoolSize());
        // More slots than connections, on purpose: threads pick their slot by
        // a hash, and eight threads in sixteen slots collide far more often
        // than the numbers suggest. With room to spare each thread mostly
        // finds its own slot and writes a cache line nobody else wants.
        int slots = slotCount(settings.getMaximumPoolSize());
        this.free = new java.util.concurrent.atomic.AtomicReferenceArray<>(slots * STRIDE);
        this.slotMask = slots - 1;
        this.housekeeper = newHousekeeper();
        this.housekeeper.start();
    }

    private Thread newHousekeeper() {
        ThreadFactory factory = runnable -> {
            Thread thread = new Thread(runnable, settings.getName() + "-housekeeper");
            thread.setDaemon(true);
            return thread;
        };
        return factory.newThread(this::housekeeping);
    }

    /**
     * Opens {@code minimumIdle} connections up front.
     *
     * <p>Separate from the constructor because it can fail: if the database is
     * unreachable at startup, the application should get to decide - abort, or
     * carry on and try again on the first access.
     */
    public void warmup() throws SQLException {
        int target = settings.getMinimumIdle();
        for (int i = 0; i < target; i++) {
            if (!permits.tryAcquire()) {
                return;
            }
            PoolEntry entry;
            try {
                entry = newEntry();
            } catch (SQLException e) {
                permits.release();
                throw e;
            }
            park(entry);
        }
    }

    // ---- handing out and taking back -------------------------------------

    /**
     * Hands out a connection.
     *
     * <p>The fast path touches <b>no shared counter and no lock</b>: it takes
     * an entry out of the free slots and wraps it. The permit is not part of
     * that path - it counts <b>living connections</b>, not borrowings, and is
     * taken when one is opened and given back when one is retired. A semaphore
     * on every borrow is one more cache line that eight threads write, and it
     * bought nothing: the number of slots already bounds the pool.
     */
    @Override
    public Connection getConnection() throws SQLException {
        if (closed) {
            throw new SQLException("this pool is closed", "08003");
        }
        // One reading of the clock, used for both the checks and the
        // deadline. Three of them per borrow were a quarter of the whole
        // operation - on Windows every one is a call into the kernel.
        long now = System.nanoTime();
        PoolEntry entry = takeUsable(now, now + settings.getConnectionTimeout().toNanos());
        if (entry == null) {
            // Only here: a borrow that found a free connection waited for
            // nothing, and an event saying so on every call would drown the
            // ones that mean something.
            PoolEvents.Wait waiting = PoolEvents.beginWait();
            boolean timedOut = true;
            try {
                entry = openOrWait(now + settings.getConnectionTimeout().toNanos());
                timedOut = false;
            } finally {
                PoolEvents.endWait(waiting, settings.getName(), borrowed.sum(), timedOut);
            }
        }
        entry.set(PoolEntry.State.IN_USE);
        boolean watched = !settings.getLeakDetectionThreshold().isZero();
        entry.markBorrowed(watched ? now : 0,
                watched ? new Throwable("this connection was borrowed here") : null);
        borrowed.increment();
        return new PooledConnection(this, entry,
                entry.statements(settings.getStatementCacheSize()));
    }

    /**
     * What to say when nobody got a connection in time.
     *
     * <p>"request timed out after 30000ms" is true and useless. The question
     * at that moment is always the same - <b>who is holding them</b> - and the
     * pool is the only one who knows. So the message names the state and the
     * three connections that have been out the longest, with the stack trace
     * of their borrow if leak detection is on; and if it is off, it says that
     * too, because that is the setting to change before the next incident.
     */
    private String timedOut() {
        long now = System.nanoTime();
        StringBuilder text = new StringBuilder(512); // seclume-allow: a message for a human, no payload in it
        text.append(settings.getName()).append(" - no connection available within ")
                .append(settings.getConnectionTimeout()).append(" (")
                .append(activeCount()).append(" of ").append(settings.getMaximumPoolSize())
                .append(" in use, ").append(idleCount()).append(" free, ")
                .append(waitingCount()).append(" waiting)");
        List<PoolEntry> holders = new ArrayList<>();
        for (PoolEntry entry : List.copyOf(entries)) {
            if (entry.state() == PoolEntry.State.IN_USE) {
                holders.add(entry);
            }
        }
        holders.sort((a, b) -> Long.compare(b.borrowedNanos(now), a.borrowedNanos(now)));
        boolean watched = !settings.getLeakDetectionThreshold().isZero();
        for (int i = 0; i < Math.min(3, holders.size()); i++) {
            PoolEntry entry = holders.get(i);
            text.append(System.lineSeparator()).append("  out for ")
                    .append(entry.borrowedNanos(now) / 1_000_000L)
                    .append(" ms");
            Throwable where = entry.borrowTrace();
            if (where != null) {
                StackTraceElement[] stack = where.getStackTrace();
                for (int line = 0; line < Math.min(6, stack.length); line++) {
                    text.append(System.lineSeparator()).append("      at ")
                            .append(stack[line]);
                }
            }
        }
        if (!holders.isEmpty() && !watched) {
            text.append(System.lineSeparator())
                    .append("  (no stack traces: leak detection is off - set ")
                    .append("leak-detection-threshold to see where the connections ")
                    .append("were borrowed)");
        }
        return text.toString();
    }

    /**
     * Nothing was free: open one, or wait for somebody to give one back.
     *
     * <p>The waiting is a park with a deadline, woken by whoever returns a
     * connection. The short maximum park is a safety net against a wakeup that
     * arrives just before the parking - not the normal way out.
     */
    private PoolEntry openOrWait(long deadline) throws SQLException {
        Thread self = Thread.currentThread();
        waiters.add(self);
        waiting.incrementAndGet();
        try {
            while (true) {
                if (permits.tryAcquire()) {
                    try {
                        return newEntry();
                    } catch (SQLException | RuntimeException e) {
                        permits.release();
                        throw e;
                    }
                }
                PoolEntry entry = takeUsable(System.nanoTime(), deadline);
                if (entry != null) {
                    return entry;
                }
                long left = deadline - System.nanoTime();
                if (left <= 0) {
                    timeouts.increment();
                    throw new SQLTransientConnectionException(timedOut(), "08003");
                }
                if (Thread.interrupted()) {
                    Thread.currentThread().interrupt();
                    throw new SQLTransientConnectionException(
                            "interrupted while waiting for a connection", "08006");
                }
                LockSupport.parkNanos(this, Math.min(left, PARK_NANOS));
            }
        } finally {
            waiting.decrementAndGet();
            waiters.remove(self);
        }
    }

    /**
     * Fetches a free connection that is still usable.
     *
     * <p>A connection may have been sitting in the pool while the server closed
     * it, and handing out a dead one pushes the failure onto a user who did
     * nothing wrong. So it is checked - but <b>only once it has been idle for
     * a while</b>. The check is a round trip, and doing it on every handout is
     * the difference between a pool that costs a fraction of a microsecond and
     * one that costs sixty. See
     * {@link PoolSettings#getValidationBypassWindow()}.
     */
    private PoolEntry takeUsable(long now, long deadline) {
        PoolEntry entry;
        while ((entry = claimIdle()) != null) {
            if (usable(entry, now)) {
                return entry;
            }
            retire(entry);
            if (System.nanoTime() > deadline) {
                return null;
            }
        }
        return null;
    }

    /**
     * Whether a connection may go out - the same rule on every path.
     *
     * <p>Too old is too old, and a connection that has been lying around is
     * asked whether it is still there. One that came back microseconds ago is
     * not asked: that would be a round trip, the most expensive thing a pool
     * can do on the hot path. See
     * {@link PoolSettings#getValidationBypassWindow()}.
     */
    private boolean usable(PoolEntry entry, long now) {
        if (!settings.getMaxLifetime().isZero()
                && entry.ageNanos(now) > settings.getMaxLifetime().toNanos()) {
            return false;
        }
        boolean stale = settings.getValidationBypassWindow().isZero()
                || entry.idleNanos(now) > settings.getValidationBypassWindow().toNanos();
        return !stale || isAlive(entry);
    }

    /**
     * Takes one connection out of the free slots.
     *
     * <p>Every thread starts at a slot of its own. That sounds like a detail
     * and is the whole difference: with all threads scanning from the front,
     * eight of them fight over the same array element and its cache line
     * travels between the cores on every borrow - measured at two microseconds
     * where the operation should cost a fraction of one. Spread out, each
     * thread mostly finds its own slot free and touches a line nobody else
     * wants.
     *
     * <p>It is a <b>hash of the thread id</b>, not a {@code ThreadLocal}: no
     * per-thread storage, nothing to clean up, and it works the same for a
     * million virtual threads - which is exactly where a thread-local cache
     * would degrade into a memory leak with a hit rate near zero.
     */
    private PoolEntry claimIdle() {
        int size = slotMask + 1;
        int start = startSlot();
        for (int i = 0; i < size; i++) {
            int slot = indexOf(start + i);
            PoolEntry candidate = free.get(slot);
            if (candidate != null && free.compareAndSet(slot, candidate, null)) {
                // No state to write here: out of the slot means out of reach.
                // Housekeeping only ever looks at the slots, so nobody else
                // can see this entry until it is parked again.
                return candidate;
            }
        }
        return null;
    }

    /**
     * Where this thread starts looking.
     *
     * <p>Fibonacci hashing of the thread id: consecutive ids - which is what a
     * thread pool hands out - end up far apart instead of next to each other.
     */
    private int startSlot() {
        long mixed = Thread.currentThread().threadId() * 0x9E3779B97F4A7C15L;
        return (int) (mixed >>> 33) & slotMask;
    }

    /**
     * Puts a connection back into the free slots.
     *
     * <p>Into the slot this thread starts from, so that the connection it
     * just used is the one it finds again - affinity without a thread-local.
     * There is always room: a permit exists for every slot, and whoever parks
     * holds one.
     */
    private void park(PoolEntry entry) {
        entry.set(PoolEntry.State.IDLE);
        int size = slotMask + 1;
        int start = startSlot();
        for (int i = 0; i < size; i++) {
            int slot = indexOf(start + i);
            if (free.get(slot) == null && free.compareAndSet(slot, null, entry)) {
                return;
            }
        }
        // Cannot happen while the permits hold - and if it ever did, keeping
        // the connection outside the pool would leak it.
        retire(entry);
    }

    private boolean isAlive(PoolEntry entry) {
        try {
            return entry.connection().isValid(
                    (int) Math.max(1, settings.getValidationTimeout().toSeconds()));
        } catch (SQLException e) {
            return false;
        }
    }

    private PoolEntry newEntry() throws SQLException {
        // This is where the call to the secret source happens - every time anew.
        Connection connection = source.getConnection();
        PoolEntry entry = new PoolEntry(connection);
        entry.credentialDeadline(credentialDeadline());
        entries.add(entry);
        created.increment();
        return entry;
    }

    /**
     * When a connection opened right now would stop being able to authenticate.
     *
     * <p>Answered by whatever {@code PoolSettings.credentialExpiry} was given,
     * and by nothing at all when it was not set - which is the default, and
     * keeps this pool what its module comment says it is: something that knows
     * {@code DataSource} and nothing about seclume's secret sources. The
     * driver side of the wiring lives in the Spring starter, which knows both.
     *
     * <p>Static passwords answer {@link Long#MAX_VALUE} and nothing changes.
     * A dynamic credential - Vault's database engine, an RDS IAM token -
     * answers with a real moment, and the pool then replaces the connection
     * <b>before</b> that rather than finding out afterwards. Without this,
     * dynamic credentials mean an authentication failure at an unpredictable
     * time in a running application, which is why most deployments that could
     * use them do not.
     *
     * <p>The margin is subtracted here rather than at the point of use so that
     * the deadline stored in the entry is already the moment to act on.
     */
    private long credentialDeadline() {
        Supplier<Instant> expiry = settings.getCredentialExpiry();
        if (expiry == null) {
            return Long.MAX_VALUE;
        }
        Instant validUntil;
        try {
            validUntil = expiry.get();
        } catch (RuntimeException e) {
            // A source that cannot say is treated as one that does not expire:
            // the pool behaves as it did before, rather than churning.
            return Long.MAX_VALUE;
        }
        if (validUntil == null) {
            return Long.MAX_VALUE;
        }
        Duration left = Duration.between(Instant.now(), validUntil)
                .minus(settings.getCredentialMargin());
        return System.nanoTime() + Math.max(0, left.toNanos());
    }

    /**
     * Opens a connection in place of one that broke while it was borrowed.
     *
     * <p>The route out of {@link PooledConnection}, and the place where this
     * project has it easier than anybody else: reconnecting needs the password,
     * and the password is not kept anywhere - the secret source is asked again,
     * exactly as it was at the start.
     *
     * <p>The entry stays the one it was, with its age and its numbers: for the
     * pool this is the same connection, and it has to be, or the size would
     * drift with every rebuild. The broken one is closed afterwards and quietly
     * - it is broken, and saying so a second time helps nobody.
     */
    void renew(PoolEntry entry) throws SQLException {
        Connection fresh = source.getConnection();
        Connection old = entry.replaceConnection(fresh);
        entry.credentialDeadline(credentialDeadline());
        renewed.increment();
        try {
            old.close();
        } catch (SQLException e) {
            // Expected: this is the connection that just failed.
        }
    }

    /** How often a borrowed connection was rebuilt - for metrics and for tests. */
    long renewals() {
        return renewed.sum();
    }

    /** Returns a connection - the route out of {@link PooledConnection}. */
    void release(PoolEntry entry, boolean broken) {
        if (entry.state() == PoolEntry.State.CLOSED) {
            return;
        }
        entry.markReturned();
        if (broken || closed || isPastLifetime(entry) || entry.isRetiringOnReturn()) {
            retire(entry);
        } else {
            park(entry);
        }
        // Somebody may be waiting for exactly this one. The count is read
        // first and is almost always zero: a volatile int that nobody writes
        // sits in every core's cache, while looking into the queue itself
        // means touching a line that the waiters keep changing - on the path
        // of every single return.
        if (waiting.get() > 0) {
            Thread waiter = waiters.peek();
            if (waiter != null) {
                LockSupport.unpark(waiter);
            }
        }
    }

    private boolean isPastLifetime(PoolEntry entry) {
        return !settings.getMaxLifetime().isZero()
                && entry.ageNanos(System.nanoTime()) > settings.getMaxLifetime().toNanos();
    }

    /** Closes a connection for good and removes it from the inventory. */
    private void retire(PoolEntry entry) {
        entry.set(PoolEntry.State.CLOSED);
        if (entries.remove(entry)) {
            // The permit belongs to the connection, so it goes back with it.
            permits.release();
        }
        retired.increment();
        // The plans belong to this session and die with it; closing them first
        // keeps the driver's own bookkeeping straight.
        entry.closeStatements();
        try {
            entry.connection().close();
        } catch (SQLException ignored) {
            // Closing a broken connection must not hurt a second time.
        }
    }

    // ---- housekeeping ----------------------------------------------------

    /**
     * The housekeeping thread: replace old connections, close surplus idle
     * schliessen, ruhende anstupsen, vergessene melden.
     *
     * <p>A single daemon thread that sleeps most of the time. It touches only
     * entries it can move from {@code IDLE} to {@code RESERVED} - it never
     * pulls a borrowed connection out from under the
     * Anwender weg.
     */
    private void housekeeping() {
        while (!closed) {
            try {
                Thread.sleep(Math.max(250, settings.getValidationTimeout().toMillis()));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            if (closed) {
                return;
            }
            try {
                sweepIdle();
                replenish();
                reportLeaks();
            } catch (RuntimeException e) {
                // Housekeeping must never die; the next round carries on.
                Logger.getLogger(SeclumePool.class.getName())
                        .warning(settings.getName() + " - housekeeping failed: " + e);
            }
        }
    }

    private void sweepIdle() {
        long now = System.nanoTime();
        int spare = idleCount() - settings.getMinimumIdle();
        for (int logical = 0; logical <= slotMask; logical++) {
            int i = indexOf(logical);
            PoolEntry entry = free.get(i);
            if (entry == null || !free.compareAndSet(i, entry, null)) {
                continue;      // borrowed in the meantime
            }
            entry.set(PoolEntry.State.RESERVED);
            boolean tooOld = !settings.getMaxLifetime().isZero()
                    && entry.ageNanos(now) > settings.getMaxLifetime().toNanos();
            boolean idleTooLong = spare > 0 && !settings.getIdleTimeout().isZero()
                    && entry.idleNanos(now) > settings.getIdleTimeout().toNanos();
            // The credential, not the connection, is what ran out here - and
            // an idle connection whose password has lapsed is worse than no
            // connection, because it looks usable right up to the moment it
            // is handed to somebody.
            if (tooOld || idleTooLong || entry.credentialLapsed(now)) {
                retire(entry);
                spare--;
                continue;
            }
            if (!settings.getKeepaliveTime().isZero()
                    && entry.idleNanos(now) > settings.getKeepaliveTime().toNanos()
                    && !isAlive(entry)) {
                retire(entry);
                continue;
            }
            park(entry);
        }
    }

    /**
     * Refills up to {@code minimumIdle}.
     *
     * <p>Without this step {@code minimumIdle} would be a lie: connections
     * would appear when load arrives and be closed as planned on reaching
     * {@code maxLifetime} - and would be rebuilt only on the next access. After a quiet night the pool would be back at
     * zero, and the first request in the morning would pay the full handshake.
     *
     * <p>If opening fails, it is neither reported nor retried: this is stock
     * keeping, not an order. Whoever really needs a connection gets the error
     * where it belongs - in {@code getConnection()}.
     */
    private void replenish() {
        int missing = settings.getMinimumIdle() - idleCount();
        for (int i = 0; i < missing && !closed; i++) {
            if (!permits.tryAcquire()) {
                return;        // every connection is out
            }
            try {
                PoolEntry entry = newEntry();
                park(entry);
                // The permit stays with the connection - it counts what is
                // alive, not what is borrowed. Giving it back here would let
                // the pool grow past its maximum.
            } catch (SQLException e) {
                permits.release();
                return;
            }
        }
    }

    /**
     * Reports connections that have been borrowed for too long - with the
     * stack trace of the borrow. Without it nobody knows which piece of code is
     * keeping them, and the report would be an annoyance rather than a hint.
     */
    private void reportLeaks() {
        if (settings.getLeakDetectionThreshold().isZero()) {
            return;
        }
        long now = System.nanoTime();
        long threshold = settings.getLeakDetectionThreshold().toNanos();
        for (PoolEntry entry : entries) {
            if (entry.state() == PoolEntry.State.IN_USE
                    && entry.borrowedNanos(now) > threshold
                    && entry.borrowTrace() != null) {
                leaksReported.increment();
                Logger.getLogger(SeclumePool.class.getName()).log(java.util.logging.Level.WARNING,
                        settings.getName() + " - a connection has been in use for "
                        + (entry.borrowedNanos(now) / 1_000_000) + " ms and was probably "
                        + "not closed", entry.borrowTrace());
            }
        }
    }

    // ---- Zustand ---------------------------------------------------------

    /** How many connections are borrowed right now. */
    public int activeCount() {
        return Math.max(0, entries.size() - idleCount());
    }

    /** How many sit free in the pool. */
    public int idleCount() {
        int count = 0;
        for (int logical = 0; logical <= slotMask; logical++) {
            if (free.get(indexOf(logical)) != null) {
                count++;
            }
        }
        return count;
    }

    /** How many there are in total. */
    public int totalCount() {
        return entries.size();
    }

    /** How many threads are waiting for a connection right now. */
    public int waitingCount() {
        return waiters.size();
    }

    /**
     * Who holds what, right now, in one string.
     *
     * <p>For the moment when nothing works any more and the question is
     * "why is the pool empty". A leak detector reports after a deadline, into
     * a log nobody is reading at three in the morning; this answers on demand:
     * every connection, how long it has been out, and - if leak detection is
     * on - the stack trace of the borrow.
     *
     * <p>No statement text and no values: what a connection was used for is
     * the application's business, and a pool dump that carried payload would
     * be the same mistake as a password on the heap.
     */
    public String report() {
        long now = System.nanoTime();
        StringBuilder text = new StringBuilder(); // seclume-allow: a report for a human, no payload in it
        text.append(settings.getName()).append(": ").append(totalCount()).append(" connections, ")
                .append(activeCount()).append(" out, ").append(idleCount()).append(" free, ")
                .append(waitingCount()).append(" waiting; maximum ")
                .append(settings.getMaximumPoolSize()).append('\n');
        int number = 0;
        for (PoolEntry entry : List.copyOf(entries)) {
            boolean out = entry.state() == PoolEntry.State.IN_USE;
            text.append("  #").append(++number).append(' ').append(entry.state())
                    .append(", opened ").append(millis(entry.ageNanos(now))).append(" ms ago");
            if (out) {
                text.append(", out for ").append(millis(entry.borrowedNanos(now))).append(" ms");
            } else {
                text.append(", idle for ").append(millis(entry.idleNanos(now))).append(" ms");
            }
            text.append('\n');
            Throwable where = entry.borrowTrace();
            if (out && where != null) {
                for (StackTraceElement line : where.getStackTrace()) {
                    text.append("      at ").append(line).append('\n');
                }
            } else if (out) {
                text.append("      (no stack: leak detection is off - set "
                        + "leak-detection-threshold to get one)\n");
            }
        }
        return text.toString();
    }

    private static long millis(long nanos) {
        return nanos / 1_000_000L;
    }

    /**
     * Uses the secret source again from now on - for a password that changed.
     *
     * <p>Every new connection asks the source anyway; this only decides what
     * happens to the ones that already stand. They are retired as they come
     * back, so a rotation costs no outage and no restart - which is what it
     * costs everywhere else, because every other pool has to keep the password
     * in order to reconnect. This one never had it.
     *
     * @param closeIdleNow whether the free connections go right away
     * @return how many connections were retired immediately
     */
    public int rotateSecret(boolean closeIdleNow) {
        rotation++;
        int closed = 0;
        if (closeIdleNow) {
            for (int logical = 0; logical <= slotMask; logical++) {
                int i = indexOf(logical);
                PoolEntry entry = free.get(i);
                if (entry != null && free.compareAndSet(i, entry, null)) {
                    retire(entry);
                    closed++;
                }
            }
        }
        for (PoolEntry entry : List.copyOf(entries)) {
            entry.retireOnReturn();
        }
        return closed;
    }

    /** How often the secret has been rotated - for metrics and for tests. */
    public long rotations() {
        return rotation;
    }

    /** Counter values for metrics - all numbers, nothing confidential. */
    public PoolStatistics statistics() {
        return new PoolStatistics(settings.getName(), totalCount(), activeCount(), idleCount(),
                waitingCount(), borrowed.sum(), created.sum(), retired.sum(), timeouts.sum(),
                leaksReported.sum(), renewed.sum());
    }

    public PoolSettings settings() {
        return settings;
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        housekeeper.interrupt();
        for (int i = 0; i < free.length(); i++) {
            free.set(i, null);
        }
        for (PoolEntry entry : List.copyOf(entries)) {
            // Borrowed connections are closed along with the rest: a pool
            // that waits for stragglers on shutdown hangs.
            retire(entry);
        }
    }

    public boolean isClosed() {
        return closed;
    }

    // ---- DataSource ------------------------------------------------------

    /**
     * The route with a user and a password - refused, and with the reason.
     * A pool that took a password per call could not
     * einmal sinnvoll poolen.
     */
    @Override
    public Connection getConnection(String username, String password) throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "getConnection(user, password) takes the password as a String, which stays "
                + "in the heap until the garbage collector happens to overwrite it - the one "
                + "thing seclume exists to prevent. Configure a secret provider on the "
                + "underlying DataSource and call getConnection().");
    }

    @Override
    public PrintWriter getLogWriter() throws SQLException {
        return source.getLogWriter();
    }

    @Override
    public void setLogWriter(PrintWriter out) throws SQLException {
        source.setLogWriter(out);
    }

    @Override
    public void setLoginTimeout(int seconds) throws SQLException {
        source.setLoginTimeout(seconds);
    }

    @Override
    public int getLoginTimeout() throws SQLException {
        return source.getLoginTimeout();
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        throw new SQLFeatureNotSupportedException("seclume does not use java.util.logging");
    }

    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
        if (iface.isInstance(this)) {
            return iface.cast(this);
        }
        return source.unwrap(iface);
    }

    @Override
    public boolean isWrapperFor(Class<?> iface) throws SQLException {
        return iface.isInstance(this) || source.isWrapperFor(iface);
    }

    /** Numbers and state only - a pool dump may give nothing away. */
    @Override
    public String toString() {
        return statistics().toString();
    }

    /** For tests: the entries, without exposing the connections. */
    List<String> entryStates() {
        List<String> states = new ArrayList<>(entries.size());
        for (PoolEntry entry : entries) {
            states.add(entry.state().name());
        }
        return states;
    }
}
