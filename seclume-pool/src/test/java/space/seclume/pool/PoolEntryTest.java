package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import space.seclume.internal.jdbc.Fronted;

/**
 * What the pool knows about one connection, checked on the entry itself.
 *
 * <p>The pool tests reach {@link PoolEntry} only through borrowing and
 * returning, where most of its answers are read but none is checked to the
 * value: a credential deadline compared one nanosecond off, a borrow time
 * that is never reset, a cache that is created anew on every call - each
 * survived mutation testing (run 43416680859, {@code mutation (pool)}). Each
 * test here names the decision the pool takes from the answer.
 */
class PoolEntryTest {

    private static PoolEntry entry() throws SQLException {
        return new PoolEntry(new StubDataSource().getConnection());
    }

    /** The state a returned connection is put back to is the one it was opened in. */
    @Test
    void theStateAtOpeningIsReadFromTheConnectionOnce() throws SQLException {
        StubDataSource source = new StubDataSource();
        source.beforeReturn(stub -> {
            stub.autoCommit = false;
            stub.readOnly = true;
            stub.isolation = Connection.TRANSACTION_SERIALIZABLE;
        });
        PoolEntry entry = new PoolEntry(source.getConnection());
        assertFalse(entry.initialAutoCommit());
        assertTrue(entry.initialReadOnly());
        assertEquals(Connection.TRANSACTION_SERIALIZABLE, entry.initialIsolation());

        // ... and not again: what the connection says later is a borrower's doing.
        StubDataSource.StubConnection stub = source.handedOut().getFirst();
        stub.autoCommit = true;
        stub.readOnly = false;
        assertFalse(entry.initialAutoCommit());
        assertTrue(entry.initialReadOnly());

        PoolEntry plain = entry();
        assertTrue(plain.initialAutoCommit());
        assertFalse(plain.initialReadOnly());
        assertEquals(Connection.TRANSACTION_READ_COMMITTED, plain.initialIsolation());
    }

    @Test
    void anAdoptedConnectionReturnsToWhatItWasGivenNotWhatItIsIn() throws SQLException {
        StubDataSource source = new StubDataSource();
        Connection connection = source.getConnection();      // autoCommit on, read-write
        PoolEntry adopted = new PoolEntry(connection, false, true, Connection.TRANSACTION_REPEATABLE_READ);
        assertFalse(adopted.initialAutoCommit());
        assertTrue(adopted.initialReadOnly());
        assertEquals(Connection.TRANSACTION_REPEATABLE_READ, adopted.initialIsolation());
        assertSame(connection, adopted.connection());
    }

    @Test
    void noCacheWithoutCapacityAndOneCachePerConnection() throws SQLException {
        PoolEntry entry = entry();
        assertNull(entry.statements(0), "a capacity of 0 switches the cache off");
        assertNull(entry.statements(-1));
        StatementCache one = entry.statements(1);
        assertNotNull(one, "the smallest capacity that keeps a statement");
        assertSame(one, entry.statements(1), "the same cache on every borrow, not a new one");
        assertSame(one, entry.statements(50), "made once; a later capacity does not replace it");
    }

    @Test
    void closingTheStatementsClosesWhatTheCacheHeldAndStartsAfresh() throws SQLException {
        PoolEntry entry = entry();
        StatementCache cache = entry.statements(4);
        FakePreparedStatement kept = new FakePreparedStatement();
        assertSame(kept.proxy, cache.take(kept.connection(), "select 1"));
        assertTrue(cache.give("select 1", kept.proxy));
        assertEquals(1, cache.size());

        entry.closeStatements();
        assertEquals(1, kept.closes.get(), "a statement the cache held is closed with it");
        assertEquals(0, cache.size());
        StatementCache next = entry.statements(4);
        assertNotSame(cache, next, "a closed cache is not handed out again");
        entry.closeStatements();
        entry.closeStatements();                    // nothing left: no failure, nothing closed twice
        assertEquals(1, kept.closes.get());
    }

    /** A plan lives in the session that was lost - the cached statements go with the socket. */
    @Test
    void replacingTheConnectionClosesItsStatementsAndAsksAgainForItsFrontedSide() throws SQLException {
        RecordingFronted first = new RecordingFronted();
        PoolEntry entry = new PoolEntry(first.connection);
        StatementCache cache = entry.statements(4);
        FakePreparedStatement kept = new FakePreparedStatement();
        assertSame(kept.proxy, cache.take(kept.connection(), "select 1"));
        assertTrue(cache.give("select 1", kept.proxy));
        assertSame(first.connection, entry.fronted());

        RecordingFronted fresh = new RecordingFronted();
        Connection old = entry.replaceConnection(fresh.connection);
        assertSame(first.connection, old, "the broken one goes back to the caller to be closed");
        assertSame(fresh.connection, entry.connection());
        assertEquals(1, kept.closes.get(), "statements prepared on the lost session are closed");
        assertNotSame(cache, entry.statements(4));
        assertSame(fresh.connection, entry.fronted(), "the new connection's side, not the lost one's");
    }

    @Test
    void theFrontedSideIsFoundDirectlyOrByUnwrappingAndAskedForOnce() throws SQLException {
        RecordingFronted direct = new RecordingFronted();
        PoolEntry entry = new PoolEntry(direct.connection);
        assertSame(direct.connection, entry.fronted());

        Fronted inner = (Fronted) new RecordingFronted().connection;
        AtomicInteger asked = new AtomicInteger();
        Connection wrapper = wrapper(inner, asked, true);
        PoolEntry wrapped = new PoolEntry(wrapper);
        assertSame(inner, wrapped.fronted(), "unwrapped from a driver connection that offers it");
        assertSame(inner, wrapped.fronted());
        assertEquals(1, asked.get(), "isWrapperFor is asked once per connection, not per borrow");

        AtomicInteger askedToo = new AtomicInteger();
        PoolEntry none = new PoolEntry(wrapper(inner, askedToo, false));
        assertNull(none.fronted(), "a driver that does not offer it hands out its own connection");
        assertNull(none.fronted());
        assertEquals(1, askedToo.get(), "\"none\" is remembered too");

        PoolEntry foreign = entry();                // the stub offers no Fronted side at all
        assertNull(foreign.fronted());
    }

    @Test
    void theAgeIsMeasuredFromTheEntrysCreation() throws SQLException {
        long before = System.nanoTime();
        PoolEntry entry = entry();
        long after = System.nanoTime();
        long later = after + 5_000_000_000L;
        long age = entry.ageNanos(later);
        assertTrue(age >= later - after && age <= later - before,
                () -> "an age of " + age + " ns for an entry made between " + before + " and " + after);
    }

    /**
     * A credential lapses at its deadline, not a nanosecond after it: the pool
     * renews a connection from the deadline on, and refuses to lend one whose
     * credential has expired from the expiry on.
     */
    @Test
    void aCredentialLapsesAndExpiresExactlyAtItsMoment() throws SQLException {
        PoolEntry entry = entry();
        long now = System.nanoTime();
        assertFalse(entry.credentialLapsed(now), "a password without an expiry never lapses");
        assertFalse(entry.credentialExpired(now));
        assertFalse(entry.credentialLapsed(Long.MAX_VALUE));
        assertFalse(entry.credentialExpired(Long.MAX_VALUE));
        assertEquals(Long.MAX_VALUE, entry.credentialDeadline());

        long deadline = now + 1_000;
        long expires = now + 2_000;
        entry.credential(new SeclumePool.CredentialTimes(deadline, expires));
        assertEquals(deadline, entry.credentialDeadline());
        assertFalse(entry.credentialLapsed(deadline - 1));
        assertTrue(entry.credentialLapsed(deadline));
        assertTrue(entry.credentialLapsed(deadline + 1));
        assertFalse(entry.credentialExpired(deadline), "the deadline is a margin before the expiry");
        assertFalse(entry.credentialExpired(expires - 1));
        assertTrue(entry.credentialExpired(expires));
        assertTrue(entry.credentialExpired(expires + 1));

        entry.credentialDeadline(now + 10);
        assertEquals(now + 10, entry.credentialDeadline());
        assertTrue(entry.credentialLapsed(now + 10));
        assertFalse(entry.credentialLapsed(now + 9));
    }

    /** The comparison is on the nanoTime scale, which may wrap: a difference, not a "<". */
    @Test
    void aDeadlineAcrossTheWrapOfNanoTimeStillLapses() throws SQLException {
        PoolEntry entry = entry();
        long deadline = Long.MIN_VALUE + 5;              // just past the wrap
        entry.credential(new SeclumePool.CredentialTimes(deadline, deadline + 10));
        assertFalse(entry.credentialLapsed(Long.MAX_VALUE - 5), "before the wrap is before the deadline");
        assertTrue(entry.credentialLapsed(deadline));
        assertFalse(entry.credentialExpired(deadline + 9));
        assertTrue(entry.credentialExpired(deadline + 10));
    }

    @Test
    void aBorrowIsTimedOnlyWhenSomebodyWatchesAndForgottenAfterwards() throws SQLException {
        PoolEntry entry = entry();
        assertFalse(entry.borrowedSince(), "a fresh entry was never borrowed");

        entry.markBorrowed(0, null);               // leak detection off
        assertFalse(entry.borrowedSince());
        assertNull(entry.borrowTrace());

        Throwable where = new Throwable("borrowed here");
        entry.markBorrowed(1_000, where);
        assertTrue(entry.borrowedSince());
        assertEquals(4_000, entry.borrowedNanos(5_000));
        assertSame(where, entry.borrowTrace());

        entry.markReturned(6_000);
        assertNull(entry.borrowTrace(), "the trace of a returned borrow is not kept");
        assertEquals(6_000, entry.lastUsedAt());
        assertEquals(1_000, entry.idleNanos(7_000));

        // Leak detection switched off since: the next borrow must not look like the old one.
        entry.markBorrowed(0, null);
        assertFalse(entry.borrowedSince(), "the time of a former borrow is cleared");
        assertNull(entry.borrowTrace());

        entry.markBorrowed(2_000, where);
        entry.markBorrowed(0, null);
        assertNull(entry.borrowTrace(), "a trace from a former borrow is cleared");
    }

    @Test
    void quietIsMeasuredFromTheLaterOfReturnAndKeepalive() throws SQLException {
        PoolEntry entry = entry();
        entry.markReturned(1_000);
        assertEquals(500, entry.quietNanos(1_500));
        long before = System.nanoTime();
        entry.markKeptAlive();
        long quiet = entry.quietNanos(before + 1_000_000);
        assertTrue(quiet <= 1_000_000, () -> "a keepalive counts as activity: quiet for " + quiet + " ns");
    }

    @Test
    void stateRetirementAndOwedResetAreKeptAsSet() throws SQLException {
        PoolEntry entry = entry();
        assertEquals(PoolEntry.State.RESERVED, entry.state(), "a fresh entry is nobody's to take");
        assertFalse(entry.compareAndSet(PoolEntry.State.IDLE, PoolEntry.State.IN_USE));
        assertTrue(entry.compareAndSet(PoolEntry.State.RESERVED, PoolEntry.State.IDLE));
        entry.setQuietly(PoolEntry.State.IN_USE);
        assertEquals(PoolEntry.State.IN_USE, entry.state());
        entry.set(PoolEntry.State.CLOSED);
        assertEquals("PoolEntry[state=CLOSED]", entry.toString());

        assertFalse(entry.isRetiringOnReturn());
        entry.retireOnReturn();
        assertTrue(entry.isRetiringOnReturn());

        assertNull(entry.owedReset());
        space.seclume.SessionReset reset = new space.seclume.SessionReset() {
            @Override
            public boolean sessionStateChanged() {
                return false;
            }

            @Override
            public boolean resetSessionState() {
                return true;
            }
        };
        entry.owe(reset);
        assertSame(reset, entry.owedReset());
        assertFalse(entry.isSettling());
        entry.settling(true);
        assertTrue(entry.isSettling());
        entry.settling(false);
        assertFalse(entry.isSettling());
    }

    /** A driver connection that is its own {@link Fronted} side, as seclume's are. */
    static final class RecordingFronted {
        final List<Connection> fronts = new ArrayList<>();
        final Connection connection;

        RecordingFronted() {
            this.connection = (Connection) Proxy.newProxyInstance(PoolEntryTest.class.getClassLoader(),
                    new Class<?>[] {Connection.class, Fronted.class}, (self, method, args) -> switch (method.getName()) {
                        case "front" -> {
                            fronts.add((Connection) args[0]);
                            yield null;
                        }
                        case "getAutoCommit" -> true;
                        case "isReadOnly", "isClosed" -> false;
                        case "getTransactionIsolation" -> Connection.TRANSACTION_READ_COMMITTED;
                        case "hashCode" -> System.identityHashCode(self);
                        case "equals" -> self == args[0];
                        case "toString" -> "RecordingFronted";
                        default -> throw new SQLException("not used: " + method.getName());
                    });
        }
    }

    /**
     * A connection that is not itself {@link Fronted} but can be unwrapped to
     * one - or says it cannot - and counts how often it was asked.
     */
    private static Connection wrapper(Fronted inner, AtomicInteger asked, boolean offers) {
        return (Connection) Proxy.newProxyInstance(PoolEntryTest.class.getClassLoader(),
                new Class<?>[] {Connection.class}, (self, method, args) -> switch (method.getName()) {
                    case "isWrapperFor" -> {
                        asked.incrementAndGet();
                        yield offers && args[0] == Fronted.class;
                    }
                    case "unwrap" -> {
                        if (offers && args[0] == Fronted.class) {
                            yield inner;
                        }
                        throw new SQLException("not a wrapper");
                    }
                    case "getAutoCommit" -> true;
                    case "isReadOnly" -> false;
                    case "getTransactionIsolation" -> Connection.TRANSACTION_READ_COMMITTED;
                    case "hashCode" -> System.identityHashCode(self);
                    case "equals" -> self == args[0];
                    default -> throw new SQLException("not used: " + method.getName());
                });
    }
}
