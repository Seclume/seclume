package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;

import space.seclume.OpenStatements;
import space.seclume.SessionReset;
import space.seclume.internal.jdbc.Fronted;

/**
 * What a returned connection is put back to before the next borrower gets it,
 * call by call.
 *
 * <p>The tests of this behaviour that check it to the call need a server
 * ({@code PoolHandOnSeamTest}, {@code PoolWithPostgresTest}) and skip under
 * mutation testing, so a skipped rollback, a skipped {@code clearWarnings} or
 * a statement cache left open across a session reset survived there (run
 * 43416680859, {@code PooledConnection}: 44 survivors). Here the driver is
 * {@link StubDataSource}'s, wrapped to record every call the pool makes - so
 * each test says what was sent to the server, not only what the pool answers.
 *
 * <p>The rule from AGENTS.md is the frame: a session is reset at the end of a
 * borrow and never in the middle of one - adopting a connection in the middle
 * of a transaction keeps it, returning it ends it.
 */
class ReturnRestoresTheSessionTest {

    private static PoolSettings settings(int statementCache) {
        PoolSettings settings = new PoolSettings();
        settings.setName("restore");
        settings.setMaximumPoolSize(2);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofSeconds(2));
        settings.setShutdownTimeout(Duration.ZERO);
        settings.setStatementCacheSize(statementCache);
        return settings;
    }

    /** A statement opened and closed again: the borrower used the connection. */
    private static void use(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            assertNotNull(statement);
        }
    }

    /** The same with a prepared statement - the kind a statement cache keeps. */
    private static void prepare(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("select 1")) {
            assertNotNull(statement);
        }
    }

    // ---- the transaction ----------------------------------------------------

    @Test
    void anOpenTransactionIsRolledBackAndAutoCommitPutBack() throws SQLException {
        Recording source = new Recording();
        try (SeclumePool pool = new SeclumePool(source, settings(0))) {
            Connection borrowed = pool.getConnection();
            Recording.Physical physical = source.physical.getFirst();
            borrowed.setAutoCommit(false);
            use(borrowed);
            physical.calls.clear();
            borrowed.close();
            assertEquals(1, physical.stub.rollbacks.get(), "what was not committed was not intended");
            assertTrue(physical.stub.autoCommit, "the next borrower gets auto-commit back");
            assertTrue(physical.calls.indexOf("rollback") < physical.calls.indexOf("setAutoCommit[true]"),
                    "rolled back before auto-commit would commit it: " + physical.calls);
        }
    }

    @Test
    void aConnectionThatStayedInAutoCommitIsNotRolledBack() throws SQLException {
        Recording source = new Recording();
        try (SeclumePool pool = new SeclumePool(source, settings(0))) {
            Connection borrowed = pool.getConnection();
            use(borrowed);
            Recording.Physical physical = source.physical.getFirst();
            physical.calls.clear();
            borrowed.close();
            assertEquals(0, physical.stub.rollbacks.get());
            assertFalse(physical.calls.contains("setAutoCommit[true]"), physical.calls.toString());
        }
    }

    /** A pool over connections that open without auto-commit: every return may end a transaction. */
    @Test
    void connectionsOpenedWithoutAutoCommitAreRolledBackOnEveryReturn() throws SQLException {
        Recording source = new Recording();
        source.stubs.beforeReturn(stub -> stub.autoCommit = false);
        try (SeclumePool pool = new SeclumePool(source, settings(0))) {
            Connection borrowed = pool.getConnection();
            use(borrowed);
            borrowed.close();
            Recording.Physical physical = source.physical.getFirst();
            assertEquals(1, physical.stub.rollbacks.get());
            assertFalse(physical.stub.autoCommit, "left as it was opened");

            // switched on by the borrower: nothing can be open, and it goes back off
            Connection again = pool.getConnection();
            assertSame(physical.connection, ((PooledConnection) again).delegate());
            again.setAutoCommit(true);
            again.close();
            assertEquals(1, physical.stub.rollbacks.get(), "auto-commit on: nothing to roll back");
            assertFalse(physical.stub.autoCommit, "put back to how it was opened");
        }
    }

    // ---- warnings and statements ------------------------------------------

    @Test
    void warningsAreClearedAfterAUseAndOnlyThen() throws SQLException {
        Recording source = new Recording();
        try (SeclumePool pool = new SeclumePool(source, settings(0))) {
            Connection untouched = pool.getConnection();
            Recording.Physical physical = source.physical.getFirst();
            physical.calls.clear();
            untouched.close();
            assertFalse(physical.calls.contains("clearWarnings[]"),
                    "nothing was asked, so nothing can have warned: " + physical.calls);

            Connection used = pool.getConnection();
            use(used);
            physical.calls.clear();
            used.close();
            assertEquals(1, Collections.frequency(physical.calls, "clearWarnings[]"), physical.calls.toString());
        }
    }

    /** An unclosed statement holds a cursor on the server and outlives the request that forgot it. */
    @Test
    void statementsTheBorrowerLeftOpenAreClosedAndCounted() throws SQLException {
        Recording source = new Recording();
        source.tracksOpenStatements = true;
        try (SeclumePool pool = new SeclumePool(source, settings(0))) {
            Connection borrowed = pool.getConnection();
            Statement forgotten = borrowed.createStatement();
            Statement closed = borrowed.createStatement();
            closed.close();
            Recording.Physical physical = source.physical.getFirst();
            assertEquals(1, physical.open().size());
            borrowed.close();
            assertTrue(forgotten.isClosed(), "closed on return");
            assertEquals(0, physical.open().size());
            assertEquals(1, pool.statementLeaks(), "and reported once");

            Connection tidy = pool.getConnection();
            use(tidy);
            tidy.close();
            assertEquals(1, pool.statementLeaks(), "a borrower that closed everything leaked nothing");
        }
    }

    @Test
    void aStatementTheCacheKeepsIsNoLeakAndStaysOpen() throws SQLException {
        Recording source = new Recording();
        source.tracksOpenStatements = true;
        source.fakeStatements = true;
        try (SeclumePool pool = new SeclumePool(source, settings(8))) {
            Connection borrowed = pool.getConnection();
            prepare(borrowed);
            borrowed.close();
            Recording.Physical physical = source.physical.getFirst();
            assertEquals(0, pool.statementLeaks());
            assertEquals(0, physical.statements.getFirst().closes.get(), "kept for the next borrower");
        }
    }

    /**
     * A session reset drops the server's prepared plans - a cached handle to
     * one would fail the next borrower. Without a reset the cache stays.
     */
    @Test
    void aSessionResetEmptiesTheStatementCacheAndNoResetKeepsIt() throws SQLException {
        Recording source = new Recording();
        source.fakeStatements = true;
        try (SeclumePool pool = new SeclumePool(source, settings(8))) {
            Connection borrowed = pool.getConnection();
            prepare(borrowed);
            borrowed.close();
            Recording.Physical physical = source.physical.getFirst();
            FakePreparedStatement first = physical.statements.getFirst();
            assertEquals(0, first.closes.get());

            Connection again = pool.getConnection();
            prepare(again);
            assertEquals(1, physical.statements.size(), "no reset, so the plan was reused");
            Counting reset = new Counting();
            physical.stub.sessionReset = reset;
            again.close();
            assertEquals(1, reset.resets);
            assertEquals(1, first.closes.get(), "the reset took the plan with it, so the handle goes too");

            try (Connection third = pool.getConnection()) {
                PreparedStatement fresh = third.prepareStatement("select 1");
                assertEquals(2, physical.statements.size(), "prepared anew");
                fresh.close();
            }
        }
    }

    @Test
    void aSessionThatCannotBeFullyResetIsNotLentAgain() throws SQLException {
        Recording source = new Recording();
        try (SeclumePool pool = new SeclumePool(source, settings(0))) {
            Connection borrowed = pool.getConnection();
            Recording.Physical physical = source.physical.getFirst();
            Counting reset = new Counting();
            reset.answer = false;
            physical.stub.sessionReset = reset;
            use(borrowed);
            borrowed.close();
            assertTrue(physical.stub.closed.get(), "closed rather than lent with another's state");
            try (Connection next = pool.getConnection()) {
                assertNotSame(physical.connection, ((PooledConnection) next).delegate());
            }
        }
    }

    // ---- the handle the driver names ---------------------------------------

    /** After the return no statement of the driver's may name a handle that is not the borrower's any more. */
    @Test
    void theDriverIsToldTheHandleOnBorrowAndForgetsItOnReturn() throws SQLException {
        Recording source = new Recording();
        try (SeclumePool pool = new SeclumePool(source, settings(0))) {
            Connection borrowed = pool.getConnection();
            Recording.Physical physical = source.physical.getFirst();
            assertSame(borrowed, physical.fronts.getLast());
            borrowed.close();
            assertNull(physical.fronts.getLast(), "the returned handle is not named any more");
        }
    }

    // ---- a connection that died while borrowed --------------------------------

    @Test
    void aUsedConnectionTheDriverClosedUnderneathIsNotParked() throws SQLException {
        Recording source = new Recording();
        try (SeclumePool pool = new SeclumePool(source, settings(0))) {
            Connection borrowed = pool.getConnection();
            use(borrowed);
            Recording.Physical physical = source.physical.getFirst();
            physical.stub.closed.set(true);        // a statement ran on the driver's object and killed it
            borrowed.close();
            try (Connection next = pool.getConnection()) {
                assertNotSame(physical.connection, ((PooledConnection) next).delegate(),
                        "the dead one is not handed out again");
            }
            assertEquals(2, source.stubs.openedCount());
        }
    }

    @Test
    void aUsedLiveConnectionIsParkedAndLentAgain() throws SQLException {
        Recording source = new Recording();
        try (SeclumePool pool = new SeclumePool(source, settings(0))) {
            Connection borrowed = pool.getConnection();
            use(borrowed);
            borrowed.close();
            Recording.Physical physical = source.physical.getFirst();
            try (Connection next = pool.getConnection()) {
                assertSame(physical.connection, ((PooledConnection) next).delegate());
            }
            assertEquals(1, source.stubs.openedCount());
            assertFalse(physical.stub.closed.get());
        }
    }

    // ---- adopted mid-transaction ----------------------------------------------

    /**
     * A session handed on in the middle of its work keeps its transaction and
     * settings while it is borrowed - and gives them up on return, back to the
     * pool's own defaults, as any borrow does.
     */
    @Test
    void anAdoptedSessionKeepsItsStateWhileBorrowedAndIsResetOnReturn() throws SQLException {
        Recording source = new Recording();
        try (SeclumePool pool = new SeclumePool(source, settings(0))) {
            pool.getConnection().close();            // a connection of its own: the pool's defaults

            Recording foreignSource = new Recording();
            Connection foreign = foreignSource.getConnection();
            Recording.Physical physical = foreignSource.physical.getFirst();
            physical.stub.autoCommit = false;           // a transaction is open
            physical.stub.readOnly = true;
            physical.stub.isolation = Connection.TRANSACTION_SERIALIZABLE;
            physical.calls.clear();

            Connection handle = pool.adopt(foreign);
            assertFalse(handle.getAutoCommit(), "the transaction stays open across the hand-on");
            assertTrue(handle.isReadOnly());
            assertEquals(Connection.TRANSACTION_SERIALIZABLE, handle.getTransactionIsolation());
            assertEquals(0, physical.stub.rollbacks.get(), "nothing is reset in the middle of the work");
            assertFalse(physical.calls.stream().anyMatch(call -> call.startsWith("set")),
                    "adopting changes nothing: " + physical.calls);

            handle.close();
            assertEquals(1, physical.stub.rollbacks.get(), "the open transaction ends with the borrow");
            assertTrue(physical.stub.autoCommit);
            assertFalse(physical.stub.readOnly);
            assertEquals(Connection.TRANSACTION_READ_COMMITTED, physical.stub.isolation);
        }
    }

    @Test
    void anAdoptedSessionInThePoolsOwnStateIsLeftAlone() throws SQLException {
        Recording source = new Recording();
        try (SeclumePool pool = new SeclumePool(source, settings(0))) {
            pool.getConnection().close();
            Recording foreignSource = new Recording();
            Connection foreign = foreignSource.getConnection();
            Recording.Physical physical = foreignSource.physical.getFirst();
            physical.calls.clear();

            pool.adopt(foreign).close();
            assertEquals(0, physical.stub.rollbacks.get(), "in auto-commit, nothing is open");
            assertFalse(physical.calls.stream().anyMatch(call -> call.startsWith("set")),
                    "nothing differed, nothing is set: " + physical.calls);
        }
    }

    /**
     * A session taken over may carry what its former holder set - a tenant, a
     * role. It counts as used from the moment it is adopted, so the return
     * resets it even when the new borrower ran nothing on it.
     */
    @Test
    void anAdoptedSessionIsResetOnReturnEvenIfNothingRanOnIt() throws SQLException {
        Recording source = new Recording();
        try (SeclumePool pool = new SeclumePool(source, settings(0))) {
            Recording foreignSource = new Recording();
            Connection foreign = foreignSource.getConnection();
            Recording.Physical physical = foreignSource.physical.getFirst();
            Counting reset = new Counting();
            physical.stub.sessionReset = reset;

            pool.adopt(foreign).close();
            assertEquals(1, reset.resets, "the former holder's session state does not reach the next borrower");
        }
    }

    /**
     * A broken connection is renewed quietly only where nothing can be lost.
     * An adopted session in the middle of a transaction has work in it: a new
     * connection would silently drop that transaction, so the failure is
     * reported instead.
     */
    @Test
    void anAdoptedTransactionIsNotRenewedUnderneathWhenTheConnectionBreaks() throws SQLException {
        Recording source = new Recording();
        try (SeclumePool pool = new SeclumePool(source, settings(0))) {
            pool.getConnection().close();
            Recording foreignSource = new Recording();
            Connection foreign = foreignSource.getConnection();
            Recording.Physical physical = foreignSource.physical.getFirst();
            physical.stub.autoCommit = false;

            Connection handle = pool.adopt(foreign);
            physical.stub.broken = true;
            SQLException lost = org.junit.jupiter.api.Assertions.assertThrows(SQLException.class,
                    handle::createStatement);
            assertEquals("08006", lost.getSQLState());
            assertEquals(1, source.stubs.openedCount(), "no new connection was opened behind the transaction");
            handle.close();
        }
    }

    // ---- the recording driver ------------------------------------------------

    /** A reset that counts, and answers as told. */
    private static final class Counting implements SessionReset {
        int resets;
        boolean answer = true;

        @Override
        public boolean sessionStateChanged() {
            return false;
        }

        @Override
        public boolean resetSessionState() {
            resets++;
            return answer;
        }
    }

    /**
     * {@link StubDataSource}'s connections behind a proxy that records each
     * call by name and arguments, is the driver's {@link Fronted} side, and -
     * when asked - lists its open statements and prepares statements that a
     * cache can keep.
     */
    static final class Recording implements DataSource {
        final StubDataSource stubs = new StubDataSource();
        final List<Physical> physical = new CopyOnWriteArrayList<>();
        boolean tracksOpenStatements;
        boolean fakeStatements;

        static final class Physical {
            final StubDataSource.StubConnection stub;
            final List<String> calls = new CopyOnWriteArrayList<>();
            final List<Connection> fronts = new CopyOnWriteArrayList<>();
            final List<Statement> created = new CopyOnWriteArrayList<>();
            final List<FakePreparedStatement> statements = new CopyOnWriteArrayList<>();
            Connection connection;

            Physical(StubDataSource.StubConnection stub) {
                this.stub = stub;
            }

            List<OpenStatements.Opened> open() throws SQLException {
                List<OpenStatements.Opened> open = new ArrayList<>();
                for (Statement statement : created) {
                    if (!statement.isClosed()) {
                        open.add(new OpenStatements.Opened(statement, "select ?", null));
                    }
                }
                return open;
            }
        }

        @Override
        public Connection getConnection() throws SQLException {
            Connection inner = stubs.getConnection();
            Physical one = new Physical(stubs.handedOut().getLast());
            OpenStatements open = new OpenStatements() {
                @Override
                public List<Opened> openStatements() {
                    try {
                        return one.open();
                    } catch (SQLException e) {
                        throw new IllegalStateException(e);
                    }
                }

                @Override
                public void traceStatements(boolean on) {
                    // no traces here
                }
            };
            one.connection = (Connection) Proxy.newProxyInstance(Recording.class.getClassLoader(),
                    new Class<?>[] {Connection.class, Fronted.class}, (self, method, given) -> {
                        Object[] args = given == null ? new Object[0] : given;
                        String name = method.getName();
                        if (!name.equals("front") && !name.equals("isWrapperFor") && !name.equals("unwrap")
                                && !name.startsWith("get") && !name.startsWith("is")
                                && !name.equals("hashCode") && !name.equals("equals") && !name.equals("toString")) {
                            one.calls.add(name + java.util.Arrays.toString(args));
                        } else if (name.equals("getAutoCommit") || name.equals("isReadOnly")) {
                            one.calls.add(name);
                        }
                        switch (name) {
                            case "front":
                                one.fronts.add((Connection) args[0]);
                                return null;
                            case "isWrapperFor":
                                if (args[0] == OpenStatements.class) {
                                    return tracksOpenStatements;
                                }
                                break;
                            case "unwrap":
                                if (args[0] == OpenStatements.class && tracksOpenStatements) {
                                    return open;
                                }
                                break;
                            case "prepareStatement":
                                if (fakeStatements && args.length == 1) {
                                    FakePreparedStatement statement = new FakePreparedStatement();
                                    one.statements.add(statement);
                                    one.created.add(statement.proxy);
                                    return statement.proxy;
                                }
                                break;
                            case "createStatement":
                                Statement statement = (Statement) invoke(inner, method, args);
                                one.created.add(statement);
                                return statement;
                            case "hashCode":
                                return System.identityHashCode(self);
                            case "equals":
                                return self == args[0];
                            case "toString":
                                return "Recording";
                            default:
                                break;
                        }
                        return invoke(inner, method, args);
                    });
            physical.add(one);
            return one.connection;
        }

        private static Object invoke(Connection inner, java.lang.reflect.Method method, Object[] args)
                throws Throwable {
            try {
                return method.invoke(inner, args);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }
        }

        @Override
        public Connection getConnection(String username, String password) throws SQLException {
            throw new SQLException("not used in these tests");
        }

        @Override
        public PrintWriter getLogWriter() {
            return null;
        }

        @Override
        public void setLogWriter(PrintWriter out) {
            // not used
        }

        @Override
        public void setLoginTimeout(int seconds) {
            // not used
        }

        @Override
        public int getLoginTimeout() {
            return 0;
        }

        @Override
        public Logger getParentLogger() {
            return Logger.getGlobal();
        }

        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException {
            throw new SQLException("not a wrapper");
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) {
            return false;
        }
    }
}
