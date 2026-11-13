package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;

/**
 * The split's own decisions, against two servers that are only modelled: which
 * of them a connection goes to and when, what it is given on the way, and how
 * a read waits for the replica - without a database, so that it runs in every
 * build.
 */
class ReadWriteSplitRoutingTest {

    /** A server as far as the split asks it: its product, and its log positions. */
    private static final class Server implements DataSource {
        final String name;
        String product = "PostgreSQL";
        String version = "17.2";
        boolean inRecovery;
        String current = "0/1000";
        String replayed;
        String gtids = "";
        int waitAnswer;
        final List<String> calls = new ArrayList<>();
        int opened;
        int closed;

        Server(String name) {
            this.name = name;
        }

        private String answer(String sql) throws SQLException {
            switch (sql) {
                case "select pg_current_wal_lsn()":
                    if (inRecovery) {
                        throw new SQLException("recovery is in progress", "55000");
                    }
                    return current;
                case "select pg_last_wal_replay_lsn()":
                    return replayed;
                case "select @@global.gtid_executed":
                    return gtids;
                default:
                    if (sql.equals(ReadWriteSplit.REPLAYED)) {
                        return inRecovery ? replayed : current;
                    }
                    throw new SQLException("the model does not know: " + sql);
            }
        }

        private ResultSet rows(Object value) {
            return (ResultSet) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {ResultSet.class}, (proxy, method, arguments) ->
                    switch (method.getName()) {
                        case "next" -> true;
                        case "getString" -> (String) value;
                        case "getInt" -> (Integer) value;
                        default -> null;
                    });
        }

        @Override
        public Connection getConnection() {
            opened++;
            DatabaseMetaData metaData = (DatabaseMetaData) Proxy.newProxyInstance(
                    getClass().getClassLoader(), new Class<?>[] {DatabaseMetaData.class},
                    (proxy, method, arguments) -> switch (method.getName()) {
                        case "getDatabaseProductName" -> product;
                        case "getDatabaseProductVersion" -> version;
                        default -> null;
                    });
            boolean[] autoCommit = {true};
            return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {Connection.class}, (proxy, method, arguments) -> {
                        if (!Set.of("getMetaData", "getAutoCommit", "close")
                                .contains(method.getName())) {
                            calls.add(method.getName() + (arguments == null ? "[]"
                                    : Arrays.toString(arguments)));
                        }
                        switch (method.getName()) {
                            case "getMetaData":
                                return metaData;
                            case "createStatement":
                                if (arguments == null) {
                                    return Proxy.newProxyInstance(getClass().getClassLoader(),
                                            new Class<?>[] {Statement.class}, (p, m, a) ->
                                            m.getName().equals("executeQuery")
                                                    ? rows(answer((String) a[0])) : null);
                                }
                                break;
                            case "prepareStatement":
                                if (arguments != null && arguments.length == 1
                                        && ((String) arguments[0])
                                                .contains("WAIT_FOR_EXECUTED_GTID_SET")) {
                                    return Proxy.newProxyInstance(getClass().getClassLoader(),
                                            new Class<?>[] {PreparedStatement.class}, (p, m, a) -> {
                                                if (m.getName().startsWith("set")) {
                                                    calls.add("wait " + a[1]);
                                                }
                                                return m.getName().equals("executeQuery")
                                                        ? rows(waitAnswer) : null;
                                            });
                                }
                                return Proxy.newProxyInstance(getClass().getClassLoader(),
                                        new Class<?>[] {PreparedStatement.class}, (p, m, a) -> null);
                            case "close":
                                closed++;
                                break;
                            case "getAutoCommit":
                                return autoCommit[0];
                            case "setAutoCommit":
                                autoCommit[0] = (Boolean) Objects.requireNonNull(arguments)[0];
                                break;
                            default:
                        }
                        return some(method.getReturnType());
                    });
        }

        @Override
        public Connection getConnection(String user, String password) {
            throw new UnsupportedOperationException();
        }

        @Override
        public PrintWriter getLogWriter() {
            return null;
        }

        @Override
        public void setLogWriter(PrintWriter out) {
            calls.add("setLogWriter");
        }

        @Override
        public void setLoginTimeout(int seconds) {
            calls.add("setLoginTimeout[" + seconds + "]");
        }

        @Override
        public int getLoginTimeout() {
            return 7;
        }

        @Override
        public Logger getParentLogger() {
            return Logger.getGlobal();
        }

        @Override
        public <T> T unwrap(Class<T> type) {
            return null;
        }

        @Override
        public boolean isWrapperFor(Class<?> type) {
            return false;
        }
    }

    private static Object some(Class<?> type) {
        if (type == boolean.class) {
            return false;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == String.class) {
            return "text";
        }
        return null;
    }

    private final Server primary = new Server("primary");
    private final Server replica = new Server("replica");
    private final ReadWriteSplit split = new ReadWriteSplit(primary, replica);

    @Test
    void aConnectionNothingRanOnTakesNoneFromEitherServer() throws Exception {
        try (Connection connection = split.getConnection()) {
            assertTrue(connection.getAutoCommit());
            assertFalse(connection.isReadOnly());
            assertEquals(Connection.TRANSACTION_READ_COMMITTED,
                    connection.getTransactionIsolation());
            connection.setAutoCommit(false);
            connection.setReadOnly(true);
            connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            assertFalse(connection.getAutoCommit());
            assertTrue(connection.isReadOnly());
            assertEquals(Connection.TRANSACTION_SERIALIZABLE, connection.getTransactionIsolation());
            connection.commit();
            connection.rollback();
            connection.clearWarnings();
            assertNull(connection.getWarnings());
            assertTrue(connection.isValid(1));
            assertFalse(connection.isClosed());
            assertTrue(connection.toString().contains("not chosen yet"), connection.toString());
        }
        assertEquals(0, primary.opened + replica.opened);
        assertArrayEquals(new long[] {0, 0, 0}, split.counts());
    }

    @Test
    void readOnlyAtItsFirstStatementGoesToTheReplicaWithWhatWasSetBefore() throws Exception {
        Connection connection = split.getConnection();
        connection.setReadOnly(true);
        connection.setAutoCommit(false);
        connection.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
        try (Statement statement = connection.createStatement()) {
            assertNotNull(statement);
        }
        assertEquals(List.of("setAutoCommit[false]", "setTransactionIsolation[4]",
                "setReadOnly[true]", "createStatement[]"), replica.calls);
        assertTrue(connection.toString().endsWith("replica"), connection.toString());
        assertEquals(0, primary.opened);
        assertArrayEquals(new long[] {0, 1, 0}, split.counts());
        // Once chosen, a setting goes to the connection at once.
        connection.setAutoCommit(true);
        assertEquals("setAutoCommit[true]", replica.calls.get(replica.calls.size() - 1));
        connection.close();
        connection.close();
        assertEquals(1, replica.closed);
        assertTrue(connection.isClosed());
        SQLException closed = assertThrows(SQLException.class, connection::createStatement);
        assertEquals("08003", closed.getSQLState());
    }

    @Test
    void anythingElseGoesToThePrimary() throws Exception {
        try (Connection connection = split.getConnection()) {
            try (PreparedStatement statement = connection.prepareStatement("insert into t values (1)")) {
                assertNotNull(statement);
            }
            assertTrue(connection.toString().endsWith("primary"), connection.toString());
        }
        assertEquals(List.of("setAutoCommit[true]", "setReadOnly[false]",
                "prepareStatement[insert into t values (1)]"), primary.calls);
        assertEquals(1, primary.closed);
        assertEquals(0, replica.opened);
        assertArrayEquals(new long[] {1, 0, 0}, split.counts());
    }

    @Test
    void aPasswordAsAStringIsRefusedAndTheSettingsReachBothServers() throws Exception {
        assertThrows(SQLFeatureNotSupportedException.class,
                () -> split.getConnection("user", "password"));
        split.setLoginTimeout(3);
        split.setLogWriter(null);
        assertEquals(List.of("setLoginTimeout[3]", "setLogWriter"), primary.calls);
        assertEquals(List.of("setLoginTimeout[3]", "setLogWriter"), replica.calls);
        assertEquals(7, split.getLoginTimeout());
        assertNull(split.getLogWriter());
        assertSame(split, split.unwrap(DataSource.class));
        assertTrue(split.isWrapperFor(ReadWriteSplit.class));
        assertFalse(split.isWrapperFor(String.class));
        assertThrows(SQLException.class, () -> split.unwrap(String.class));
        assertEquals(ReadWriteSplit.class.getName(), split.getParentLogger().getName());
    }

    /** Every method of a connection reaches the server chosen, with what it was given. */
    @Test
    void everyMethodReachesTheChosenConnection() throws Exception {
        Set<String> decidedHere = Set.of("close", "isClosed", "unwrap", "isWrapperFor");
        int delegated = 0;
        for (Method method : Connection.class.getMethods()) {
            if (Modifier.isStatic(method.getModifiers()) || decidedHere.contains(method.getName())) {
                continue;
            }
            Server server = new Server("only");
            Connection connection = new ReadWriteSplit(server, server).getConnection();
            connection.nativeSQL("chosen");
            server.calls.clear();
            Object[] arguments = Arrays.stream(method.getParameterTypes())
                    .map(type -> type == int.class ? (Object) 5 : type == boolean.class ? true
                            : type == String.class ? "text" : type == long.class ? 6L : null)
                    .toArray();
            try {
                method.invoke(connection, arguments);
            } catch (InvocationTargetException thrown) {
                throw new AssertionError(method + " failed", thrown.getCause());
            }
            String expected = method.getName() + (arguments.length == 0 ? "[]"
                    : Arrays.toString(arguments));
            if (method.getName().equals("getMetaData") || method.getName().equals("getAutoCommit")) {
                continue;                       // answered by the model without a record
            }
            assertTrue(server.calls.contains(expected), method + ": " + server.calls);
            delegated++;
        }
        assertTrue(delegated > 45, "methods of a connection: " + delegated);
    }

    // ---- read your writes -------------------------------------------------

    private void write() throws SQLException {
        try (Connection connection = split.getConnection()) {
            connection.setAutoCommit(false);
            try (Statement statement = connection.createStatement()) {
                assertNotNull(statement);
            }
            connection.commit();
        }
    }

    private String read() throws SQLException {
        try (Connection connection = split.getConnection()) {
            connection.setReadOnly(true);
            try (Statement statement = connection.createStatement()) {
                assertNotNull(statement);
            }
            return connection.toString();
        }
    }

    @Test
    void aReadWaitsForTheReplicaAndGoesToThePrimaryWhenItStaysBehind() throws Exception {
        replica.inRecovery = true;
        replica.replayed = "0/0800";
        split.readYourWrites(Duration.ofMillis(40));
        assertTrue(read().endsWith("replica"), "nothing written yet: nothing to wait for");
        write();
        long before = System.nanoTime();
        assertTrue(read().endsWith("primary"), "the replica is behind the write");
        assertTrue(System.nanoTime() - before >= Duration.ofMillis(40).toNanos(), "it waited");
        assertArrayEquals(new long[] {2, 1, 1}, split.counts());
        assertEquals(replica.opened, replica.closed, "the replica's connection went back");
        replica.replayed = "0/1000";
        assertTrue(read().endsWith("replica"), "caught up");
        primary.current = "1/0";
        try (Connection autoCommit = split.getConnection()) {
            try (Statement statement = autoCommit.createStatement()) { // in auto-commit: noted when given back
                assertNotNull(statement);
            }
        }
        assertTrue(read().endsWith("primary"));
        replica.replayed = "1/0";
        assertTrue(read().endsWith("replica"));
    }

    /**
     * The primary itself as the replica - one server on a developer's machine -
     * or a standby promoted since: it has replayed nothing, and is at its own
     * position. A read goes to it at once.
     */
    @Test
    void aReplicaThatIsNotInRecoveryIsAtItsOwnPosition() throws Exception {
        replica.inRecovery = false;
        replica.replayed = null;
        replica.current = primary.current;
        split.readYourWrites(Duration.ofSeconds(3));
        write();
        long before = System.nanoTime();
        assertTrue(read().endsWith("replica"));
        assertTrue(System.nanoTime() - before < Duration.ofSeconds(2).toNanos(),
                "it did not wait for a replay that never comes");
        assertArrayEquals(new long[] {1, 1, 0}, split.counts());
    }

    @Test
    void aReplicaThatCannotSayHowFarItIsGivesItsConnectionBack() {
        replica.product = "PostgreSQL";
        replica.inRecovery = true;
        replica.replayed = "not a position";
        split.readYourWrites(Duration.ofMillis(20));
        assertThrows(SQLException.class, this::write0ThenRead);
        assertEquals(replica.opened, replica.closed);
    }

    private void write0ThenRead() throws SQLException {
        write();
        read();
    }

    @Test
    void mySqlWaitsOnTheServerForTheGtidsTheWriteLeft() throws Exception {
        primary.product = replica.product = "MySQL";
        primary.version = replica.version = "8.4.3";
        primary.gtids = "3e11fa47-71ca-11e1-9e33-c80aa9429562:1-5";
        split.readYourWrites(Duration.ofMillis(1500));
        assertTrue(read().endsWith("replica"), "nothing written yet");
        write();
        replica.waitAnswer = 0;
        assertTrue(read().endsWith("replica"));
        assertTrue(replica.calls.contains("wait 3e11fa47-71ca-11e1-9e33-c80aa9429562:1-5"),
                replica.calls.toString());
        assertTrue(replica.calls.contains("wait 1.500"), replica.calls.toString());
        replica.waitAnswer = 1;
        assertTrue(read().endsWith("primary"), "the server's wait timed out");
    }

    @Test
    void readYourWritesIsRefusedWhereTheSplitKnowsNoPosition() {
        primary.product = replica.product = "MySQL";
        primary.version = replica.version = "11.4.2-MariaDB";
        split.readYourWrites(Duration.ofMillis(20));
        assertThrows(SQLFeatureNotSupportedException.class, this::write);
        split.readYourWrites(Duration.ZERO);
        assertTrue(assertDoesNotThrowRead().endsWith("replica"), "switched off again");
    }

    private String assertDoesNotThrowRead() {
        try {
            return read();
        } catch (SQLException e) {
            throw new AssertionError(e);
        }
    }

    /** Two connections note their GTID sets in any order: the later set stays, not the last stored. */
    @Test
    void ofTwoGtidSetsTheOneWithMoreTransactionsIsTheLaterOne() {
        String earlier = "3e11fa47-71ca-11e1-9e33-c80aa9429562:1-5";
        String later = "3e11fa47-71ca-11e1-9e33-c80aa9429562:1-6";
        assertEquals(later, ReadWriteSplit.later(earlier, later));
        assertEquals(later, ReadWriteSplit.later(later, earlier));
        assertEquals(earlier, ReadWriteSplit.later(null, earlier));
        assertEquals(5, ReadWriteSplit.transactions(earlier));
        assertEquals(7, ReadWriteSplit.transactions("a:1-5:7, b:3"));
        assertEquals(3, ReadWriteSplit.transactions("a:tag:1-3"));
        assertEquals(0, ReadWriteSplit.transactions(""));
    }
}
