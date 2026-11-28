package space.seclume.r2dbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.sql.SQLTimeoutException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.Test;

import io.r2dbc.spi.R2dbcNonTransientResourceException;
import io.r2dbc.spi.R2dbcTimeoutException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * What an R2DBC connection does to the JDBC connection underneath, recorded
 * call by call: the lock wait timeout per database, and a refusal where
 * there is none; a transaction left open at close() rolled back before the
 * close; a statement timeout set on the statement, and a driver's timeout
 * reaching the subscriber as R2dbcTimeoutException.
 */
class ConnectionContractTest {

    /** A JDBC connection that records what is asked of it. */
    private static final class Recorded {
        final List<String> calls = new CopyOnWriteArrayList<>();
        volatile boolean autoCommit = true;
        volatile int queryTimeout;
        volatile boolean timesOut;

        java.sql.Connection connection() {
            return (java.sql.Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {java.sql.Connection.class}, (self, method, args) -> {
                        String name = method.getName();
                        switch (name) {
                            case "setAutoCommit" -> autoCommit = (Boolean) args[0];
                            case "getAutoCommit" -> {
                                return autoCommit;
                            }
                            case "isClosed" -> {
                                return calls.contains("close");
                            }
                            case "createStatement" -> {
                                return statement(null);
                            }
                            case "prepareStatement" -> {
                                return statement((String) args[0]);
                            }
                            case "getMetaData" -> {
                                return Proxy.newProxyInstance(getClass().getClassLoader(),
                                        new Class<?>[] {java.sql.DatabaseMetaData.class},
                                        (m, call, a) -> call.getReturnType() == String.class
                                                ? "stand-in" : call.getReturnType() == int.class
                                                ? 0 : call.getReturnType() == boolean.class
                                                ? false : null);
                            }
                            case "getTransactionIsolation" -> {
                                return java.sql.Connection.TRANSACTION_READ_COMMITTED;
                            }
                            case "hashCode" -> {
                                return System.identityHashCode(self);
                            }
                            case "equals" -> {
                                return self == args[0];
                            }
                            default -> { }
                        }
                        calls.add(name);
                        return method.getReturnType() == boolean.class ? false
                                : method.getReturnType() == int.class ? 0 : null;
                    });
        }

        private java.sql.Statement statement(String prepared) {
            return (java.sql.Statement) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {java.sql.PreparedStatement.class}, (self, method, args) -> {
                        switch (method.getName()) {
                            case "setQueryTimeout" -> queryTimeout = (Integer) args[0];
                            case "getQueryTimeout" -> {
                                return queryTimeout;
                            }
                            case "execute", "executeQuery", "executeUpdate", "executeLargeUpdate" -> {
                                calls.add("execute " + (args == null ? prepared : args[0]));
                                if (timesOut) {
                                    throw new SQLTimeoutException("the statement did not finish "
                                            + "within the query timeout and was cancelled", "57014");
                                }
                                return method.getReturnType() == boolean.class ? false
                                        : method.getReturnType() == int.class ? 0 : null;
                            }
                            case "hashCode" -> {
                                return System.identityHashCode(self);
                            }
                            case "equals" -> {
                                return self == args[0];
                            }
                            default -> { }
                        }
                        return method.getReturnType() == boolean.class ? false
                                : method.getReturnType() == int.class ? 0 : null;
                    });
        }
    }

    private static SeclumeConnection over(Recorded recorded, Placeholders.Dialect dialect)
            throws java.sql.SQLException {
        return new SeclumeConnection(recorded.connection(), new Lane(), dialect);
    }

    @Test
    void theLockWaitTimeoutIsEachDatabasesOwnAndOracleIsRefused() throws Exception {
        String[][] expected = {
            {"POSTGRESQL", "set lock_timeout = 2500"},
            {"MYSQL", "set innodb_lock_wait_timeout = 3"},
            {"SQLSERVER", "set lock_timeout 2500"}};
        for (String[] one : expected) {
            Recorded recorded = new Recorded();
            SeclumeConnection connection = over(recorded, Placeholders.Dialect.valueOf(one[0]));
            connection.setLockWaitTimeout(Duration.ofMillis(2500)).block();
            assertTrue(recorded.calls.contains("execute " + one[1]), one[0] + ": " + recorded.calls);
            connection.close().block();
        }
        Recorded recorded = new Recorded();
        SeclumeConnection oracle = over(recorded, Placeholders.Dialect.ORACLE);
        R2dbcNonTransientResourceException refused = assertInstanceOf(
                R2dbcNonTransientResourceException.class,
                oracle.setLockWaitTimeout(Duration.ofSeconds(2)).materialize().block()
                        .getThrowable());
        assertEquals("0A000", refused.getSqlState());
        assertTrue(recorded.calls.stream().noneMatch(c -> c.startsWith("execute")),
                "something was sent to Oracle: " + recorded.calls);
        oracle.close().block();
    }

    @Test
    void anOpenTransactionIsRolledBackBeforeTheClose() throws Exception {
        Recorded recorded = new Recorded();
        SeclumeConnection connection = over(recorded, Placeholders.Dialect.POSTGRESQL);
        connection.beginTransaction().block();
        connection.close().block();
        int rollback = recorded.calls.indexOf("rollback");
        int close = recorded.calls.indexOf("close");
        assertTrue(rollback >= 0 && rollback < close,
                "the open transaction was not rolled back before the close: " + recorded.calls);

        Recorded idle = new Recorded();
        SeclumeConnection autoCommit = over(idle, Placeholders.Dialect.POSTGRESQL);
        autoCommit.close().block();
        assertTrue(!idle.calls.contains("rollback"), "a rollback without a transaction");
    }

    @Test
    void theStatementTimeoutIsSetAndADriverTimeoutIsAnR2dbcTimeout() throws Exception {
        Recorded recorded = new Recorded();
        recorded.timesOut = true;
        SeclumeConnection connection = over(recorded, Placeholders.Dialect.POSTGRESQL);
        connection.setStatementTimeout(Duration.ofMillis(1500)).block();
        Throwable failed = Flux.from(connection.createStatement("select pg_sleep(60)").execute())
                .flatMap(result -> Flux.from(result.getRowsUpdated()))
                .then().materialize().block().getThrowable();
        assertEquals(2, recorded.queryTimeout, "1.5 s rounds up to whole seconds");
        assertInstanceOf(R2dbcTimeoutException.class, failed, String.valueOf(failed));
        connection.close().block();
    }
}
