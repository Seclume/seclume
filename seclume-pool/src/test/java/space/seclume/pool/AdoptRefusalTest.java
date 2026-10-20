package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;

/**
 * A connection the pool cannot take in costs it nothing.
 *
 * <p>{@link SeclumePool#adopt} takes a permit first and asks the connection
 * for its state after. A connection that could not answer - closed, broken -
 * used to throw out of {@code adopt} with the permit still taken, and the pool
 * was one connection smaller for the rest of its life: at size 1, every later
 * adopt and every borrow was refused as "full". Found in review, 20.10.2026.
 *
 * <p>No database: the connections are stand-ins that answer the handful of
 * questions {@code adopt} asks, and the pool is never asked to open one.
 */
class AdoptRefusalTest {

    @Test
    void aConnectionThatCannotSayItsIsolationIsRefusedAndThePermitGoesBack() throws Exception {
        try (SeclumePool pool = new SeclumePool(noDatabase(), settings(1))) {
            Connection broken = connection(true);
            assertThrows(SQLException.class, () -> pool.adopt(broken));
            assertEquals(0, pool.totalCount());

            Connection working = connection(false);
            Connection handle = pool.adopt(working);
            assertEquals(1, pool.totalCount());
            assertSame(working, pool.detach(handle));
            assertEquals(0, pool.totalCount());
        }
    }

    @Test
    void manyRefusalsLeaveThePoolItsFullSize() throws Exception {
        try (SeclumePool pool = new SeclumePool(noDatabase(), settings(2))) {
            for (int i = 0; i < 10; i++) {
                assertThrows(SQLException.class, () -> pool.adopt(connection(true)));
            }
            Connection first = pool.adopt(connection(false));
            Connection second = pool.adopt(connection(false));
            assertEquals(2, pool.totalCount());
            pool.detach(first);
            pool.detach(second);
        }
    }

    private static PoolSettings settings(int max) {
        PoolSettings settings = new PoolSettings();
        settings.setName("adopt-refusal-test");
        settings.setMaximumPoolSize(max);
        settings.setStatementCacheSize(0);
        settings.setConnectionTimeout(Duration.ofSeconds(1));
        return settings;
    }

    /** A data source the pool must not need here. */
    private static DataSource noDatabase() {
        return (DataSource) Proxy.newProxyInstance(DataSource.class.getClassLoader(),
                new Class<?>[] {DataSource.class}, (proxy, method, args) -> {
                    throw new SQLException("no database in this test: " + method.getName());
                });
    }

    /**
     * A stand-in: read committed, auto-commit on, open - or, when
     * {@code broken}, one that throws for its isolation as a closed one does.
     */
    private static Connection connection(boolean broken) {
        return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
                new Class<?>[] {Connection.class}, (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getTransactionIsolation":
                            if (broken) {
                                throw new SQLException("this connection is closed", "08003");
                            }
                            return Connection.TRANSACTION_READ_COMMITTED;
                        case "getAutoCommit":
                            return true;
                        case "isReadOnly":
                        case "isClosed":
                            return false;
                        case "isValid":
                            return true;
                        case "equals":
                            return proxy == args[0];
                        case "hashCode":
                            return System.identityHashCode(proxy);
                        case "toString":
                            return broken ? "broken stand-in" : "stand-in";
                        default:
                            Class<?> type = method.getReturnType();
                            if (type == boolean.class) {
                                return false;
                            }
                            if (type == int.class) {
                                return 0;
                            }
                            if (type == long.class) {
                                return 0L;
                            }
                            return null;
                    }
                });
    }
}
