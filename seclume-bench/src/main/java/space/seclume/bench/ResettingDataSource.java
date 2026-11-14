package space.seclume.bench;

import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.util.logging.Logger;

import javax.sql.DataSource;

/**
 * A pool's connections, each reset on its close before it goes back - what an
 * application on HikariCP has to do itself to get what seclume's pool does
 * on every return: {@code DISCARD ALL} on PostgreSQL, COM_RESET_CONNECTION
 * through Connector/J's {@code resetServerState()} on MySQL. Waited for, as
 * a call on the closing thread is.
 *
 * <p>For {@link PoolBenchmark}'s {@code hikari-vendor-reset}: the comparison
 * at the same security.
 */
final class ResettingDataSource implements DataSource, AutoCloseable {

    private final DataSource pool;
    private final BenchDatabase.Kind kind;

    ResettingDataSource(DataSource pool, BenchDatabase.Kind kind) {
        if (kind != BenchDatabase.Kind.POSTGRESQL && kind != BenchDatabase.Kind.MYSQL) {
            throw new IllegalArgumentException("hikari-vendor-reset is for PostgreSQL and MySQL; "
                    + kind + " has no reset outside its own pool");
        }
        this.pool = pool;
        this.kind = kind;
    }

    private void reset(Connection connection) throws SQLException {
        if (kind == BenchDatabase.Kind.POSTGRESQL) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("discard all");
            }
        } else {
            connection.unwrap(com.mysql.cj.jdbc.JdbcConnection.class).resetServerState();
        }
    }

    @Override
    public Connection getConnection() throws SQLException {
        Connection borrowed = pool.getConnection();
        return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
                new Class<?>[] {Connection.class}, (proxy, method, args) -> {
                    if (method.getName().equals("close") && method.getParameterCount() == 0) {
                        try {
                            reset(borrowed);
                        } finally {
                            borrowed.close();
                        }
                        return null;
                    }
                    try {
                        return method.invoke(borrowed, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                });
    }

    @Override
    public Connection getConnection(String user, String password) throws SQLException {
        throw new SQLFeatureNotSupportedException("the pool's own credentials only");
    }

    @Override
    public PrintWriter getLogWriter() throws SQLException {
        return pool.getLogWriter();
    }

    @Override
    public void setLogWriter(PrintWriter out) throws SQLException {
        pool.setLogWriter(out);
    }

    @Override
    public void setLoginTimeout(int seconds) throws SQLException {
        pool.setLoginTimeout(seconds);
    }

    @Override
    public int getLoginTimeout() throws SQLException {
        return pool.getLoginTimeout();
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        return pool.getParentLogger();
    }

    @Override
    public <T> T unwrap(Class<T> type) throws SQLException {
        return pool.unwrap(type);
    }

    @Override
    public boolean isWrapperFor(Class<?> type) throws SQLException {
        return pool.isWrapperFor(type);
    }

    /** Closes the pool underneath. */
    @Override
    public void close() throws Exception {
        if (pool instanceof AutoCloseable closeable) {
            closeable.close();
        }
    }
}
