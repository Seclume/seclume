package space.seclume.bench;

import java.io.PrintWriter;
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
        return new Resetting(pool.getConnection());
    }

    /**
     * The borrowed connection, with the reset in front of its close - written
     * out rather than a dynamic proxy, which this project does not use (see
     * NoReflectionTest).
     */
    private final class Resetting implements Connection {

        private final Connection borrowed;

        Resetting(Connection borrowed) {
            this.borrowed = borrowed;
        }

        @Override
        public void close() throws SQLException {
            try {
                reset(borrowed);
            } finally {
                borrowed.close();
            }
        }

        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException {
            return borrowed.unwrap(iface);
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) throws SQLException {
            return borrowed.isWrapperFor(iface);
        }

        @Override
        public java.sql.Statement createStatement() throws java.sql.SQLException {
            return borrowed.createStatement();
        }

        @Override
        public java.sql.PreparedStatement prepareStatement(String a0) throws java.sql.SQLException {
            return borrowed.prepareStatement(a0);
        }

        @Override
        public java.sql.CallableStatement prepareCall(String a0) throws java.sql.SQLException {
            return borrowed.prepareCall(a0);
        }

        @Override
        public String nativeSQL(String a0) throws java.sql.SQLException {
            return borrowed.nativeSQL(a0);
        }

        @Override
        public void setAutoCommit(boolean a0) throws java.sql.SQLException {
            borrowed.setAutoCommit(a0);
        }

        @Override
        public boolean getAutoCommit() throws java.sql.SQLException {
            return borrowed.getAutoCommit();
        }

        @Override
        public void commit() throws java.sql.SQLException {
            borrowed.commit();
        }

        @Override
        public void rollback() throws java.sql.SQLException {
            borrowed.rollback();
        }

        @Override
        public boolean isClosed() throws java.sql.SQLException {
            return borrowed.isClosed();
        }

        @Override
        public java.sql.DatabaseMetaData getMetaData() throws java.sql.SQLException {
            return borrowed.getMetaData();
        }

        @Override
        public void setReadOnly(boolean a0) throws java.sql.SQLException {
            borrowed.setReadOnly(a0);
        }

        @Override
        public boolean isReadOnly() throws java.sql.SQLException {
            return borrowed.isReadOnly();
        }

        @Override
        public void setCatalog(String a0) throws java.sql.SQLException {
            borrowed.setCatalog(a0);
        }

        @Override
        public String getCatalog() throws java.sql.SQLException {
            return borrowed.getCatalog();
        }

        @Override
        public void setTransactionIsolation(int a0) throws java.sql.SQLException {
            borrowed.setTransactionIsolation(a0);
        }

        @Override
        public int getTransactionIsolation() throws java.sql.SQLException {
            return borrowed.getTransactionIsolation();
        }

        @Override
        public java.sql.SQLWarning getWarnings() throws java.sql.SQLException {
            return borrowed.getWarnings();
        }

        @Override
        public void clearWarnings() throws java.sql.SQLException {
            borrowed.clearWarnings();
        }

        @Override
        public java.sql.Statement createStatement(int a0, int a1) throws java.sql.SQLException {
            return borrowed.createStatement(a0, a1);
        }

        @Override
        public java.sql.PreparedStatement prepareStatement(String a0, int a1, int a2) throws java.sql.SQLException {
            return borrowed.prepareStatement(a0, a1, a2);
        }

        @Override
        public java.sql.CallableStatement prepareCall(String a0, int a1, int a2) throws java.sql.SQLException {
            return borrowed.prepareCall(a0, a1, a2);
        }

        @Override
        public java.util.Map<String, Class<?>> getTypeMap() throws java.sql.SQLException {
            return borrowed.getTypeMap();
        }

        @Override
        public void setTypeMap(java.util.Map<String, Class<?>> a0) throws java.sql.SQLException {
            borrowed.setTypeMap(a0);
        }

        @Override
        public void setHoldability(int a0) throws java.sql.SQLException {
            borrowed.setHoldability(a0);
        }

        @Override
        public int getHoldability() throws java.sql.SQLException {
            return borrowed.getHoldability();
        }

        @Override
        public java.sql.Savepoint setSavepoint() throws java.sql.SQLException {
            return borrowed.setSavepoint();
        }

        @Override
        public java.sql.Savepoint setSavepoint(String a0) throws java.sql.SQLException {
            return borrowed.setSavepoint(a0);
        }

        @Override
        public void rollback(java.sql.Savepoint a0) throws java.sql.SQLException {
            borrowed.rollback(a0);
        }

        @Override
        public void releaseSavepoint(java.sql.Savepoint a0) throws java.sql.SQLException {
            borrowed.releaseSavepoint(a0);
        }

        @Override
        public java.sql.Statement createStatement(int a0, int a1, int a2) throws java.sql.SQLException {
            return borrowed.createStatement(a0, a1, a2);
        }

        @Override
        public java.sql.PreparedStatement prepareStatement(String a0, int a1, int a2, int a3) throws java.sql.SQLException {
            return borrowed.prepareStatement(a0, a1, a2, a3);
        }

        @Override
        public java.sql.CallableStatement prepareCall(String a0, int a1, int a2, int a3) throws java.sql.SQLException {
            return borrowed.prepareCall(a0, a1, a2, a3);
        }

        @Override
        public java.sql.PreparedStatement prepareStatement(String a0, int a1) throws java.sql.SQLException {
            return borrowed.prepareStatement(a0, a1);
        }

        @Override
        public java.sql.PreparedStatement prepareStatement(String a0, int[] a1) throws java.sql.SQLException {
            return borrowed.prepareStatement(a0, a1);
        }

        @Override
        public java.sql.PreparedStatement prepareStatement(String a0, String[] a1) throws java.sql.SQLException {
            return borrowed.prepareStatement(a0, a1);
        }

        @Override
        public java.sql.Clob createClob() throws java.sql.SQLException {
            return borrowed.createClob();
        }

        @Override
        public java.sql.Blob createBlob() throws java.sql.SQLException {
            return borrowed.createBlob();
        }

        @Override
        public java.sql.NClob createNClob() throws java.sql.SQLException {
            return borrowed.createNClob();
        }

        @Override
        public java.sql.SQLXML createSQLXML() throws java.sql.SQLException {
            return borrowed.createSQLXML();
        }

        @Override
        public boolean isValid(int a0) throws java.sql.SQLException {
            return borrowed.isValid(a0);
        }

        @Override
        public void setClientInfo(String a0, String a1) throws java.sql.SQLClientInfoException {
            borrowed.setClientInfo(a0, a1);
        }

        @Override
        public void setClientInfo(java.util.Properties a0) throws java.sql.SQLClientInfoException {
            borrowed.setClientInfo(a0);
        }

        @Override
        public String getClientInfo(String a0) throws java.sql.SQLException {
            return borrowed.getClientInfo(a0);
        }

        @Override
        public java.util.Properties getClientInfo() throws java.sql.SQLException {
            return borrowed.getClientInfo();
        }

        @Override
        public java.sql.Array createArrayOf(String a0, Object[] a1) throws java.sql.SQLException {
            return borrowed.createArrayOf(a0, a1);
        }

        @Override
        public java.sql.Struct createStruct(String a0, Object[] a1) throws java.sql.SQLException {
            return borrowed.createStruct(a0, a1);
        }

        @Override
        public void setSchema(String a0) throws java.sql.SQLException {
            borrowed.setSchema(a0);
        }

        @Override
        public String getSchema() throws java.sql.SQLException {
            return borrowed.getSchema();
        }

        @Override
        public void abort(java.util.concurrent.Executor a0) throws java.sql.SQLException {
            borrowed.abort(a0);
        }

        @Override
        public void setNetworkTimeout(java.util.concurrent.Executor a0, int a1) throws java.sql.SQLException {
            borrowed.setNetworkTimeout(a0, a1);
        }

        @Override
        public int getNetworkTimeout() throws java.sql.SQLException {
            return borrowed.getNetworkTimeout();
        }
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
