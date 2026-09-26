package space.seclume.pool;

import java.io.PrintWriter;
import java.sql.Array;
import java.sql.Blob;
import java.sql.CallableStatement;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.NClob;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLClientInfoException;
import java.sql.SQLWarning;
import java.sql.SQLXML;
import java.sql.Savepoint;
import java.sql.Struct;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import java.util.logging.Logger;

import javax.sql.DataSource;

/**
 * One data source for a primary and a read replica: a connection that is
 * read-only when its first statement runs goes to the replica, every other one
 * to the primary.
 *
 * <p>What every Spring application builds by hand today out of an
 * {@code AbstractRoutingDataSource} and a {@code LazyConnectionDataSourceProxy},
 * in one piece. The choice waits for the first statement because that is when
 * it is known: Spring's {@code @Transactional(readOnly = true)} calls
 * {@code setReadOnly(true)} after taking the connection, before using it.
 *
 * <p><b>Read your writes</b> ({@link #readYourWrites}): a replica is behind
 * the primary by however long replication takes, so a request that writes and
 * then reads from the replica may not see its own write. With this switched
 * on, the position of the primary is noted when a writing connection is given
 * back, and a replica connection waits until it has replayed that far before
 * its first statement - up to a limit, after which the read goes to the
 * primary instead. PostgreSQL through {@code pg_current_wal_lsn} and
 * {@code pg_last_wal_replay_lsn}; MySQL through the executed GTID set and
 * {@code WAIT_FOR_EXECUTED_GTID_SET} (GTID mode on); elsewhere the setting is
 * refused rather than ignored.
 */
public final class ReadWriteSplit implements DataSource {

    private final DataSource primary;
    private final DataSource replica;
    private volatile Duration readYourWrites;

    /** The highest primary position a writing connection left behind; 0 for none yet. */
    private final AtomicLong written = new AtomicLong();

    private final LongAdder toPrimary = new LongAdder();
    private final LongAdder toReplica = new LongAdder();
    private final LongAdder fellBack = new LongAdder();

    public ReadWriteSplit(DataSource primary, DataSource replica) {
        this.primary = primary;
        this.replica = replica;
    }

    /**
     * Reads wait until the replica has caught up with the last write, up to
     * {@code maxWait}; beyond it they go to the primary. {@code null} or zero
     * switches it off (the default).
     */
    public ReadWriteSplit readYourWrites(Duration maxWait) {
        this.readYourWrites = maxWait == null || maxWait.isZero() ? null : maxWait;
        return this;
    }

    /** Connections that went to the primary, to the replica, and reads that fell back. */
    public long[] counts() {
        return new long[] {toPrimary.sum(), toReplica.sum(), fellBack.sum()};
    }

    @Override
    public Connection getConnection() {
        return new Routing();
    }

    @Override
    public Connection getConnection(String username, String password) throws SQLException {
        throw new SQLFeatureNotSupportedException("a password as a String is refused - "
                + "configure the secret on the primary and replica data sources");
    }

    @Override
    public PrintWriter getLogWriter() throws SQLException {
        return primary.getLogWriter();
    }

    @Override
    public void setLogWriter(PrintWriter out) throws SQLException {
        primary.setLogWriter(out);
        replica.setLogWriter(out);
    }

    @Override
    public void setLoginTimeout(int seconds) throws SQLException {
        primary.setLoginTimeout(seconds);
        replica.setLoginTimeout(seconds);
    }

    @Override
    public int getLoginTimeout() throws SQLException {
        return primary.getLoginTimeout();
    }

    @Override
    public Logger getParentLogger() {
        return Logger.getLogger(ReadWriteSplit.class.getName());
    }

    @Override
    public <T> T unwrap(Class<T> type) throws SQLException {
        if (type.isInstance(this)) {
            return type.cast(this);
        }
        throw new SQLException("not a wrapper for " + type.getName());
    }

    @Override
    public boolean isWrapperFor(Class<?> type) {
        return type.isInstance(this);
    }

    // ---- the connection that decides at its first statement ---------------

    /**
     * Written out method by method rather than as a dynamic proxy: the library
     * uses no reflection, so a native image needs to be told nothing about it.
     */
    private final class Routing implements Connection {

        private Connection target;
        private boolean toThePrimary;
        private boolean closed;
        private boolean autoCommit = true;
        private boolean readOnly;
        private Integer isolation;

        @Override
        public void setAutoCommit(boolean value) throws SQLException {
            if (target == null) {
                autoCommit = value;
            } else {
                target.setAutoCommit(value);
            }
        }

        @Override
        public boolean getAutoCommit() throws SQLException {
            return target == null ? autoCommit : target.getAutoCommit();
        }

        @Override
        public void setReadOnly(boolean value) throws SQLException {
            if (target == null) {
                readOnly = value;
            } else {
                target.setReadOnly(value);
            }
        }

        @Override
        public boolean isReadOnly() throws SQLException {
            return target == null ? readOnly : target.isReadOnly();
        }

        @Override
        public void setTransactionIsolation(int level) throws SQLException {
            if (target == null) {
                isolation = level;
            } else {
                target.setTransactionIsolation(level);
            }
        }

        @Override
        public int getTransactionIsolation() throws SQLException {
            if (target == null) {
                return isolation != null ? isolation : TRANSACTION_READ_COMMITTED;
            }
            return target.getTransactionIsolation();
        }

        @Override
        public void commit() throws SQLException {
            if (target == null) {
                return;                                   // nothing has run, nothing to end
            }
            target.commit();
            if (toThePrimary && readYourWrites != null) {
                noteWrite(target);
            }
        }

        @Override
        public void rollback() throws SQLException {
            if (target != null) {
                target.rollback();
            }
        }

        @Override
        public SQLWarning getWarnings() throws SQLException {
            return target == null ? null : target.getWarnings();
        }

        @Override
        public void clearWarnings() throws SQLException {
            if (target != null) {
                target.clearWarnings();
            }
        }

        @Override
        public boolean isValid(int timeout) throws SQLException {
            return target == null ? !closed : target.isValid(timeout);
        }

        @Override
        public boolean isClosed() throws SQLException {
            return closed || target != null && target.isClosed();
        }

        @Override
        public void setClientInfo(String name, String value) throws SQLClientInfoException {
            try {
                target().setClientInfo(name, value);
            } catch (SQLClientInfoException e) {
                throw e;
            } catch (SQLException e) {
                throw new SQLClientInfoException(e.getMessage(), e.getSQLState(), null, e);
            }
        }

        @Override
        public void setClientInfo(java.util.Properties properties) throws SQLClientInfoException {
            try {
                target().setClientInfo(properties);
            } catch (SQLClientInfoException e) {
                throw e;
            } catch (SQLException e) {
                throw new SQLClientInfoException(e.getMessage(), e.getSQLState(), null, e);
            }
        }

        @Override
        public <T> T unwrap(Class<T> type) throws SQLException {
            if (type.isInstance(this)) {
                return type.cast(this);
            }
            return target().unwrap(type);
        }

        @Override
        public boolean isWrapperFor(Class<?> type) throws SQLException {
            return type.isInstance(this) || target().isWrapperFor(type);
        }

        @Override
        public String toString() {
            return "ReadWriteSplit connection -> " + (target == null ? "not chosen yet"
                    : toThePrimary ? "primary" : "replica");
        }

        @Override
        public Statement createStatement() throws SQLException {
            return target().createStatement();
        }

        @Override
        public PreparedStatement prepareStatement(String sql) throws SQLException {
            return target().prepareStatement(sql);
        }

        @Override
        public CallableStatement prepareCall(String sql) throws SQLException {
            return target().prepareCall(sql);
        }

        @Override
        public String nativeSQL(String sql) throws SQLException {
            return target().nativeSQL(sql);
        }

        @Override
        public DatabaseMetaData getMetaData() throws SQLException {
            return target().getMetaData();
        }

        @Override
        public void setCatalog(String catalog) throws SQLException {
            target().setCatalog(catalog);
        }

        @Override
        public String getCatalog() throws SQLException {
            return target().getCatalog();
        }

        @Override
        public Statement createStatement(int type, int concurrency) throws SQLException {
            return target().createStatement(type, concurrency);
        }

        @Override
        public PreparedStatement prepareStatement(String sql, int type, int concurrency) throws SQLException {
            return target().prepareStatement(sql, type, concurrency);
        }

        @Override
        public CallableStatement prepareCall(String sql, int type, int concurrency) throws SQLException {
            return target().prepareCall(sql, type, concurrency);
        }

        @Override
        public java.util.Map<String, Class<?>> getTypeMap() throws SQLException {
            return target().getTypeMap();
        }

        @Override
        public void setTypeMap(java.util.Map<String, Class<?>> map) throws SQLException {
            target().setTypeMap(map);
        }

        @Override
        public void setHoldability(int holdability) throws SQLException {
            target().setHoldability(holdability);
        }

        @Override
        public int getHoldability() throws SQLException {
            return target().getHoldability();
        }

        @Override
        public Savepoint setSavepoint() throws SQLException {
            return target().setSavepoint();
        }

        @Override
        public Savepoint setSavepoint(String name) throws SQLException {
            return target().setSavepoint(name);
        }

        @Override
        public void rollback(Savepoint savepoint) throws SQLException {
            target().rollback(savepoint);
        }

        @Override
        public void releaseSavepoint(Savepoint savepoint) throws SQLException {
            target().releaseSavepoint(savepoint);
        }

        @Override
        public Statement createStatement(int type, int concurrency, int holdability) throws SQLException {
            return target().createStatement(type, concurrency, holdability);
        }

        @Override
        public PreparedStatement prepareStatement(String sql, int type, int concurrency, int holdability) throws SQLException {
            return target().prepareStatement(sql, type, concurrency, holdability);
        }

        @Override
        public CallableStatement prepareCall(String sql, int type, int concurrency, int holdability) throws SQLException {
            return target().prepareCall(sql, type, concurrency, holdability);
        }

        @Override
        public PreparedStatement prepareStatement(String sql, int keys) throws SQLException {
            return target().prepareStatement(sql, keys);
        }

        @Override
        public PreparedStatement prepareStatement(String sql, int[] columns) throws SQLException {
            return target().prepareStatement(sql, columns);
        }

        @Override
        public PreparedStatement prepareStatement(String sql, String[] columns) throws SQLException {
            return target().prepareStatement(sql, columns);
        }

        @Override
        public Clob createClob() throws SQLException {
            return target().createClob();
        }

        @Override
        public Blob createBlob() throws SQLException {
            return target().createBlob();
        }

        @Override
        public NClob createNClob() throws SQLException {
            return target().createNClob();
        }

        @Override
        public SQLXML createSQLXML() throws SQLException {
            return target().createSQLXML();
        }

        @Override
        public String getClientInfo(String name) throws SQLException {
            return target().getClientInfo(name);
        }

        @Override
        public java.util.Properties getClientInfo() throws SQLException {
            return target().getClientInfo();
        }

        @Override
        public Array createArrayOf(String type, Object[] elements) throws SQLException {
            return target().createArrayOf(type, elements);
        }

        @Override
        public Struct createStruct(String type, Object[] attributes) throws SQLException {
            return target().createStruct(type, attributes);
        }

        @Override
        public void setSchema(String schema) throws SQLException {
            target().setSchema(schema);
        }

        @Override
        public String getSchema() throws SQLException {
            return target().getSchema();
        }

        @Override
        public void abort(java.util.concurrent.Executor executor) throws SQLException {
            target().abort(executor);
        }

        @Override
        public void setNetworkTimeout(java.util.concurrent.Executor executor, int millis) throws SQLException {
            target().setNetworkTimeout(executor, millis);
        }

        @Override
        public int getNetworkTimeout() throws SQLException {
            return target().getNetworkTimeout();
        }

        private Connection target() throws SQLException {
            if (closed) {
                throw new SQLException("this connection is closed", "08003");
            }
            if (target != null) {
                return target;
            }
            Duration wait = readYourWrites;
            if (readOnly) {
                Connection candidate = replica.getConnection();
                if (wait == null || caughtUp(candidate, wait)) {
                    target = candidate;
                    toThePrimary = false;
                    toReplica.increment();
                } else {
                    candidate.close();
                    fellBack.increment();
                }
            }
            if (target == null) {
                target = primary.getConnection();
                toThePrimary = true;
                toPrimary.increment();
            }
            target.setAutoCommit(autoCommit);
            if (isolation != null) {
                target.setTransactionIsolation(isolation);
            }
            target.setReadOnly(readOnly);
            return target;
        }

        @Override
        public void close() throws SQLException {
            if (closed) {
                return;
            }
            closed = true;
            if (target == null) {
                return;
            }
            try {
                // In auto-commit every statement committed itself; a
                // transaction noted its position at commit.
                if (toThePrimary && !readOnly && readYourWrites != null
                        && target.getAutoCommit()) {
                    noteWrite(target);
                }
            } finally {
                target.close();
            }
        }
    }

    /** The last executed GTID set a writing MySQL connection left behind; null for none. */
    private final java.util.concurrent.atomic.AtomicReference<String> writtenGtids =
            new java.util.concurrent.atomic.AtomicReference<>();

    /** Notes how far the primary is, after a write. */
    private void noteWrite(Connection primary) throws SQLException {
        switch (dialect(primary)) {
            case POSTGRESQL -> written.accumulateAndGet(
                    parseLsn(one(primary, "select pg_current_wal_lsn()")), Math::max);
            case MYSQL -> {
                String executed = one(primary, "select @@global.gtid_executed");
                if (executed != null && !executed.isBlank()) {
                    // Cumulative on the primary: the latest read holds the ones before.
                    writtenGtids.set(executed.replace("\n", "").trim());
                }
            }
        }
    }

    /** Whether {@code replica} has applied the last noted write, waited for up to {@code wait}. */
    private boolean caughtUp(Connection replica, Duration wait) throws SQLException {
        return switch (dialect(replica)) {
            case POSTGRESQL -> caughtUpWal(replica, written.get(), wait);
            case MYSQL -> {
                String gtids = writtenGtids.get();
                if (gtids == null) {
                    yield true;
                }
                // One call, and the server does the waiting: 0 applied, 1 timed out.
                try (java.sql.PreparedStatement statement = replica.prepareStatement(
                        "select WAIT_FOR_EXECUTED_GTID_SET(?, ?)")) {
                    statement.setString(1, gtids);
                    statement.setBigDecimal(2, java.math.BigDecimal.valueOf(wait.toMillis(), 3));
                    try (ResultSet rows = statement.executeQuery()) {
                        rows.next();
                        yield rows.getInt(1) == 0;
                    }
                }
            }
        };
    }

    private static boolean caughtUpWal(Connection replica, long position, Duration wait)
            throws SQLException {
        if (position == 0) {
            return true;
        }
        long deadline = System.nanoTime() + wait.toNanos();
        while (true) {
            if (parseLsn(one(replica, "select pg_last_wal_replay_lsn()")) >= position) {
                return true;
            }
            if (System.nanoTime() - deadline >= 0) {
                return false;
            }
            try {
                Thread.sleep(5);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
    }

    private enum Dialect { POSTGRESQL, MYSQL }

    private static Dialect dialect(Connection connection) throws SQLException {
        String product = String.valueOf(connection.getMetaData().getDatabaseProductName())
                .toLowerCase(java.util.Locale.ROOT);
        String version = String.valueOf(connection.getMetaData().getDatabaseProductVersion())
                .toLowerCase(java.util.Locale.ROOT);
        if (product.contains("postgres")) {
            return Dialect.POSTGRESQL;
        }
        if (product.contains("mysql") && !version.contains("mariadb")) {
            return Dialect.MYSQL;
        }
        throw new SQLFeatureNotSupportedException("read-your-writes knows PostgreSQL's log "
                + "positions and MySQL's GTIDs - this is " + product + " " + version);
    }

    private static String one(Connection connection, String query) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(query)) {
            rows.next();
            return rows.getString(1);
        }
    }

    static long parseLsn(String lsn) {
        if (lsn == null) {
            return 0;
        }
        int slash = lsn.indexOf('/');
        return (Long.parseLong(lsn.substring(0, slash), 16) << 32)
                | Long.parseLong(lsn.substring(slash + 1), 16);
    }
}
