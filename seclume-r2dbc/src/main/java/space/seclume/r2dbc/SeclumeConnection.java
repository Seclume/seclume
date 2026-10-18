package space.seclume.r2dbc;

import java.sql.Savepoint;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import io.r2dbc.spi.Batch;
import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionMetadata;
import io.r2dbc.spi.IsolationLevel;
import io.r2dbc.spi.Statement;
import io.r2dbc.spi.TransactionDefinition;
import io.r2dbc.spi.ValidationDepth;
import io.r2dbc.spi.Wrapped;
import reactor.core.publisher.Mono;

/**
 * An R2DBC connection over one seclume JDBC connection, its calls in order on
 * a lane of their own (see {@link Lane}).
 *
 * <p>{@link #unwrap()} hands out the JDBC connection underneath - for what
 * R2DBC has no word for, and for moving the session elsewhere: run that as
 * a task on this connection's lane ({@link #onLane}), where nothing else
 * touches it meanwhile.
 *
 * <p>Closing it closes the JDBC connection, which a seclume pool takes back
 * - with the session reset that comes with every return.
 */
final class SeclumeConnection implements Connection, Wrapped<java.sql.Connection> {

    private final java.sql.Connection jdbc;
    private final Lane lane;
    private final Placeholders.Dialect dialect;
    private final Map<String, Savepoint> savepoints = new HashMap<>();
    private volatile boolean autoCommit = true;
    private volatile IsolationLevel isolation = IsolationLevel.READ_COMMITTED;
    private final ConnectionMetadata metadata;

    /** Made on the lane - it asks the JDBC connection what it is. */
    SeclumeConnection(java.sql.Connection jdbc, Lane lane, Placeholders.Dialect dialect)
            throws java.sql.SQLException {
        this.jdbc = jdbc;
        this.lane = lane;
        this.dialect = dialect;
        this.autoCommit = jdbc.getAutoCommit();
        this.isolation = isolation(jdbc.getTransactionIsolation());
        java.sql.DatabaseMetaData meta = jdbc.getMetaData();
        String product = meta.getDatabaseProductName();
        String version = meta.getDatabaseProductVersion();
        this.metadata = new ConnectionMetadata() {
            @Override
            public String getDatabaseProductName() {
                return product;
            }

            @Override
            public String getDatabaseVersion() {
                return version;
            }
        };
    }

    @Override
    public java.sql.Connection unwrap() {
        return jdbc;
    }

    /**
     * Runs {@code work} on this connection's lane, after everything
     * subscribed to before it and before anything after - the quiet point to
     * act on the JDBC connection directly.
     */
    public <T> Mono<T> onLane(java.util.concurrent.Callable<T> work) {
        return lane.call(work);
    }

    @Override
    public Mono<Void> beginTransaction() {
        return lane.run(() -> {
            jdbc.setAutoCommit(false);
            autoCommit = false;
        });
    }

    @Override
    public Mono<Void> beginTransaction(TransactionDefinition definition) {
        return lane.run(() -> {
            IsolationLevel level = definition.getAttribute(TransactionDefinition.ISOLATION_LEVEL);
            if (level != null) {
                jdbc.setTransactionIsolation(jdbcIsolation(level));
                isolation = level;
            }
            Boolean readOnly = definition.getAttribute(TransactionDefinition.READ_ONLY);
            if (readOnly != null) {
                jdbc.setReadOnly(readOnly);
            }
            jdbc.setAutoCommit(false);
            autoCommit = false;
        });
    }

    @Override
    public Mono<Void> commitTransaction() {
        return lane.run(() -> {
            if (!jdbc.getAutoCommit()) {
                jdbc.commit();
                jdbc.setAutoCommit(true);
                autoCommit = true;
                savepoints.clear();
            }
        });
    }

    @Override
    public Mono<Void> rollbackTransaction() {
        return lane.run(() -> {
            if (!jdbc.getAutoCommit()) {
                jdbc.rollback();
                jdbc.setAutoCommit(true);
                autoCommit = true;
                savepoints.clear();
            }
        });
    }

    @Override
    public Mono<Void> createSavepoint(String name) {
        return lane.run(() -> {
            if (jdbc.getAutoCommit()) {
                // R2DBC: a savepoint outside a transaction begins one.
                jdbc.setAutoCommit(false);
                autoCommit = false;
            }
            savepoints.put(name, jdbc.setSavepoint(name));
        });
    }

    @Override
    public Mono<Void> releaseSavepoint(String name) {
        return lane.run(() -> {
            Savepoint savepoint = savepoints.remove(name);
            if (savepoint != null) {
                jdbc.releaseSavepoint(savepoint);
            }
        });
    }

    @Override
    public Mono<Void> rollbackTransactionToSavepoint(String name) {
        return lane.run(() -> {
            Savepoint savepoint = savepoints.get(name);
            if (savepoint == null) {
                throw new java.sql.SQLException("no savepoint named '" + name + "'", "3B001");
            }
            jdbc.rollback(savepoint);
        });
    }

    @Override
    public Statement createStatement(String sql) {
        return new SeclumeStatement(jdbc, lane, sql, dialect);
    }

    @Override
    public Batch createBatch() {
        return new SeclumeBatch(jdbc, lane);
    }

    @Override
    public boolean isAutoCommit() {
        return autoCommit;
    }

    @Override
    public Mono<Void> setAutoCommit(boolean value) {
        return lane.run(() -> {
            jdbc.setAutoCommit(value);
            autoCommit = value;
        });
    }

    @Override
    public IsolationLevel getTransactionIsolationLevel() {
        return isolation;
    }

    @Override
    public Mono<Void> setTransactionIsolationLevel(IsolationLevel level) {
        return lane.run(() -> {
            jdbc.setTransactionIsolation(jdbcIsolation(level));
            isolation = level;
        });
    }

    @Override
    public Mono<Void> setLockWaitTimeout(Duration timeout) {
        // No portable JDBC call; each database has its own statement for it.
        return Mono.empty();
    }

    @Override
    public Mono<Void> setStatementTimeout(Duration timeout) {
        return Mono.empty();
    }

    @Override
    public Mono<Boolean> validate(ValidationDepth depth) {
        if (lane.isClosed()) {
            return Mono.just(false);
        }
        if (depth == ValidationDepth.LOCAL) {
            return lane.call(() -> !jdbc.isClosed()).onErrorReturn(false);
        }
        return lane.call(() -> jdbc.isValid(5)).onErrorReturn(false);
    }

    @Override
    public ConnectionMetadata getMetadata() {
        return metadata;
    }

    @Override
    public Mono<Void> close() {
        // Closing twice is nothing, as R2DBC asks.
        // The lane is closed before close() completes, not after: whoever
        // asks next - validate() in R2DBC's own suite - has to see it closed,
        // or hands a task to a thread that is about to go.
        return Mono.defer(() -> lane.isClosed() ? Mono.empty()
                : lane.run(jdbc::close)
                        .onErrorResume(failure -> Mono.fromRunnable(lane::close)
                                .then(Mono.error(failure)))
                        .then(Mono.fromRunnable(lane::close)));
    }

    private static int jdbcIsolation(IsolationLevel level) {
        if (IsolationLevel.READ_UNCOMMITTED.equals(level)) {
            return java.sql.Connection.TRANSACTION_READ_UNCOMMITTED;
        }
        if (IsolationLevel.REPEATABLE_READ.equals(level)) {
            return java.sql.Connection.TRANSACTION_REPEATABLE_READ;
        }
        if (IsolationLevel.SERIALIZABLE.equals(level)) {
            return java.sql.Connection.TRANSACTION_SERIALIZABLE;
        }
        return java.sql.Connection.TRANSACTION_READ_COMMITTED;
    }

    private static IsolationLevel isolation(int jdbcLevel) {
        return switch (jdbcLevel) {
            case java.sql.Connection.TRANSACTION_READ_UNCOMMITTED -> IsolationLevel.READ_UNCOMMITTED;
            case java.sql.Connection.TRANSACTION_REPEATABLE_READ -> IsolationLevel.REPEATABLE_READ;
            case java.sql.Connection.TRANSACTION_SERIALIZABLE -> IsolationLevel.SERIALIZABLE;
            default -> IsolationLevel.READ_COMMITTED;
        };
    }
}
