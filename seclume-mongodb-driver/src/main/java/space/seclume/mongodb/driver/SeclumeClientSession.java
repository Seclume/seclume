package space.seclume.mongodb.driver;

import java.util.concurrent.TimeUnit;

import org.bson.BsonDocument;
import org.bson.BsonTimestamp;

import com.mongodb.ClientSessionOptions;
import com.mongodb.MongoException;
import com.mongodb.ServerAddress;
import com.mongodb.TransactionOptions;
import com.mongodb.client.ClientSession;
import com.mongodb.client.TransactionBody;
import com.mongodb.session.ServerSession;

import space.seclume.mongodb.driver.internal.LogicalSession;
import space.seclume.mongodb.driver.internal.Topology;

/**
 * An explicit session: causal consistency and transactions. It is handed to
 * the API's methods that take a {@link ClientSession}; a session of another
 * driver is refused there.
 */
final class SeclumeClientSession implements ClientSession {

    /** {@code withTransaction} gives up retrying after this long, as the specification says. */
    private static final long WITH_TRANSACTION_LIMIT_MILLIS = 120_000;
    private static final int MAX_TIME_EXPIRED = 50;

    private final Topology topology;
    private final LogicalSession session;
    private final ClientSessionOptions options;
    private final Object originator;
    private final TransactionOptions clientDefaults;
    private volatile boolean closed;

    /** {@code timeoutMS} of the client or the session; null for none. */
    private final Long timeoutMillis;

    /** A session that carries on what another client handed off; see {@link SeclumeSessions}. */
    SeclumeClientSession(Topology topology, LogicalSession.State state, Object originator,
            TransactionOptions clientDefaults, Long timeoutMillis) {
        this.timeoutMillis = timeoutMillis;
        this.topology = topology;
        this.options = ClientSessionOptions.builder()
                .causallyConsistent(state.causallyConsistent()).build();
        this.originator = originator;
        this.clientDefaults = clientDefaults;
        this.session = LogicalSession.of(state);
    }

    SeclumeClientSession(Topology topology, ClientSessionOptions options, Object originator,
            TransactionOptions clientDefaults, Long timeoutMillis) {
        this.timeoutMillis = timeoutMillis;
        boolean snapshot = Boolean.TRUE.equals(options.isSnapshot());
        if (snapshot && Boolean.TRUE.equals(options.isCausallyConsistent())) {
            throw new IllegalArgumentException("a session is either causally consistent or a "
                    + "snapshot session, not both");
        }
        this.topology = topology;
        this.options = options;
        this.originator = originator;
        this.clientDefaults = clientDefaults;
        this.session = topology.acquire(true, !snapshot
                && (options.isCausallyConsistent() == null || options.isCausallyConsistent()));
        this.session.snapshot(snapshot);
    }

    /** The session behind an API argument; {@code null} for none. */
    static LogicalSession of(ClientSession session, Topology topology) {
        if (session == null) {
            return null;
        }
        if (!(session instanceof SeclumeClientSession ours) || ours.topology != topology) {
            throw new IllegalArgumentException("the session was started by another client");
        }
        if (ours.closed) {
            throw new IllegalStateException("the session is closed");
        }
        return ours.session;
    }

    @Override
    public ServerAddress getPinnedServerAddress() {
        return null;
    }

    @Override
    public boolean hasActiveTransaction() {
        return session.inTransaction();
    }

    @Override
    public boolean notifyMessageSent() {
        return false;
    }

    @Override
    public void notifyOperationInitiated(Object operation) {
        // the driver's own bookkeeping; nothing here needs it
    }

    @Override
    public TransactionOptions getTransactionOptions() {
        if (!session.inTransaction()) {
            throw new IllegalStateException("there is no transaction in progress");
        }
        return session.transactionOptions();
    }

    @Override
    public void startTransaction() {
        startTransaction(TransactionOptions.builder().build());
    }

    /** The options given, then the session's defaults, then the client's - the specification's order. */
    @Override
    public void startTransaction(TransactionOptions transactionOptions) {
        TransactionOptions merged = TransactionOptions.merge(TransactionOptions.merge(
                transactionOptions, options.getDefaultTransactionOptions()), clientDefaults);
        session.startTransaction(merged);
    }

    @Override
    public void commitTransaction() {
        topology.commit(session);
    }

    @Override
    public void abortTransaction() {
        topology.abort(session);
    }

    @Override
    public <T> T withTransaction(TransactionBody<T> body) {
        return withTransaction(body, TransactionOptions.builder().build());
    }

    /**
     * The convenient transaction API: the body is run again after a
     * transient error, the commit is retried after an unknown result, both
     * until two minutes have passed (transactions-convenient-api specification).
     */
    @Override
    public <T> T withTransaction(TransactionBody<T> body, TransactionOptions transactionOptions) {
        long start = System.nanoTime();
        outer:
        while (true) {
            startTransaction(transactionOptions);
            T result;
            try {
                result = body.execute();
            } catch (RuntimeException e) {
                if (session.inTransaction()) {
                    abortTransaction();
                }
                if (e instanceof MongoException mongo
                        && mongo.hasErrorLabel(MongoException.TRANSIENT_TRANSACTION_ERROR_LABEL)
                        && within(start)) {
                    continue;
                }
                throw e;
            }
            if (!session.inTransaction()) {
                return result;                           // the body ended it itself
            }
            while (true) {
                try {
                    commitTransaction();
                    return result;
                } catch (MongoException e) {
                    if (e.hasErrorLabel(MongoException.UNKNOWN_TRANSACTION_COMMIT_RESULT_LABEL)
                            && within(start) && !maxTimeExpired(e)) {
                        continue;
                    }
                    if (e.hasErrorLabel(MongoException.TRANSIENT_TRANSACTION_ERROR_LABEL)
                            && within(start)) {
                        continue outer;
                    }
                    throw e;
                }
            }
        }
    }

    /** Two minutes - or timeoutMS, which replaces them (client-side operations timeout). */
    private boolean within(long start) {
        long limit = timeoutMillis != null && timeoutMillis > 0 ? timeoutMillis
                : WITH_TRANSACTION_LIMIT_MILLIS;
        return System.nanoTime() - start < TimeUnit.MILLISECONDS.toNanos(limit);
    }

    private static boolean maxTimeExpired(MongoException e) {
        return e.getCode() == MAX_TIME_EXPIRED;
    }

    @Override
    public com.mongodb.internal.observability.micrometer.TransactionSpan getTransactionSpan() {
        return null;
    }

    @Override
    public Object getTransactionContext() {
        return null;
    }

    @Override
    public void setTransactionContext(ServerAddress address, Object context) {
        // pinning is the topology's
    }

    @Override
    public void clearTransactionContext() {
        // pinning is the topology's
    }

    @Override
    public BsonDocument getRecoveryToken() {
        return null;
    }

    @Override
    public void setRecoveryToken(BsonDocument recoveryToken) {
        // kept by the topology from the replies
    }

    @Override
    public ClientSessionOptions getOptions() {
        return options;
    }

    @Override
    public boolean isCausallyConsistent() {
        return session.causallyConsistent();
    }

    @Override
    public Object getOriginator() {
        return originator;
    }

    @Override
    public ServerSession getServerSession() {
        return new ServerSession() {
            @Override
            public BsonDocument getIdentifier() {
                return session.lsid();
            }

            @Override
            public long getTransactionNumber() {
                return session.transactionNumber();
            }

            @Override
            public long advanceTransactionNumber() {
                return session.advanceTransactionNumber();
            }

            @Override
            public boolean isClosed() {
                return closed;
            }

            @Override
            public void markDirty() {
                session.markDirty();
            }

            @Override
            public boolean isMarkedDirty() {
                return session.dirty();
            }
        };
    }

    @Override
    public BsonTimestamp getOperationTime() {
        return session.operationTime();
    }

    @Override
    public void advanceOperationTime(BsonTimestamp operationTime) {
        session.advanceOperationTime(operationTime);
    }

    @Override
    public void advanceClusterTime(BsonDocument clusterTime) {
        session.advanceClusterTime(clusterTime);
    }

    @Override
    public void setSnapshotTimestamp(BsonTimestamp snapshotTimestamp) {
        session.snapshotTime(snapshotTimestamp);
    }

    @Override
    public BsonTimestamp getSnapshotTimestamp() {
        return session.snapshotTime();
    }

    @Override
    public BsonDocument getClusterTime() {
        return session.clusterTime();
    }

    /**
     * Lets go of the session without ending it: an open transaction stays
     * open on the server, and the server session does not go back to this
     * client's pool - whoever takes the state up uses its {@code lsid}.
     * Open cursors are closed; they are not carried.
     */
    LogicalSession.State handOff() {
        if (closed) {
            throw new IllegalStateException("the session is closed");
        }
        String why = session.notCarriable();
        if (why != null) {
            throw new IllegalStateException(why + " cannot be handed off");
        }
        closed = true;
        session.closeCursors();
        return session.state();
    }

    /** Aborts a transaction left open and gives the server session back to the pool. */
    @Override
    public void close() {
        if (closed) {
            return;
        }
        try {
            if (session.inTransaction()) {
                abortTransaction();
            }
        } finally {
            closed = true;
            session.closeCursors();
            topology.release(session);
        }
    }

    @Override
    public com.mongodb.internal.TimeoutContext getTimeoutContext() {
        return null;
    }

    @Override
    public Object getOverloadRetryPolicyState() {
        return null;
    }
}
