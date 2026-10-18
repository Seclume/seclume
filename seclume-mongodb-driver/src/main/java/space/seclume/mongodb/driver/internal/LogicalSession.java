package space.seclume.mongodb.driver.internal;

import java.nio.ByteBuffer;
import java.util.UUID;

import org.bson.BsonBinary;
import org.bson.BsonBinarySubType;
import org.bson.BsonBoolean;
import org.bson.BsonDocument;
import org.bson.BsonInt64;
import org.bson.BsonTimestamp;

import com.mongodb.ReadConcern;
import com.mongodb.TransactionOptions;
import com.mongodb.WriteConcern;

/**
 * A logical session as the server knows it - an {@code lsid} sent with each
 * command - and what the driver keeps for it: the transaction number, the
 * state of a transaction, and the times that make reads causally consistent.
 *
 * <p>From the driver sessions, transactions and causal consistency
 * specifications (github.com/mongodb/specifications, source/sessions,
 * source/transactions, source/causal-consistency).
 */
public final class LogicalSession {

    /** Where a transaction stands; the transactions specification's states. */
    public enum Transaction { NONE, STARTING, IN_PROGRESS, COMMITTED, ABORTED }

    private final BsonDocument lsid;
    private boolean explicit;
    private boolean causallyConsistent;
    private long transactionNumber;
    private long lastUsedNanos = System.nanoTime();
    private volatile boolean dirty;
    private Transaction transaction = Transaction.NONE;
    private TransactionOptions transactionOptions;
    private BsonTimestamp operationTime;
    private BsonDocument clusterTime;
    private BsonDocument recoveryToken;
    private ServerPool pinned;

    /**
     * A new server session. Sessions are pooled and reused (see
     * {@link Topology#acquire}): the server keeps a record per {@code lsid}
     * for half an hour, and a new one per operation would pile them up to
     * its limit.
     */
    LogicalSession(boolean explicit, boolean causallyConsistent) {
        UUID id = UUID.randomUUID();
        ByteBuffer bytes = ByteBuffer.allocate(16); // seclume-allow: a random session id, public to the server
        bytes.putLong(id.getMostSignificantBits()).putLong(id.getLeastSignificantBits());
        this.lsid = new BsonDocument("id", new BsonBinary(BsonBinarySubType.UUID_STANDARD,
                bytes.array()));
        this.explicit = explicit;
        this.causallyConsistent = causallyConsistent;
    }

    /** Taken from the pool for another use: its id and transaction number stay. */
    synchronized void reuse(boolean explicit, boolean causallyConsistent) {
        this.explicit = explicit;
        this.causallyConsistent = causallyConsistent;
        transaction = Transaction.NONE;
        transactionOptions = null;
        operationTime = null;
        clusterTime = null;
        recoveryToken = null;
        pinned = null;
    }

    /**
     * Everything the driver keeps for a logical session; the server keeps the
     * rest under the {@code lsid}. With it a session - a transaction in
     * progress included - can be carried on by another client of the same
     * servers: commands with this {@code lsid} and {@code txnNumber} continue
     * what the server already has.
     */
    public record State(BsonDocument lsid, long transactionNumber, Transaction transaction,
                        TransactionOptions transactionOptions, boolean causallyConsistent,
                        BsonTimestamp operationTime, BsonDocument clusterTime,
                        BsonDocument recoveryToken) {
    }

    public synchronized State state() {
        return new State(lsid.clone(), transactionNumber, transaction, transactionOptions,
                causallyConsistent, operationTime, clusterTime, recoveryToken);
    }

    /** A session from its {@link #state}; explicit, as only an explicit session has one to carry. */
    public static LogicalSession of(State state) {
        LogicalSession session = new LogicalSession(state.lsid(), state.causallyConsistent());
        session.transactionNumber = state.transactionNumber();
        session.transaction = state.transaction();
        session.transactionOptions = state.transactionOptions();
        session.operationTime = state.operationTime();
        session.clusterTime = state.clusterTime();
        session.recoveryToken = state.recoveryToken();
        return session;
    }

    private LogicalSession(BsonDocument lsid, boolean causallyConsistent) {
        this.lsid = lsid;
        this.explicit = true;
        this.causallyConsistent = causallyConsistent;
    }

    public BsonDocument lsid() {
        return lsid;
    }

    public synchronized boolean explicit() {
        return explicit;
    }

    public synchronized boolean causallyConsistent() {
        return causallyConsistent;
    }

    public synchronized long transactionNumber() {
        return transactionNumber;
    }

    public synchronized long advanceTransactionNumber() {
        return ++transactionNumber;
    }

    /** After a network error the server may hold state for it the driver cannot know: not reused. */
    public void markDirty() {
        dirty = true;
    }

    public boolean dirty() {
        return dirty;
    }

    void used() {
        lastUsedNanos = System.nanoTime();
    }

    long lastUsedNanos() {
        return lastUsedNanos;
    }

    // ---- transactions -------------------------------------------------------

    public synchronized Transaction transaction() {
        return transaction;
    }

    public synchronized boolean inTransaction() {
        return transaction == Transaction.STARTING || transaction == Transaction.IN_PROGRESS;
    }

    public synchronized TransactionOptions transactionOptions() {
        return transactionOptions;
    }

    public synchronized void startTransaction(TransactionOptions options) {
        if (inTransaction()) {
            throw new IllegalStateException("a transaction is already in progress");
        }
        WriteConcern concern = options.getWriteConcern();
        if (concern != null && !concern.isAcknowledged()) {
            throw new IllegalArgumentException("a transaction's write concern must be "
                    + "acknowledged, not " + concern);
        }
        transactionOptions = options;
        transactionNumber++;
        transaction = Transaction.STARTING;
        recoveryToken = null;
        pinned = null;
    }

    synchronized void transactionSent() {
        if (transaction == Transaction.STARTING) {
            transaction = Transaction.IN_PROGRESS;
        }
    }

    synchronized void transactionEnded(Transaction how) {
        transaction = how;
    }

    synchronized ServerPool pinned() {
        return pinned;
    }

    synchronized void pin(ServerPool server) {
        pinned = server;
    }

    synchronized BsonDocument recoveryToken() {
        return recoveryToken;
    }

    synchronized void recoveryToken(BsonDocument token) {
        recoveryToken = token;
    }

    // ---- causal consistency -------------------------------------------------

    public synchronized BsonTimestamp operationTime() {
        return operationTime;
    }

    public synchronized void advanceOperationTime(BsonTimestamp time) {
        if (time != null && (operationTime == null || time.compareTo(operationTime) > 0)) {
            operationTime = time;
        }
    }

    public synchronized BsonDocument clusterTime() {
        return clusterTime;
    }

    public synchronized void advanceClusterTime(BsonDocument time) {
        clusterTime = Topology.later(clusterTime, time);
    }

    /**
     * What a command carries for this session: the {@code lsid}, and in a
     * transaction its number and {@code autocommit: false} - with
     * {@code startTransaction} and the read concern on the first command only.
     * Inside a transaction no command has a write concern of its own; the
     * commit has the transaction's.
     *
     * @param read whether the command reads, for causal consistency
     */
    synchronized void decorate(BsonDocument command, boolean read) {
        command.put("lsid", lsid);
        if (inTransaction()) {
            command.put("txnNumber", new BsonInt64(transactionNumber));
            command.put("autocommit", BsonBoolean.FALSE);
            command.remove("writeConcern");
            command.remove("readConcern");
            if (transaction == Transaction.STARTING) {
                command.put("startTransaction", BsonBoolean.TRUE);
                BsonDocument readConcern = readConcernFor(transactionOptions.getReadConcern());
                if (!readConcern.isEmpty()) {
                    command.put("readConcern", readConcern);
                }
            }
            return;
        }
        if (read && causallyConsistent && operationTime != null) {
            BsonDocument readConcern = command.containsKey("readConcern")
                    ? command.getDocument("readConcern").clone() : new BsonDocument();
            readConcern.put("afterClusterTime", operationTime);
            command.put("readConcern", readConcern);
        }
    }

    private BsonDocument readConcernFor(ReadConcern concern) {
        BsonDocument readConcern = concern == null || concern.isServerDefault()
                ? new BsonDocument() : concern.asDocument().clone();
        if (causallyConsistent && operationTime != null) {
            readConcern.put("afterClusterTime", operationTime);
        }
        return readConcern;
    }
}
