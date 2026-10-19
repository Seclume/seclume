package space.seclume.mongodb.driver.internal;

import java.nio.ByteBuffer;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.bson.BsonBinary;
import org.bson.BsonBinarySubType;
import org.bson.BsonBoolean;
import org.bson.BsonDocument;
import org.bson.BsonInt64;
import org.bson.BsonString;
import org.bson.BsonTimestamp;

import com.mongodb.ReadConcern;
import com.mongodb.ReadConcernLevel;
import com.mongodb.ReadPreference;
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
    private boolean snapshot;
    private BsonTimestamp snapshotTime;
    private final java.util.Set<AutoCloseable> cursors = new java.util.LinkedHashSet<>();

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
        unpin();
        snapshot = false;
        snapshotTime = null;
    }

    /**
     * A snapshot session (sessions specification, "Snapshot reads"): every
     * read sees the data as of one point in time - the first read's, which
     * the server names in its reply ({@code atClusterTime}).
     */
    public synchronized void snapshot(boolean on) {
        snapshot = on;
        snapshotTime = null;
    }

    public synchronized boolean isSnapshot() {
        return snapshot;
    }

    public synchronized BsonTimestamp snapshotTime() {
        return snapshotTime;
    }

    public synchronized void snapshotTime(BsonTimestamp time) {
        if (snapshot && snapshotTime == null) {
            snapshotTime = time;
        }
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

        /** As BSON - to be carried between processes; it holds no credential. */
        public BsonDocument toBson() {
            BsonDocument out = new BsonDocument("lsid", lsid.clone())
                    .append("txnNumber", new BsonInt64(transactionNumber))
                    .append("transaction", new BsonString(transaction.name()))
                    .append("causallyConsistent", BsonBoolean.valueOf(causallyConsistent));
            if (transactionOptions != null) {
                out.put("transactionOptions", options(transactionOptions));
            }
            if (operationTime != null) {
                out.put("operationTime", operationTime);
            }
            if (clusterTime != null) {
                out.put("clusterTime", clusterTime.clone());
            }
            if (recoveryToken != null) {
                out.put("recoveryToken", recoveryToken.clone());
            }
            return out;
        }

        /** The state {@link #toBson} wrote. */
        public static State fromBson(BsonDocument in) {
            return new State(in.getDocument("lsid").clone(),
                    in.getInt64("txnNumber").getValue(),
                    Transaction.valueOf(in.getString("transaction").getValue()),
                    in.containsKey("transactionOptions")
                            ? options(in.getDocument("transactionOptions")) : null,
                    in.getBoolean("causallyConsistent").getValue(),
                    in.containsKey("operationTime") ? in.getTimestamp("operationTime") : null,
                    in.containsKey("clusterTime") ? in.getDocument("clusterTime").clone() : null,
                    in.containsKey("recoveryToken") ? in.getDocument("recoveryToken").clone()
                            : null);
        }

        private static BsonDocument options(TransactionOptions options) {
            BsonDocument out = new BsonDocument();
            if (options.getReadConcern() != null && options.getReadConcern().getLevel() != null) {
                out.put("readConcern", new BsonString(options.getReadConcern().getLevel()
                        .getValue()));
            }
            if (options.getWriteConcern() != null) {
                out.put("writeConcern", options.getWriteConcern().asDocument());
            }
            if (options.getReadPreference() != null) {
                out.put("readPreference", new BsonString(options.getReadPreference().getName()));
            }
            Long maxCommit = options.getMaxCommitTime(TimeUnit.MILLISECONDS);
            if (maxCommit != null) {
                out.put("maxCommitTimeMS", new BsonInt64(maxCommit));
            }
            return out;
        }

        private static TransactionOptions options(BsonDocument in) {
            TransactionOptions.Builder options = TransactionOptions.builder();
            if (in.containsKey("readConcern")) {
                options.readConcern(new ReadConcern(ReadConcernLevel.fromString(
                        in.getString("readConcern").getValue())));
            }
            if (in.containsKey("writeConcern")) {
                options.writeConcern(writeConcern(in.getDocument("writeConcern")));
            }
            if (in.containsKey("readPreference")) {
                options.readPreference(ReadPreference.valueOf(
                        in.getString("readPreference").getValue()));
            }
            if (in.containsKey("maxCommitTimeMS")) {
                options.maxCommitTime(in.getInt64("maxCommitTimeMS").getValue(),
                        TimeUnit.MILLISECONDS);
            }
            return options.build();
        }

        private static WriteConcern writeConcern(BsonDocument in) {
            WriteConcern concern = WriteConcern.ACKNOWLEDGED;
            if (in.containsKey("w")) {
                concern = in.get("w").isString()
                        ? new WriteConcern(in.getString("w").getValue())
                        : new WriteConcern(in.getNumber("w").intValue());
            }
            if (in.containsKey("wtimeout")) {
                concern = concern.withWTimeout(in.getNumber("wtimeout").longValue(),
                        TimeUnit.MILLISECONDS);
            }
            if (in.containsKey("j")) {
                concern = concern.withJournal(in.getBoolean("j").getValue());
            }
            return concern;
        }
    }

    /**
     * Why this session cannot be carried on elsewhere, or null when it can:
     * a snapshot session reads at a time the next client would not know to
     * keep, and a transaction pinned to one mongos lives on that mongos only.
     */
    public synchronized String notCarriable() {
        if (snapshot) {
            return "a snapshot session";
        }
        if (pinned != null && inTransaction()) {
            return "a transaction pinned to one mongos";
        }
        return null;
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

    /**
     * A cursor opened under this session. A cursor belongs to its
     * {@code lsid}, and the session is pooled: one left open would be
     * reachable to the next user of the same server session, so the session
     * closes what is still open when it ends ({@link #closeCursors}).
     */
    public synchronized void opened(AutoCloseable cursor) {
        cursors.add(cursor);
    }

    public synchronized void ended(AutoCloseable cursor) {
        cursors.remove(cursor);
    }

    /** Closes - kills on the server - every cursor still open under this session. */
    public void closeCursors() {
        java.util.List<AutoCloseable> open;
        synchronized (this) {
            open = new java.util.ArrayList<>(cursors);
            cursors.clear();
        }
        for (AutoCloseable cursor : open) {
            try {
                cursor.close();
            } catch (Exception ignored) {
                // killCursors is best effort; the server ends the cursor with the session
            }
        }
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
        if (snapshot) {
            throw new IllegalStateException("transactions are not supported in a snapshot "
                    + "session");
        }
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
        unpin();
    }

    synchronized void transactionSent() {
        if (transaction == Transaction.STARTING) {
            transaction = Transaction.IN_PROGRESS;
        }
    }

    synchronized void transactionEnded(Transaction how) {
        transaction = how;
        if (pinned != null && pinned.pinned()) {
            // Behind a balancer the connection is given back with the
            // transaction's end; a mongos stays pinned for a retried commit.
            unpin();
        }
    }

    synchronized ServerPool pinned() {
        return pinned;
    }

    /**
     * Keeps the transaction on {@code server}: a mongos, or behind a load
     * balancer one connection, which the session then holds until
     * {@link #unpin}.
     */
    synchronized void pin(ServerPool server) {
        if (pinned == server) {
            return;
        }
        server.retain();
        if (pinned != null) {
            pinned.release();
        }
        pinned = server;
    }

    /** Lets go of the pinned server, giving a held connection back. */
    synchronized void unpin() {
        if (pinned != null) {
            pinned.release();
            pinned = null;
        }
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
        if (read && snapshot) {
            BsonDocument readConcern = new BsonDocument("level",
                    new org.bson.BsonString("snapshot"));
            if (snapshotTime != null) {
                readConcern.put("atClusterTime", snapshotTime);
            }
            command.put("readConcern", readConcern);
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
