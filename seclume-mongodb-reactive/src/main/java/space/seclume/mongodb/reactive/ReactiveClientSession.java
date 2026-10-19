package space.seclume.mongodb.reactive;

import org.bson.BsonDocument;
import org.bson.BsonTimestamp;
import org.reactivestreams.Publisher;

import com.mongodb.ClientSessionOptions;
import com.mongodb.ServerAddress;
import com.mongodb.TransactionOptions;
import com.mongodb.session.ServerSession;

/**
 * A reactive session over a sync one. Its commands may run on different
 * worker threads one after the other; the sync session's state is
 * synchronized, so that is safe - and a transaction started here is the same
 * transaction for every publisher given this session.
 */
final class ReactiveClientSession implements com.mongodb.reactivestreams.client.ClientSession {

    final com.mongodb.client.ClientSession sync;

    ReactiveClientSession(com.mongodb.client.ClientSession sync) {
        this.sync = sync;
    }

    @Override
    public Publisher<Void> commitTransaction() {
        return Publishers.run(sync::commitTransaction);
    }

    @Override
    public Publisher<Void> abortTransaction() {
        return Publishers.run(sync::abortTransaction);
    }

    @Override
    public boolean hasActiveTransaction() {
        return sync.hasActiveTransaction();
    }

    @Override
    public boolean notifyMessageSent() {
        return sync.notifyMessageSent();
    }

    @Override
    public void notifyOperationInitiated(Object operation) {
        sync.notifyOperationInitiated(operation);
    }

    @Override
    public TransactionOptions getTransactionOptions() {
        return sync.getTransactionOptions();
    }

    @Override
    public void startTransaction() {
        sync.startTransaction();
    }

    @Override
    public void startTransaction(TransactionOptions options) {
        sync.startTransaction(options);
    }

    @Override
    public com.mongodb.internal.observability.micrometer.TransactionSpan getTransactionSpan() {
        return null;
    }

    @Override
    public ServerAddress getPinnedServerAddress() {
        return sync.getPinnedServerAddress();
    }

    @Override
    public Object getTransactionContext() {
        return sync.getTransactionContext();
    }

    @Override
    public void setTransactionContext(ServerAddress address, Object context) {
        sync.setTransactionContext(address, context);
    }

    @Override
    public void clearTransactionContext() {
        sync.clearTransactionContext();
    }

    @Override
    public BsonDocument getRecoveryToken() {
        return sync.getRecoveryToken();
    }

    @Override
    public void setRecoveryToken(BsonDocument token) {
        sync.setRecoveryToken(token);
    }

    @Override
    public ClientSessionOptions getOptions() {
        return sync.getOptions();
    }

    @Override
    public boolean isCausallyConsistent() {
        return sync.isCausallyConsistent();
    }

    @Override
    public Object getOriginator() {
        return sync.getOriginator();
    }

    @Override
    public ServerSession getServerSession() {
        return sync.getServerSession();
    }

    @Override
    public BsonTimestamp getOperationTime() {
        return sync.getOperationTime();
    }

    @Override
    public void advanceOperationTime(BsonTimestamp time) {
        sync.advanceOperationTime(time);
    }

    @Override
    public void advanceClusterTime(BsonDocument time) {
        sync.advanceClusterTime(time);
    }

    @Override
    public void setSnapshotTimestamp(BsonTimestamp time) {
        sync.setSnapshotTimestamp(time);
    }

    @Override
    public BsonTimestamp getSnapshotTimestamp() {
        return sync.getSnapshotTimestamp();
    }

    @Override
    public BsonDocument getClusterTime() {
        return sync.getClusterTime();
    }

    @Override
    public void close() {
        sync.close();
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
