package space.seclume.mongodb.reactive;

/**
 * Generated from the reactive and the sync API: every method of
 * {@code com.mongodb.reactivestreams.client.ChangeStreamPublisher} on {@code com.mongodb.client.ChangeStreamIterable} (see Publishers for how a call becomes a
 * publisher). Regenerate rather than edit.
 */
@SuppressWarnings({"deprecation", "unchecked", "rawtypes"})
final class ChangeStreamPublisherImpl<TResult> extends IterablePublisher<com.mongodb.client.model.changestream.ChangeStreamDocument<TResult>> implements com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> {

    private final com.mongodb.client.ChangeStreamIterable<TResult> sync;

    ChangeStreamPublisherImpl(com.mongodb.client.ChangeStreamIterable<TResult> sync) {
        super(sync);
        this.sync = sync;
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> fullDocument(com.mongodb.client.model.changestream.FullDocument arg0) {
        sync.fullDocument(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> fullDocumentBeforeChange(com.mongodb.client.model.changestream.FullDocumentBeforeChange arg0) {
        sync.fullDocumentBeforeChange(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> resumeAfter(org.bson.BsonDocument arg0) {
        sync.resumeAfter(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> startAtOperationTime(org.bson.BsonTimestamp arg0) {
        sync.startAtOperationTime(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> startAfter(org.bson.BsonDocument arg0) {
        sync.startAfter(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> maxAwaitTime(long arg0, java.util.concurrent.TimeUnit arg1) {
        sync.maxAwaitTime(arg0, arg1);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> collation(com.mongodb.client.model.Collation arg0) {
        sync.collation(arg0);
        return this;
    }

    @Override
    public <TDocument> org.reactivestreams.Publisher<TDocument> withDocumentClass(java.lang.Class<TDocument> arg0) {
        return Publishers.many(() -> sync.withDocumentClass(arg0).cursor());
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> batchSize(int arg0) {
        sync.batchSize(arg0);
        return this;
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.model.changestream.ChangeStreamDocument<TResult>> first() {
        return Publishers.single(() -> sync.first());
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> comment(java.lang.String arg0) {
        sync.comment(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> comment(org.bson.BsonValue arg0) {
        sync.comment(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> showExpandedEvents(boolean arg0) {
        sync.showExpandedEvents(arg0);
        return this;
    }

}
