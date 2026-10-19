package space.seclume.mongodb.reactive;

/**
 * Generated from the reactive and the sync API: every method of
 * {@code com.mongodb.reactivestreams.client.ListSearchIndexesPublisher} on {@code com.mongodb.client.ListSearchIndexesIterable} (see Publishers for how a call becomes a
 * publisher). Regenerate rather than edit.
 */
@SuppressWarnings({"deprecation", "unchecked", "rawtypes"})
final class ListSearchIndexesPublisherImpl<TResult> extends IterablePublisher<TResult> implements com.mongodb.reactivestreams.client.ListSearchIndexesPublisher<TResult> {

    private final com.mongodb.client.ListSearchIndexesIterable<TResult> sync;

    ListSearchIndexesPublisherImpl(com.mongodb.client.ListSearchIndexesIterable<TResult> sync) {
        super(sync);
        this.sync = sync;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListSearchIndexesPublisher<TResult> name(java.lang.String arg0) {
        sync.name(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListSearchIndexesPublisher<TResult> allowDiskUse(java.lang.Boolean arg0) {
        sync.allowDiskUse(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListSearchIndexesPublisher<TResult> batchSize(int arg0) {
        sync.batchSize(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListSearchIndexesPublisher<TResult> maxTime(long arg0, java.util.concurrent.TimeUnit arg1) {
        sync.maxTime(arg0, arg1);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListSearchIndexesPublisher<TResult> collation(com.mongodb.client.model.Collation arg0) {
        sync.collation(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListSearchIndexesPublisher<TResult> comment(java.lang.String arg0) {
        sync.comment(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListSearchIndexesPublisher<TResult> comment(org.bson.BsonValue arg0) {
        sync.comment(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListSearchIndexesPublisher<TResult> timeoutMode(com.mongodb.client.cursor.TimeoutMode arg0) {
        sync.timeoutMode(arg0);
        return this;
    }

    @Override
    public org.reactivestreams.Publisher<TResult> first() {
        return Publishers.single(() -> sync.first());
    }

    @Override
    public org.reactivestreams.Publisher<org.bson.Document> explain() {
        return Publishers.single(() -> sync.explain());
    }

    @Override
    public org.reactivestreams.Publisher<org.bson.Document> explain(com.mongodb.ExplainVerbosity arg0) {
        return Publishers.single(() -> sync.explain(arg0));
    }

    @Override
    public <E> org.reactivestreams.Publisher<E> explain(java.lang.Class<E> arg0) {
        return Publishers.single(() -> sync.explain(arg0));
    }

    @Override
    public <E> org.reactivestreams.Publisher<E> explain(java.lang.Class<E> arg0, com.mongodb.ExplainVerbosity arg1) {
        return Publishers.single(() -> sync.explain(arg0, arg1));
    }

}
