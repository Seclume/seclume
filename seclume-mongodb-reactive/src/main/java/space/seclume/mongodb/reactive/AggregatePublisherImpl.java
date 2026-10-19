package space.seclume.mongodb.reactive;

/**
 * Generated from the reactive and the sync API: every method of
 * {@code com.mongodb.reactivestreams.client.AggregatePublisher} on {@code com.mongodb.client.AggregateIterable} (see Publishers for how a call becomes a
 * publisher). Regenerate rather than edit.
 */
@SuppressWarnings({"deprecation", "unchecked", "rawtypes"})
final class AggregatePublisherImpl<TResult> extends IterablePublisher<TResult> implements com.mongodb.reactivestreams.client.AggregatePublisher<TResult> {

    private final com.mongodb.client.AggregateIterable<TResult> sync;

    AggregatePublisherImpl(com.mongodb.client.AggregateIterable<TResult> sync) {
        super(sync);
        this.sync = sync;
    }

    @Override
    public com.mongodb.reactivestreams.client.AggregatePublisher<TResult> allowDiskUse(java.lang.Boolean arg0) {
        sync.allowDiskUse(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.AggregatePublisher<TResult> maxTime(long arg0, java.util.concurrent.TimeUnit arg1) {
        sync.maxTime(arg0, arg1);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.AggregatePublisher<TResult> maxAwaitTime(long arg0, java.util.concurrent.TimeUnit arg1) {
        sync.maxAwaitTime(arg0, arg1);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.AggregatePublisher<TResult> bypassDocumentValidation(java.lang.Boolean arg0) {
        sync.bypassDocumentValidation(arg0);
        return this;
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> toCollection() {
        return Publishers.run(() -> sync.toCollection());
    }

    @Override
    public com.mongodb.reactivestreams.client.AggregatePublisher<TResult> collation(com.mongodb.client.model.Collation arg0) {
        sync.collation(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.AggregatePublisher<TResult> comment(java.lang.String arg0) {
        sync.comment(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.AggregatePublisher<TResult> comment(org.bson.BsonValue arg0) {
        sync.comment(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.AggregatePublisher<TResult> hint(org.bson.conversions.Bson arg0) {
        sync.hint(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.AggregatePublisher<TResult> hintString(java.lang.String arg0) {
        sync.hintString(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.AggregatePublisher<TResult> let(org.bson.conversions.Bson arg0) {
        sync.let(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.AggregatePublisher<TResult> batchSize(int arg0) {
        sync.batchSize(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.AggregatePublisher<TResult> timeoutMode(com.mongodb.client.cursor.TimeoutMode arg0) {
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
