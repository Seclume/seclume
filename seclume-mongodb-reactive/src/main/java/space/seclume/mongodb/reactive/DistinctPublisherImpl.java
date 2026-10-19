package space.seclume.mongodb.reactive;

/**
 * Generated from the reactive and the sync API: every method of
 * {@code com.mongodb.reactivestreams.client.DistinctPublisher} on {@code com.mongodb.client.DistinctIterable} (see Publishers for how a call becomes a
 * publisher). Regenerate rather than edit.
 */
@SuppressWarnings({"deprecation", "unchecked", "rawtypes"})
final class DistinctPublisherImpl<TResult> extends IterablePublisher<TResult> implements com.mongodb.reactivestreams.client.DistinctPublisher<TResult> {

    private final com.mongodb.client.DistinctIterable<TResult> sync;

    DistinctPublisherImpl(com.mongodb.client.DistinctIterable<TResult> sync) {
        super(sync);
        this.sync = sync;
    }

    @Override
    public com.mongodb.reactivestreams.client.DistinctPublisher<TResult> filter(org.bson.conversions.Bson arg0) {
        sync.filter(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.DistinctPublisher<TResult> maxTime(long arg0, java.util.concurrent.TimeUnit arg1) {
        sync.maxTime(arg0, arg1);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.DistinctPublisher<TResult> collation(com.mongodb.client.model.Collation arg0) {
        sync.collation(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.DistinctPublisher<TResult> batchSize(int arg0) {
        sync.batchSize(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.DistinctPublisher<TResult> comment(java.lang.String arg0) {
        sync.comment(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.DistinctPublisher<TResult> comment(org.bson.BsonValue arg0) {
        sync.comment(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.DistinctPublisher<TResult> hint(org.bson.conversions.Bson arg0) {
        sync.hint(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.DistinctPublisher<TResult> hintString(java.lang.String arg0) {
        sync.hintString(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.DistinctPublisher<TResult> timeoutMode(com.mongodb.client.cursor.TimeoutMode arg0) {
        sync.timeoutMode(arg0);
        return this;
    }

    @Override
    public org.reactivestreams.Publisher<TResult> first() {
        return Publishers.single(() -> sync.first());
    }

}
