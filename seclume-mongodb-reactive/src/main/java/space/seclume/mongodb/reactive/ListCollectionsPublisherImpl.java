package space.seclume.mongodb.reactive;

/**
 * Generated from the reactive and the sync API: every method of
 * {@code com.mongodb.reactivestreams.client.ListCollectionsPublisher} on {@code com.mongodb.client.ListCollectionsIterable} (see Publishers for how a call becomes a
 * publisher). Regenerate rather than edit.
 */
@SuppressWarnings({"deprecation", "unchecked", "rawtypes"})
final class ListCollectionsPublisherImpl<TResult> extends IterablePublisher<TResult> implements com.mongodb.reactivestreams.client.ListCollectionsPublisher<TResult> {

    private final com.mongodb.client.ListCollectionsIterable<TResult> sync;

    ListCollectionsPublisherImpl(com.mongodb.client.ListCollectionsIterable<TResult> sync) {
        super(sync);
        this.sync = sync;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListCollectionsPublisher<TResult> filter(org.bson.conversions.Bson arg0) {
        sync.filter(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListCollectionsPublisher<TResult> maxTime(long arg0, java.util.concurrent.TimeUnit arg1) {
        sync.maxTime(arg0, arg1);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListCollectionsPublisher<TResult> batchSize(int arg0) {
        sync.batchSize(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListCollectionsPublisher<TResult> comment(java.lang.String arg0) {
        sync.comment(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListCollectionsPublisher<TResult> comment(org.bson.BsonValue arg0) {
        sync.comment(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListCollectionsPublisher<TResult> timeoutMode(com.mongodb.client.cursor.TimeoutMode arg0) {
        sync.timeoutMode(arg0);
        return this;
    }

    @Override
    public org.reactivestreams.Publisher<TResult> first() {
        return Publishers.single(() -> sync.first());
    }

}
