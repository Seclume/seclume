package space.seclume.mongodb.reactive;

/**
 * Generated from the reactive and the sync API: every method of
 * {@code com.mongodb.reactivestreams.client.MapReducePublisher} on {@code com.mongodb.client.MapReduceIterable} (see Publishers for how a call becomes a
 * publisher). Regenerate rather than edit.
 */
@SuppressWarnings({"deprecation", "unchecked", "rawtypes"})
final class MapReducePublisherImpl<TResult> extends IterablePublisher<TResult> implements com.mongodb.reactivestreams.client.MapReducePublisher<TResult> {

    private final com.mongodb.client.MapReduceIterable<TResult> sync;

    MapReducePublisherImpl(com.mongodb.client.MapReduceIterable<TResult> sync) {
        super(sync);
        this.sync = sync;
    }

    @Override
    public com.mongodb.reactivestreams.client.MapReducePublisher<TResult> collectionName(java.lang.String arg0) {
        sync.collectionName(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.MapReducePublisher<TResult> finalizeFunction(java.lang.String arg0) {
        sync.finalizeFunction(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.MapReducePublisher<TResult> scope(org.bson.conversions.Bson arg0) {
        sync.scope(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.MapReducePublisher<TResult> sort(org.bson.conversions.Bson arg0) {
        sync.sort(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.MapReducePublisher<TResult> filter(org.bson.conversions.Bson arg0) {
        sync.filter(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.MapReducePublisher<TResult> limit(int arg0) {
        sync.limit(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.MapReducePublisher<TResult> jsMode(boolean arg0) {
        sync.jsMode(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.MapReducePublisher<TResult> verbose(boolean arg0) {
        sync.verbose(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.MapReducePublisher<TResult> maxTime(long arg0, java.util.concurrent.TimeUnit arg1) {
        sync.maxTime(arg0, arg1);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.MapReducePublisher<TResult> action(com.mongodb.client.model.MapReduceAction arg0) {
        sync.action(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.MapReducePublisher<TResult> databaseName(java.lang.String arg0) {
        sync.databaseName(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.MapReducePublisher<TResult> bypassDocumentValidation(java.lang.Boolean arg0) {
        sync.bypassDocumentValidation(arg0);
        return this;
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> toCollection() {
        return Publishers.run(() -> sync.toCollection());
    }

    @Override
    public com.mongodb.reactivestreams.client.MapReducePublisher<TResult> collation(com.mongodb.client.model.Collation arg0) {
        sync.collation(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.MapReducePublisher<TResult> batchSize(int arg0) {
        sync.batchSize(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.MapReducePublisher<TResult> timeoutMode(com.mongodb.client.cursor.TimeoutMode arg0) {
        sync.timeoutMode(arg0);
        return this;
    }

    @Override
    public org.reactivestreams.Publisher<TResult> first() {
        return Publishers.single(() -> sync.first());
    }

}
