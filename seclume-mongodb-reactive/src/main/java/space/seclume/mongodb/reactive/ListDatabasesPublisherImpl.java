package space.seclume.mongodb.reactive;

/**
 * Generated from the reactive and the sync API: every method of
 * {@code com.mongodb.reactivestreams.client.ListDatabasesPublisher} on {@code com.mongodb.client.ListDatabasesIterable} (see Publishers for how a call becomes a
 * publisher). Regenerate rather than edit.
 */
@SuppressWarnings({"deprecation", "unchecked", "rawtypes"})
final class ListDatabasesPublisherImpl<TResult> extends IterablePublisher<TResult> implements com.mongodb.reactivestreams.client.ListDatabasesPublisher<TResult> {

    private final com.mongodb.client.ListDatabasesIterable<TResult> sync;

    ListDatabasesPublisherImpl(com.mongodb.client.ListDatabasesIterable<TResult> sync) {
        super(sync);
        this.sync = sync;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListDatabasesPublisher<TResult> maxTime(long arg0, java.util.concurrent.TimeUnit arg1) {
        sync.maxTime(arg0, arg1);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListDatabasesPublisher<TResult> filter(org.bson.conversions.Bson arg0) {
        sync.filter(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListDatabasesPublisher<TResult> nameOnly(java.lang.Boolean arg0) {
        sync.nameOnly(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListDatabasesPublisher<TResult> authorizedDatabasesOnly(java.lang.Boolean arg0) {
        sync.authorizedDatabasesOnly(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListDatabasesPublisher<TResult> batchSize(int arg0) {
        sync.batchSize(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListDatabasesPublisher<TResult> comment(java.lang.String arg0) {
        sync.comment(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListDatabasesPublisher<TResult> comment(org.bson.BsonValue arg0) {
        sync.comment(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListDatabasesPublisher<TResult> timeoutMode(com.mongodb.client.cursor.TimeoutMode arg0) {
        sync.timeoutMode(arg0);
        return this;
    }

    @Override
    public org.reactivestreams.Publisher<TResult> first() {
        return Publishers.single(() -> sync.first());
    }

}
