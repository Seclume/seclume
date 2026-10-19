package space.seclume.mongodb.reactive;

/**
 * Generated from the reactive and the sync API: every method of
 * {@code com.mongodb.reactivestreams.client.ListCollectionNamesPublisher} on {@code com.mongodb.client.ListCollectionNamesIterable} (see Publishers for how a call becomes a
 * publisher). Regenerate rather than edit.
 */
@SuppressWarnings({"deprecation", "unchecked", "rawtypes"})
final class ListCollectionNamesPublisherImpl extends IterablePublisher<java.lang.String> implements com.mongodb.reactivestreams.client.ListCollectionNamesPublisher {

    private final com.mongodb.client.ListCollectionNamesIterable sync;

    ListCollectionNamesPublisherImpl(com.mongodb.client.ListCollectionNamesIterable sync) {
        super(sync);
        this.sync = sync;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListCollectionNamesPublisher filter(org.bson.conversions.Bson arg0) {
        sync.filter(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListCollectionNamesPublisher maxTime(long arg0, java.util.concurrent.TimeUnit arg1) {
        sync.maxTime(arg0, arg1);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListCollectionNamesPublisher batchSize(int arg0) {
        sync.batchSize(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListCollectionNamesPublisher comment(java.lang.String arg0) {
        sync.comment(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.ListCollectionNamesPublisher comment(org.bson.BsonValue arg0) {
        sync.comment(arg0);
        return this;
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.String> first() {
        return Publishers.single(() -> sync.first());
    }

    @Override
    public com.mongodb.reactivestreams.client.ListCollectionNamesPublisher authorizedCollections(boolean arg0) {
        sync.authorizedCollections(arg0);
        return this;
    }

}
