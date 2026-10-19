package space.seclume.mongodb.reactive;

/**
 * Generated from the reactive and the sync API: every method of
 * {@code com.mongodb.reactivestreams.client.MongoCluster} on {@code com.mongodb.client.MongoCluster} (see Publishers for how a call becomes a
 * publisher). Regenerate rather than edit.
 */
@SuppressWarnings({"deprecation", "unchecked", "rawtypes"})
class ReactiveCluster implements com.mongodb.reactivestreams.client.MongoCluster {

    final com.mongodb.client.MongoCluster sync;

    ReactiveCluster(com.mongodb.client.MongoCluster sync) {
        this.sync = sync;
    }

    @Override
    public org.bson.codecs.configuration.CodecRegistry getCodecRegistry() {
        return sync.getCodecRegistry();
    }

    @Override
    public com.mongodb.ReadPreference getReadPreference() {
        return sync.getReadPreference();
    }

    @Override
    public com.mongodb.WriteConcern getWriteConcern() {
        return sync.getWriteConcern();
    }

    @Override
    public com.mongodb.ReadConcern getReadConcern() {
        return sync.getReadConcern();
    }

    @Override
    public java.lang.Long getTimeout(java.util.concurrent.TimeUnit arg0) {
        return sync.getTimeout(arg0);
    }

    @Override
    public com.mongodb.reactivestreams.client.MongoCluster withCodecRegistry(org.bson.codecs.configuration.CodecRegistry arg0) {
        return new ReactiveCluster(sync.withCodecRegistry(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.MongoCluster withReadPreference(com.mongodb.ReadPreference arg0) {
        return new ReactiveCluster(sync.withReadPreference(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.MongoCluster withWriteConcern(com.mongodb.WriteConcern arg0) {
        return new ReactiveCluster(sync.withWriteConcern(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.MongoCluster withReadConcern(com.mongodb.ReadConcern arg0) {
        return new ReactiveCluster(sync.withReadConcern(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.MongoCluster withTimeout(long arg0, java.util.concurrent.TimeUnit arg1) {
        return new ReactiveCluster(sync.withTimeout(arg0, arg1));
    }

    @Override
    public com.mongodb.reactivestreams.client.MongoDatabase getDatabase(java.lang.String arg0) {
        return new ReactiveDatabase(sync.getDatabase(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.reactivestreams.client.ClientSession> startSession() {
        return Publishers.single(() -> new ReactiveClientSession(sync.startSession()));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.reactivestreams.client.ClientSession> startSession(com.mongodb.ClientSessionOptions arg0) {
        return Publishers.single(() -> new ReactiveClientSession(sync.startSession(arg0)));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.String> listDatabaseNames() {
        return Publishers.many(() -> sync.listDatabaseNames().cursor());
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.String> listDatabaseNames(com.mongodb.reactivestreams.client.ClientSession arg0) {
        return Publishers.many(() -> sync.listDatabaseNames(Sessions.sync(arg0)).cursor());
    }

    @Override
    public com.mongodb.reactivestreams.client.ListDatabasesPublisher<org.bson.Document> listDatabases() {
        return new ListDatabasesPublisherImpl<>(sync.listDatabases());
    }

    @Override
    public com.mongodb.reactivestreams.client.ListDatabasesPublisher<org.bson.Document> listDatabases(com.mongodb.reactivestreams.client.ClientSession arg0) {
        return new ListDatabasesPublisherImpl<>(sync.listDatabases(Sessions.sync(arg0)));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.ListDatabasesPublisher<TResult> listDatabases(java.lang.Class<TResult> arg0) {
        return new ListDatabasesPublisherImpl<>(sync.listDatabases(arg0));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.ListDatabasesPublisher<TResult> listDatabases(com.mongodb.reactivestreams.client.ClientSession arg0, java.lang.Class<TResult> arg1) {
        return new ListDatabasesPublisherImpl<>(sync.listDatabases(Sessions.sync(arg0), arg1));
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<org.bson.Document> watch() {
        return new ChangeStreamPublisherImpl<>(sync.watch());
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> watch(java.lang.Class<TResult> arg0) {
        return new ChangeStreamPublisherImpl<>(sync.watch(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<org.bson.Document> watch(java.util.List<? extends org.bson.conversions.Bson> arg0) {
        return new ChangeStreamPublisherImpl<>(sync.watch(arg0));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> watch(java.util.List<? extends org.bson.conversions.Bson> arg0, java.lang.Class<TResult> arg1) {
        return new ChangeStreamPublisherImpl<>(sync.watch(arg0, arg1));
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<org.bson.Document> watch(com.mongodb.reactivestreams.client.ClientSession arg0) {
        return new ChangeStreamPublisherImpl<>(sync.watch(Sessions.sync(arg0)));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> watch(com.mongodb.reactivestreams.client.ClientSession arg0, java.lang.Class<TResult> arg1) {
        return new ChangeStreamPublisherImpl<>(sync.watch(Sessions.sync(arg0), arg1));
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<org.bson.Document> watch(com.mongodb.reactivestreams.client.ClientSession arg0, java.util.List<? extends org.bson.conversions.Bson> arg1) {
        return new ChangeStreamPublisherImpl<>(sync.watch(Sessions.sync(arg0), arg1));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> watch(com.mongodb.reactivestreams.client.ClientSession arg0, java.util.List<? extends org.bson.conversions.Bson> arg1, java.lang.Class<TResult> arg2) {
        return new ChangeStreamPublisherImpl<>(sync.watch(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.model.bulk.ClientBulkWriteResult> bulkWrite(java.util.List<? extends com.mongodb.client.model.bulk.ClientNamespacedWriteModel> arg0) {
        return Publishers.single(() -> sync.bulkWrite(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.model.bulk.ClientBulkWriteResult> bulkWrite(java.util.List<? extends com.mongodb.client.model.bulk.ClientNamespacedWriteModel> arg0, com.mongodb.client.model.bulk.ClientBulkWriteOptions arg1) {
        return Publishers.single(() -> sync.bulkWrite(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.model.bulk.ClientBulkWriteResult> bulkWrite(com.mongodb.reactivestreams.client.ClientSession arg0, java.util.List<? extends com.mongodb.client.model.bulk.ClientNamespacedWriteModel> arg1) {
        return Publishers.single(() -> sync.bulkWrite(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.model.bulk.ClientBulkWriteResult> bulkWrite(com.mongodb.reactivestreams.client.ClientSession arg0, java.util.List<? extends com.mongodb.client.model.bulk.ClientNamespacedWriteModel> arg1, com.mongodb.client.model.bulk.ClientBulkWriteOptions arg2) {
        return Publishers.single(() -> sync.bulkWrite(Sessions.sync(arg0), arg1, arg2));
    }

}
