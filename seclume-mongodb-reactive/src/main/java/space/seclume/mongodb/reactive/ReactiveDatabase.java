package space.seclume.mongodb.reactive;

/**
 * Generated from the reactive and the sync API: every method of
 * {@code com.mongodb.reactivestreams.client.MongoDatabase} on {@code com.mongodb.client.MongoDatabase} (see Publishers for how a call becomes a
 * publisher). Regenerate rather than edit.
 */
@SuppressWarnings({"deprecation", "unchecked", "rawtypes"})
class ReactiveDatabase implements com.mongodb.reactivestreams.client.MongoDatabase {

    final com.mongodb.client.MongoDatabase sync;

    ReactiveDatabase(com.mongodb.client.MongoDatabase sync) {
        this.sync = sync;
    }

    @Override
    public java.lang.String getName() {
        return sync.getName();
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
    public com.mongodb.reactivestreams.client.MongoDatabase withCodecRegistry(org.bson.codecs.configuration.CodecRegistry arg0) {
        return new ReactiveDatabase(sync.withCodecRegistry(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.MongoDatabase withReadPreference(com.mongodb.ReadPreference arg0) {
        return new ReactiveDatabase(sync.withReadPreference(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.MongoDatabase withWriteConcern(com.mongodb.WriteConcern arg0) {
        return new ReactiveDatabase(sync.withWriteConcern(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.MongoDatabase withReadConcern(com.mongodb.ReadConcern arg0) {
        return new ReactiveDatabase(sync.withReadConcern(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.MongoDatabase withTimeout(long arg0, java.util.concurrent.TimeUnit arg1) {
        return new ReactiveDatabase(sync.withTimeout(arg0, arg1));
    }

    @Override
    public com.mongodb.reactivestreams.client.MongoCollection<org.bson.Document> getCollection(java.lang.String arg0) {
        return new ReactiveCollection<>(sync.getCollection(arg0));
    }

    @Override
    public <TDocument> com.mongodb.reactivestreams.client.MongoCollection<TDocument> getCollection(java.lang.String arg0, java.lang.Class<TDocument> arg1) {
        return new ReactiveCollection<>(sync.getCollection(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<org.bson.Document> runCommand(org.bson.conversions.Bson arg0) {
        return Publishers.single(() -> sync.runCommand(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<org.bson.Document> runCommand(org.bson.conversions.Bson arg0, com.mongodb.ReadPreference arg1) {
        return Publishers.single(() -> sync.runCommand(arg0, arg1));
    }

    @Override
    public <TResult> org.reactivestreams.Publisher<TResult> runCommand(org.bson.conversions.Bson arg0, java.lang.Class<TResult> arg1) {
        return Publishers.single(() -> sync.runCommand(arg0, arg1));
    }

    @Override
    public <TResult> org.reactivestreams.Publisher<TResult> runCommand(org.bson.conversions.Bson arg0, com.mongodb.ReadPreference arg1, java.lang.Class<TResult> arg2) {
        return Publishers.single(() -> sync.runCommand(arg0, arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<org.bson.Document> runCommand(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1) {
        return Publishers.single(() -> sync.runCommand(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<org.bson.Document> runCommand(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, com.mongodb.ReadPreference arg2) {
        return Publishers.single(() -> sync.runCommand(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public <TResult> org.reactivestreams.Publisher<TResult> runCommand(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, java.lang.Class<TResult> arg2) {
        return Publishers.single(() -> sync.runCommand(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public <TResult> org.reactivestreams.Publisher<TResult> runCommand(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, com.mongodb.ReadPreference arg2, java.lang.Class<TResult> arg3) {
        return Publishers.single(() -> sync.runCommand(Sessions.sync(arg0), arg1, arg2, arg3));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> drop() {
        return Publishers.run(() -> sync.drop());
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> drop(com.mongodb.reactivestreams.client.ClientSession arg0) {
        return Publishers.run(() -> sync.drop(Sessions.sync(arg0)));
    }

    @Override
    public com.mongodb.reactivestreams.client.ListCollectionNamesPublisher listCollectionNames() {
        return new ListCollectionNamesPublisherImpl(sync.listCollectionNames());
    }

    @Override
    public com.mongodb.reactivestreams.client.ListCollectionNamesPublisher listCollectionNames(com.mongodb.reactivestreams.client.ClientSession arg0) {
        return new ListCollectionNamesPublisherImpl(sync.listCollectionNames(Sessions.sync(arg0)));
    }

    @Override
    public com.mongodb.reactivestreams.client.ListCollectionsPublisher<org.bson.Document> listCollections() {
        return new ListCollectionsPublisherImpl<>(sync.listCollections());
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.ListCollectionsPublisher<TResult> listCollections(java.lang.Class<TResult> arg0) {
        return new ListCollectionsPublisherImpl<>(sync.listCollections(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.ListCollectionsPublisher<org.bson.Document> listCollections(com.mongodb.reactivestreams.client.ClientSession arg0) {
        return new ListCollectionsPublisherImpl<>(sync.listCollections(Sessions.sync(arg0)));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.ListCollectionsPublisher<TResult> listCollections(com.mongodb.reactivestreams.client.ClientSession arg0, java.lang.Class<TResult> arg1) {
        return new ListCollectionsPublisherImpl<>(sync.listCollections(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> createCollection(java.lang.String arg0) {
        return Publishers.run(() -> sync.createCollection(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> createCollection(java.lang.String arg0, com.mongodb.client.model.CreateCollectionOptions arg1) {
        return Publishers.run(() -> sync.createCollection(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> createCollection(com.mongodb.reactivestreams.client.ClientSession arg0, java.lang.String arg1) {
        return Publishers.run(() -> sync.createCollection(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> createCollection(com.mongodb.reactivestreams.client.ClientSession arg0, java.lang.String arg1, com.mongodb.client.model.CreateCollectionOptions arg2) {
        return Publishers.run(() -> sync.createCollection(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> createView(java.lang.String arg0, java.lang.String arg1, java.util.List<? extends org.bson.conversions.Bson> arg2) {
        return Publishers.run(() -> sync.createView(arg0, arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> createView(java.lang.String arg0, java.lang.String arg1, java.util.List<? extends org.bson.conversions.Bson> arg2, com.mongodb.client.model.CreateViewOptions arg3) {
        return Publishers.run(() -> sync.createView(arg0, arg1, arg2, arg3));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> createView(com.mongodb.reactivestreams.client.ClientSession arg0, java.lang.String arg1, java.lang.String arg2, java.util.List<? extends org.bson.conversions.Bson> arg3) {
        return Publishers.run(() -> sync.createView(Sessions.sync(arg0), arg1, arg2, arg3));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> createView(com.mongodb.reactivestreams.client.ClientSession arg0, java.lang.String arg1, java.lang.String arg2, java.util.List<? extends org.bson.conversions.Bson> arg3, com.mongodb.client.model.CreateViewOptions arg4) {
        return Publishers.run(() -> sync.createView(Sessions.sync(arg0), arg1, arg2, arg3, arg4));
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
    public com.mongodb.reactivestreams.client.AggregatePublisher<org.bson.Document> aggregate(java.util.List<? extends org.bson.conversions.Bson> arg0) {
        return new AggregatePublisherImpl<>(sync.aggregate(arg0));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.AggregatePublisher<TResult> aggregate(java.util.List<? extends org.bson.conversions.Bson> arg0, java.lang.Class<TResult> arg1) {
        return new AggregatePublisherImpl<>(sync.aggregate(arg0, arg1));
    }

    @Override
    public com.mongodb.reactivestreams.client.AggregatePublisher<org.bson.Document> aggregate(com.mongodb.reactivestreams.client.ClientSession arg0, java.util.List<? extends org.bson.conversions.Bson> arg1) {
        return new AggregatePublisherImpl<>(sync.aggregate(Sessions.sync(arg0), arg1));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.AggregatePublisher<TResult> aggregate(com.mongodb.reactivestreams.client.ClientSession arg0, java.util.List<? extends org.bson.conversions.Bson> arg1, java.lang.Class<TResult> arg2) {
        return new AggregatePublisherImpl<>(sync.aggregate(Sessions.sync(arg0), arg1, arg2));
    }

}
