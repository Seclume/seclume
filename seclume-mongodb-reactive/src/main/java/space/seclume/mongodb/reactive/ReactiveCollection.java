package space.seclume.mongodb.reactive;

/**
 * Generated from the reactive and the sync API: every method of
 * {@code com.mongodb.reactivestreams.client.MongoCollection} on {@code com.mongodb.client.MongoCollection} (see Publishers for how a call becomes a
 * publisher). Regenerate rather than edit.
 */
@SuppressWarnings({"deprecation", "unchecked", "rawtypes"})
class ReactiveCollection<TDocument> implements com.mongodb.reactivestreams.client.MongoCollection<TDocument> {

    final com.mongodb.client.MongoCollection<TDocument> sync;

    ReactiveCollection(com.mongodb.client.MongoCollection<TDocument> sync) {
        this.sync = sync;
    }

    @Override
    public com.mongodb.MongoNamespace getNamespace() {
        return sync.getNamespace();
    }

    @Override
    public java.lang.Class<TDocument> getDocumentClass() {
        return sync.getDocumentClass();
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
    public <NewTDocument> com.mongodb.reactivestreams.client.MongoCollection<NewTDocument> withDocumentClass(java.lang.Class<NewTDocument> arg0) {
        return new ReactiveCollection<>(sync.withDocumentClass(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.MongoCollection<TDocument> withCodecRegistry(org.bson.codecs.configuration.CodecRegistry arg0) {
        return new ReactiveCollection<>(sync.withCodecRegistry(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.MongoCollection<TDocument> withReadPreference(com.mongodb.ReadPreference arg0) {
        return new ReactiveCollection<>(sync.withReadPreference(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.MongoCollection<TDocument> withWriteConcern(com.mongodb.WriteConcern arg0) {
        return new ReactiveCollection<>(sync.withWriteConcern(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.MongoCollection<TDocument> withReadConcern(com.mongodb.ReadConcern arg0) {
        return new ReactiveCollection<>(sync.withReadConcern(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.MongoCollection<TDocument> withTimeout(long arg0, java.util.concurrent.TimeUnit arg1) {
        return new ReactiveCollection<>(sync.withTimeout(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Long> estimatedDocumentCount() {
        return Publishers.single(() -> sync.estimatedDocumentCount());
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Long> estimatedDocumentCount(com.mongodb.client.model.EstimatedDocumentCountOptions arg0) {
        return Publishers.single(() -> sync.estimatedDocumentCount(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Long> countDocuments() {
        return Publishers.single(() -> sync.countDocuments());
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Long> countDocuments(org.bson.conversions.Bson arg0) {
        return Publishers.single(() -> sync.countDocuments(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Long> countDocuments(org.bson.conversions.Bson arg0, com.mongodb.client.model.CountOptions arg1) {
        return Publishers.single(() -> sync.countDocuments(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Long> countDocuments(com.mongodb.reactivestreams.client.ClientSession arg0) {
        return Publishers.single(() -> sync.countDocuments(Sessions.sync(arg0)));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Long> countDocuments(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1) {
        return Publishers.single(() -> sync.countDocuments(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Long> countDocuments(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, com.mongodb.client.model.CountOptions arg2) {
        return Publishers.single(() -> sync.countDocuments(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.DistinctPublisher<TResult> distinct(java.lang.String arg0, java.lang.Class<TResult> arg1) {
        return new DistinctPublisherImpl<>(sync.distinct(arg0, arg1));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.DistinctPublisher<TResult> distinct(java.lang.String arg0, org.bson.conversions.Bson arg1, java.lang.Class<TResult> arg2) {
        return new DistinctPublisherImpl<>(sync.distinct(arg0, arg1, arg2));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.DistinctPublisher<TResult> distinct(com.mongodb.reactivestreams.client.ClientSession arg0, java.lang.String arg1, java.lang.Class<TResult> arg2) {
        return new DistinctPublisherImpl<>(sync.distinct(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.DistinctPublisher<TResult> distinct(com.mongodb.reactivestreams.client.ClientSession arg0, java.lang.String arg1, org.bson.conversions.Bson arg2, java.lang.Class<TResult> arg3) {
        return new DistinctPublisherImpl<>(sync.distinct(Sessions.sync(arg0), arg1, arg2, arg3));
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TDocument> find() {
        return new FindPublisherImpl<>(sync.find());
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.FindPublisher<TResult> find(java.lang.Class<TResult> arg0) {
        return new FindPublisherImpl<>(sync.find(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TDocument> find(org.bson.conversions.Bson arg0) {
        return new FindPublisherImpl<>(sync.find(arg0));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.FindPublisher<TResult> find(org.bson.conversions.Bson arg0, java.lang.Class<TResult> arg1) {
        return new FindPublisherImpl<>(sync.find(arg0, arg1));
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TDocument> find(com.mongodb.reactivestreams.client.ClientSession arg0) {
        return new FindPublisherImpl<>(sync.find(Sessions.sync(arg0)));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.FindPublisher<TResult> find(com.mongodb.reactivestreams.client.ClientSession arg0, java.lang.Class<TResult> arg1) {
        return new FindPublisherImpl<>(sync.find(Sessions.sync(arg0), arg1));
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TDocument> find(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1) {
        return new FindPublisherImpl<>(sync.find(Sessions.sync(arg0), arg1));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.FindPublisher<TResult> find(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, java.lang.Class<TResult> arg2) {
        return new FindPublisherImpl<>(sync.find(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public com.mongodb.reactivestreams.client.AggregatePublisher<TDocument> aggregate(java.util.List<? extends org.bson.conversions.Bson> arg0) {
        return new AggregatePublisherImpl<>(sync.aggregate(arg0));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.AggregatePublisher<TResult> aggregate(java.util.List<? extends org.bson.conversions.Bson> arg0, java.lang.Class<TResult> arg1) {
        return new AggregatePublisherImpl<>(sync.aggregate(arg0, arg1));
    }

    @Override
    public com.mongodb.reactivestreams.client.AggregatePublisher<TDocument> aggregate(com.mongodb.reactivestreams.client.ClientSession arg0, java.util.List<? extends org.bson.conversions.Bson> arg1) {
        return new AggregatePublisherImpl<>(sync.aggregate(Sessions.sync(arg0), arg1));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.AggregatePublisher<TResult> aggregate(com.mongodb.reactivestreams.client.ClientSession arg0, java.util.List<? extends org.bson.conversions.Bson> arg1, java.lang.Class<TResult> arg2) {
        return new AggregatePublisherImpl<>(sync.aggregate(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<org.bson.Document> watch() {
        return new ChangeStreamPublisherImpl<>(sync.watch(org.bson.Document.class));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> watch(java.lang.Class<TResult> arg0) {
        return new ChangeStreamPublisherImpl<>(sync.watch(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<org.bson.Document> watch(java.util.List<? extends org.bson.conversions.Bson> arg0) {
        return new ChangeStreamPublisherImpl<>(sync.watch(arg0, org.bson.Document.class));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> watch(java.util.List<? extends org.bson.conversions.Bson> arg0, java.lang.Class<TResult> arg1) {
        return new ChangeStreamPublisherImpl<>(sync.watch(arg0, arg1));
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<org.bson.Document> watch(com.mongodb.reactivestreams.client.ClientSession arg0) {
        return new ChangeStreamPublisherImpl<>(sync.watch(Sessions.sync(arg0), org.bson.Document.class));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> watch(com.mongodb.reactivestreams.client.ClientSession arg0, java.lang.Class<TResult> arg1) {
        return new ChangeStreamPublisherImpl<>(sync.watch(Sessions.sync(arg0), arg1));
    }

    @Override
    public com.mongodb.reactivestreams.client.ChangeStreamPublisher<org.bson.Document> watch(com.mongodb.reactivestreams.client.ClientSession arg0, java.util.List<? extends org.bson.conversions.Bson> arg1) {
        return new ChangeStreamPublisherImpl<>(sync.watch(Sessions.sync(arg0), arg1, org.bson.Document.class));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.ChangeStreamPublisher<TResult> watch(com.mongodb.reactivestreams.client.ClientSession arg0, java.util.List<? extends org.bson.conversions.Bson> arg1, java.lang.Class<TResult> arg2) {
        return new ChangeStreamPublisherImpl<>(sync.watch(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public com.mongodb.reactivestreams.client.MapReducePublisher<TDocument> mapReduce(java.lang.String arg0, java.lang.String arg1) {
        return new MapReducePublisherImpl<>(sync.mapReduce(arg0, arg1));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.MapReducePublisher<TResult> mapReduce(java.lang.String arg0, java.lang.String arg1, java.lang.Class<TResult> arg2) {
        return new MapReducePublisherImpl<>(sync.mapReduce(arg0, arg1, arg2));
    }

    @Override
    public com.mongodb.reactivestreams.client.MapReducePublisher<TDocument> mapReduce(com.mongodb.reactivestreams.client.ClientSession arg0, java.lang.String arg1, java.lang.String arg2) {
        return new MapReducePublisherImpl<>(sync.mapReduce(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.MapReducePublisher<TResult> mapReduce(com.mongodb.reactivestreams.client.ClientSession arg0, java.lang.String arg1, java.lang.String arg2, java.lang.Class<TResult> arg3) {
        return new MapReducePublisherImpl<>(sync.mapReduce(Sessions.sync(arg0), arg1, arg2, arg3));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.bulk.BulkWriteResult> bulkWrite(java.util.List<? extends com.mongodb.client.model.WriteModel<? extends TDocument>> arg0) {
        return Publishers.single(() -> sync.bulkWrite(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.bulk.BulkWriteResult> bulkWrite(java.util.List<? extends com.mongodb.client.model.WriteModel<? extends TDocument>> arg0, com.mongodb.client.model.BulkWriteOptions arg1) {
        return Publishers.single(() -> sync.bulkWrite(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.bulk.BulkWriteResult> bulkWrite(com.mongodb.reactivestreams.client.ClientSession arg0, java.util.List<? extends com.mongodb.client.model.WriteModel<? extends TDocument>> arg1) {
        return Publishers.single(() -> sync.bulkWrite(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.bulk.BulkWriteResult> bulkWrite(com.mongodb.reactivestreams.client.ClientSession arg0, java.util.List<? extends com.mongodb.client.model.WriteModel<? extends TDocument>> arg1, com.mongodb.client.model.BulkWriteOptions arg2) {
        return Publishers.single(() -> sync.bulkWrite(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.InsertOneResult> insertOne(TDocument arg0) {
        return Publishers.single(() -> sync.insertOne(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.InsertOneResult> insertOne(TDocument arg0, com.mongodb.client.model.InsertOneOptions arg1) {
        return Publishers.single(() -> sync.insertOne(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.InsertOneResult> insertOne(com.mongodb.reactivestreams.client.ClientSession arg0, TDocument arg1) {
        return Publishers.single(() -> sync.insertOne(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.InsertOneResult> insertOne(com.mongodb.reactivestreams.client.ClientSession arg0, TDocument arg1, com.mongodb.client.model.InsertOneOptions arg2) {
        return Publishers.single(() -> sync.insertOne(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.InsertManyResult> insertMany(java.util.List<? extends TDocument> arg0) {
        return Publishers.single(() -> sync.insertMany(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.InsertManyResult> insertMany(java.util.List<? extends TDocument> arg0, com.mongodb.client.model.InsertManyOptions arg1) {
        return Publishers.single(() -> sync.insertMany(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.InsertManyResult> insertMany(com.mongodb.reactivestreams.client.ClientSession arg0, java.util.List<? extends TDocument> arg1) {
        return Publishers.single(() -> sync.insertMany(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.InsertManyResult> insertMany(com.mongodb.reactivestreams.client.ClientSession arg0, java.util.List<? extends TDocument> arg1, com.mongodb.client.model.InsertManyOptions arg2) {
        return Publishers.single(() -> sync.insertMany(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.DeleteResult> deleteOne(org.bson.conversions.Bson arg0) {
        return Publishers.single(() -> sync.deleteOne(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.DeleteResult> deleteOne(org.bson.conversions.Bson arg0, com.mongodb.client.model.DeleteOptions arg1) {
        return Publishers.single(() -> sync.deleteOne(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.DeleteResult> deleteOne(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1) {
        return Publishers.single(() -> sync.deleteOne(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.DeleteResult> deleteOne(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, com.mongodb.client.model.DeleteOptions arg2) {
        return Publishers.single(() -> sync.deleteOne(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.DeleteResult> deleteMany(org.bson.conversions.Bson arg0) {
        return Publishers.single(() -> sync.deleteMany(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.DeleteResult> deleteMany(org.bson.conversions.Bson arg0, com.mongodb.client.model.DeleteOptions arg1) {
        return Publishers.single(() -> sync.deleteMany(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.DeleteResult> deleteMany(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1) {
        return Publishers.single(() -> sync.deleteMany(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.DeleteResult> deleteMany(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, com.mongodb.client.model.DeleteOptions arg2) {
        return Publishers.single(() -> sync.deleteMany(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> replaceOne(org.bson.conversions.Bson arg0, TDocument arg1) {
        return Publishers.single(() -> sync.replaceOne(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> replaceOne(org.bson.conversions.Bson arg0, TDocument arg1, com.mongodb.client.model.ReplaceOptions arg2) {
        return Publishers.single(() -> sync.replaceOne(arg0, arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> replaceOne(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, TDocument arg2) {
        return Publishers.single(() -> sync.replaceOne(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> replaceOne(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, TDocument arg2, com.mongodb.client.model.ReplaceOptions arg3) {
        return Publishers.single(() -> sync.replaceOne(Sessions.sync(arg0), arg1, arg2, arg3));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> updateOne(org.bson.conversions.Bson arg0, org.bson.conversions.Bson arg1) {
        return Publishers.single(() -> sync.updateOne(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> updateOne(org.bson.conversions.Bson arg0, org.bson.conversions.Bson arg1, com.mongodb.client.model.UpdateOptions arg2) {
        return Publishers.single(() -> sync.updateOne(arg0, arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> updateOne(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, org.bson.conversions.Bson arg2) {
        return Publishers.single(() -> sync.updateOne(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> updateOne(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, org.bson.conversions.Bson arg2, com.mongodb.client.model.UpdateOptions arg3) {
        return Publishers.single(() -> sync.updateOne(Sessions.sync(arg0), arg1, arg2, arg3));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> updateOne(org.bson.conversions.Bson arg0, java.util.List<? extends org.bson.conversions.Bson> arg1) {
        return Publishers.single(() -> sync.updateOne(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> updateOne(org.bson.conversions.Bson arg0, java.util.List<? extends org.bson.conversions.Bson> arg1, com.mongodb.client.model.UpdateOptions arg2) {
        return Publishers.single(() -> sync.updateOne(arg0, arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> updateOne(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, java.util.List<? extends org.bson.conversions.Bson> arg2) {
        return Publishers.single(() -> sync.updateOne(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> updateOne(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, java.util.List<? extends org.bson.conversions.Bson> arg2, com.mongodb.client.model.UpdateOptions arg3) {
        return Publishers.single(() -> sync.updateOne(Sessions.sync(arg0), arg1, arg2, arg3));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> updateMany(org.bson.conversions.Bson arg0, org.bson.conversions.Bson arg1) {
        return Publishers.single(() -> sync.updateMany(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> updateMany(org.bson.conversions.Bson arg0, org.bson.conversions.Bson arg1, com.mongodb.client.model.UpdateOptions arg2) {
        return Publishers.single(() -> sync.updateMany(arg0, arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> updateMany(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, org.bson.conversions.Bson arg2) {
        return Publishers.single(() -> sync.updateMany(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> updateMany(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, org.bson.conversions.Bson arg2, com.mongodb.client.model.UpdateOptions arg3) {
        return Publishers.single(() -> sync.updateMany(Sessions.sync(arg0), arg1, arg2, arg3));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> updateMany(org.bson.conversions.Bson arg0, java.util.List<? extends org.bson.conversions.Bson> arg1) {
        return Publishers.single(() -> sync.updateMany(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> updateMany(org.bson.conversions.Bson arg0, java.util.List<? extends org.bson.conversions.Bson> arg1, com.mongodb.client.model.UpdateOptions arg2) {
        return Publishers.single(() -> sync.updateMany(arg0, arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> updateMany(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, java.util.List<? extends org.bson.conversions.Bson> arg2) {
        return Publishers.single(() -> sync.updateMany(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<com.mongodb.client.result.UpdateResult> updateMany(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, java.util.List<? extends org.bson.conversions.Bson> arg2, com.mongodb.client.model.UpdateOptions arg3) {
        return Publishers.single(() -> sync.updateMany(Sessions.sync(arg0), arg1, arg2, arg3));
    }

    @Override
    public org.reactivestreams.Publisher<TDocument> findOneAndDelete(org.bson.conversions.Bson arg0) {
        return Publishers.single(() -> sync.findOneAndDelete(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<TDocument> findOneAndDelete(org.bson.conversions.Bson arg0, com.mongodb.client.model.FindOneAndDeleteOptions arg1) {
        return Publishers.single(() -> sync.findOneAndDelete(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<TDocument> findOneAndDelete(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1) {
        return Publishers.single(() -> sync.findOneAndDelete(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<TDocument> findOneAndDelete(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, com.mongodb.client.model.FindOneAndDeleteOptions arg2) {
        return Publishers.single(() -> sync.findOneAndDelete(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<TDocument> findOneAndReplace(org.bson.conversions.Bson arg0, TDocument arg1) {
        return Publishers.single(() -> sync.findOneAndReplace(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<TDocument> findOneAndReplace(org.bson.conversions.Bson arg0, TDocument arg1, com.mongodb.client.model.FindOneAndReplaceOptions arg2) {
        return Publishers.single(() -> sync.findOneAndReplace(arg0, arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<TDocument> findOneAndReplace(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, TDocument arg2) {
        return Publishers.single(() -> sync.findOneAndReplace(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<TDocument> findOneAndReplace(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, TDocument arg2, com.mongodb.client.model.FindOneAndReplaceOptions arg3) {
        return Publishers.single(() -> sync.findOneAndReplace(Sessions.sync(arg0), arg1, arg2, arg3));
    }

    @Override
    public org.reactivestreams.Publisher<TDocument> findOneAndUpdate(org.bson.conversions.Bson arg0, org.bson.conversions.Bson arg1) {
        return Publishers.single(() -> sync.findOneAndUpdate(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<TDocument> findOneAndUpdate(org.bson.conversions.Bson arg0, org.bson.conversions.Bson arg1, com.mongodb.client.model.FindOneAndUpdateOptions arg2) {
        return Publishers.single(() -> sync.findOneAndUpdate(arg0, arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<TDocument> findOneAndUpdate(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, org.bson.conversions.Bson arg2) {
        return Publishers.single(() -> sync.findOneAndUpdate(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<TDocument> findOneAndUpdate(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, org.bson.conversions.Bson arg2, com.mongodb.client.model.FindOneAndUpdateOptions arg3) {
        return Publishers.single(() -> sync.findOneAndUpdate(Sessions.sync(arg0), arg1, arg2, arg3));
    }

    @Override
    public org.reactivestreams.Publisher<TDocument> findOneAndUpdate(org.bson.conversions.Bson arg0, java.util.List<? extends org.bson.conversions.Bson> arg1) {
        return Publishers.single(() -> sync.findOneAndUpdate(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<TDocument> findOneAndUpdate(org.bson.conversions.Bson arg0, java.util.List<? extends org.bson.conversions.Bson> arg1, com.mongodb.client.model.FindOneAndUpdateOptions arg2) {
        return Publishers.single(() -> sync.findOneAndUpdate(arg0, arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<TDocument> findOneAndUpdate(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, java.util.List<? extends org.bson.conversions.Bson> arg2) {
        return Publishers.single(() -> sync.findOneAndUpdate(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<TDocument> findOneAndUpdate(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, java.util.List<? extends org.bson.conversions.Bson> arg2, com.mongodb.client.model.FindOneAndUpdateOptions arg3) {
        return Publishers.single(() -> sync.findOneAndUpdate(Sessions.sync(arg0), arg1, arg2, arg3));
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
    public org.reactivestreams.Publisher<java.lang.Void> drop(com.mongodb.client.model.DropCollectionOptions arg0) {
        return Publishers.run(() -> sync.drop(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> drop(com.mongodb.reactivestreams.client.ClientSession arg0, com.mongodb.client.model.DropCollectionOptions arg1) {
        return Publishers.run(() -> sync.drop(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.String> createSearchIndex(java.lang.String arg0, org.bson.conversions.Bson arg1) {
        return Publishers.single(() -> sync.createSearchIndex(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.String> createSearchIndex(org.bson.conversions.Bson arg0) {
        return Publishers.single(() -> sync.createSearchIndex(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.String> createSearchIndexes(java.util.List<com.mongodb.client.model.SearchIndexModel> arg0) {
        return Publishers.list(() -> sync.createSearchIndexes(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> updateSearchIndex(java.lang.String arg0, org.bson.conversions.Bson arg1) {
        return Publishers.run(() -> sync.updateSearchIndex(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> dropSearchIndex(java.lang.String arg0) {
        return Publishers.run(() -> sync.dropSearchIndex(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.ListSearchIndexesPublisher<org.bson.Document> listSearchIndexes() {
        return new ListSearchIndexesPublisherImpl<>(sync.listSearchIndexes());
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.ListSearchIndexesPublisher<TResult> listSearchIndexes(java.lang.Class<TResult> arg0) {
        return new ListSearchIndexesPublisherImpl<>(sync.listSearchIndexes(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.String> createIndex(org.bson.conversions.Bson arg0) {
        return Publishers.single(() -> sync.createIndex(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.String> createIndex(org.bson.conversions.Bson arg0, com.mongodb.client.model.IndexOptions arg1) {
        return Publishers.single(() -> sync.createIndex(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.String> createIndex(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1) {
        return Publishers.single(() -> sync.createIndex(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.String> createIndex(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, com.mongodb.client.model.IndexOptions arg2) {
        return Publishers.single(() -> sync.createIndex(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.String> createIndexes(java.util.List<com.mongodb.client.model.IndexModel> arg0) {
        return Publishers.list(() -> sync.createIndexes(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.String> createIndexes(java.util.List<com.mongodb.client.model.IndexModel> arg0, com.mongodb.client.model.CreateIndexOptions arg1) {
        return Publishers.list(() -> sync.createIndexes(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.String> createIndexes(com.mongodb.reactivestreams.client.ClientSession arg0, java.util.List<com.mongodb.client.model.IndexModel> arg1) {
        return Publishers.list(() -> sync.createIndexes(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.String> createIndexes(com.mongodb.reactivestreams.client.ClientSession arg0, java.util.List<com.mongodb.client.model.IndexModel> arg1, com.mongodb.client.model.CreateIndexOptions arg2) {
        return Publishers.list(() -> sync.createIndexes(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public com.mongodb.reactivestreams.client.ListIndexesPublisher<org.bson.Document> listIndexes() {
        return new ListIndexesPublisherImpl<>(sync.listIndexes());
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.ListIndexesPublisher<TResult> listIndexes(java.lang.Class<TResult> arg0) {
        return new ListIndexesPublisherImpl<>(sync.listIndexes(arg0));
    }

    @Override
    public com.mongodb.reactivestreams.client.ListIndexesPublisher<org.bson.Document> listIndexes(com.mongodb.reactivestreams.client.ClientSession arg0) {
        return new ListIndexesPublisherImpl<>(sync.listIndexes(Sessions.sync(arg0)));
    }

    @Override
    public <TResult> com.mongodb.reactivestreams.client.ListIndexesPublisher<TResult> listIndexes(com.mongodb.reactivestreams.client.ClientSession arg0, java.lang.Class<TResult> arg1) {
        return new ListIndexesPublisherImpl<>(sync.listIndexes(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> dropIndex(java.lang.String arg0) {
        return Publishers.run(() -> sync.dropIndex(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> dropIndex(org.bson.conversions.Bson arg0) {
        return Publishers.run(() -> sync.dropIndex(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> dropIndex(java.lang.String arg0, com.mongodb.client.model.DropIndexOptions arg1) {
        return Publishers.run(() -> sync.dropIndex(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> dropIndex(org.bson.conversions.Bson arg0, com.mongodb.client.model.DropIndexOptions arg1) {
        return Publishers.run(() -> sync.dropIndex(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> dropIndex(com.mongodb.reactivestreams.client.ClientSession arg0, java.lang.String arg1) {
        return Publishers.run(() -> sync.dropIndex(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> dropIndex(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1) {
        return Publishers.run(() -> sync.dropIndex(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> dropIndex(com.mongodb.reactivestreams.client.ClientSession arg0, java.lang.String arg1, com.mongodb.client.model.DropIndexOptions arg2) {
        return Publishers.run(() -> sync.dropIndex(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> dropIndex(com.mongodb.reactivestreams.client.ClientSession arg0, org.bson.conversions.Bson arg1, com.mongodb.client.model.DropIndexOptions arg2) {
        return Publishers.run(() -> sync.dropIndex(Sessions.sync(arg0), arg1, arg2));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> dropIndexes() {
        return Publishers.run(() -> sync.dropIndexes());
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> dropIndexes(com.mongodb.client.model.DropIndexOptions arg0) {
        return Publishers.run(() -> sync.dropIndexes(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> dropIndexes(com.mongodb.reactivestreams.client.ClientSession arg0) {
        return Publishers.run(() -> sync.dropIndexes(Sessions.sync(arg0)));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> dropIndexes(com.mongodb.reactivestreams.client.ClientSession arg0, com.mongodb.client.model.DropIndexOptions arg1) {
        return Publishers.run(() -> sync.dropIndexes(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> renameCollection(com.mongodb.MongoNamespace arg0) {
        return Publishers.run(() -> sync.renameCollection(arg0));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> renameCollection(com.mongodb.MongoNamespace arg0, com.mongodb.client.model.RenameCollectionOptions arg1) {
        return Publishers.run(() -> sync.renameCollection(arg0, arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> renameCollection(com.mongodb.reactivestreams.client.ClientSession arg0, com.mongodb.MongoNamespace arg1) {
        return Publishers.run(() -> sync.renameCollection(Sessions.sync(arg0), arg1));
    }

    @Override
    public org.reactivestreams.Publisher<java.lang.Void> renameCollection(com.mongodb.reactivestreams.client.ClientSession arg0, com.mongodb.MongoNamespace arg1, com.mongodb.client.model.RenameCollectionOptions arg2) {
        return Publishers.run(() -> sync.renameCollection(Sessions.sync(arg0), arg1, arg2));
    }

}
