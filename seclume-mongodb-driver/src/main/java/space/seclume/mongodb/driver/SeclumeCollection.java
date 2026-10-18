package space.seclume.mongodb.driver;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.bson.BsonArray;
import org.bson.BsonBoolean;
import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonString;
import org.bson.BsonValue;
import org.bson.Document;
import org.bson.codecs.Codec;
import org.bson.codecs.configuration.CodecRegistry;
import org.bson.conversions.Bson;

import com.mongodb.MongoCommandException;
import com.mongodb.MongoNamespace;
import com.mongodb.ReadConcern;
import com.mongodb.ReadPreference;
import com.mongodb.WriteConcern;
import com.mongodb.bulk.BulkWriteInsert;
import com.mongodb.bulk.BulkWriteResult;
import com.mongodb.bulk.BulkWriteUpsert;
import com.mongodb.client.AggregateIterable;
import com.mongodb.client.ChangeStreamIterable;
import com.mongodb.client.ClientSession;
import com.mongodb.client.DistinctIterable;
import com.mongodb.client.FindIterable;
import com.mongodb.client.ListIndexesIterable;
import com.mongodb.client.ListSearchIndexesIterable;
import com.mongodb.client.MapReduceIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.BulkWriteOptions;
import com.mongodb.client.model.CountOptions;
import com.mongodb.client.model.CreateIndexOptions;
import com.mongodb.client.model.DeleteManyModel;
import com.mongodb.client.model.DeleteOneModel;
import com.mongodb.client.model.DeleteOptions;
import com.mongodb.client.model.DropCollectionOptions;
import com.mongodb.client.model.DropIndexOptions;
import com.mongodb.client.model.EstimatedDocumentCountOptions;
import com.mongodb.client.model.FindOneAndDeleteOptions;
import com.mongodb.client.model.FindOneAndReplaceOptions;
import com.mongodb.client.model.FindOneAndUpdateOptions;
import com.mongodb.client.model.IndexModel;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.InsertManyOptions;
import com.mongodb.client.model.InsertOneModel;
import com.mongodb.client.model.InsertOneOptions;
import com.mongodb.client.model.RenameCollectionOptions;
import com.mongodb.client.model.ReplaceOneModel;
import com.mongodb.client.model.ReplaceOptions;
import com.mongodb.client.model.ReturnDocument;
import com.mongodb.client.model.SearchIndexModel;
import com.mongodb.client.model.UpdateManyModel;
import com.mongodb.client.model.UpdateOneModel;
import com.mongodb.client.model.UpdateOptions;
import com.mongodb.client.model.WriteModel;
import com.mongodb.client.result.DeleteResult;
import com.mongodb.client.result.InsertManyResult;
import com.mongodb.client.result.InsertOneResult;
import com.mongodb.client.result.UpdateResult;

import space.seclume.mongodb.driver.internal.LogicalSession;
import space.seclume.mongodb.driver.internal.Topology;

/**
 * A collection: every overload of the API comes down to one method per
 * operation, which builds the command the server documents for it.
 *
 * <p>Command fields and their meaning are from the server's command reference
 * (mongodb.com/docs/manual/reference/command) and the CRUD specification
 * (github.com/mongodb/specifications, source/crud/crud.md).
 */
final class SeclumeCollection<T> implements MongoCollection<T> {

    private static final int NAMESPACE_NOT_FOUND = 26;

    private final Topology topology;
    private final MongoNamespace namespace;
    private final Class<T> documentClass;
    private final CodecRegistry registry;
    private final ReadPreference readPreference;
    private final WriteConcern writeConcern;
    private final ReadConcern readConcern;

    SeclumeCollection(Topology topology, MongoNamespace namespace, Class<T> documentClass,
            CodecRegistry registry, ReadPreference readPreference, WriteConcern writeConcern,
            ReadConcern readConcern) {
        this.topology = topology;
        this.namespace = namespace;
        this.documentClass = documentClass;
        this.registry = registry;
        this.readPreference = readPreference;
        this.writeConcern = writeConcern;
        this.readConcern = readConcern;
    }

    private String db() {
        return namespace.getDatabaseName();
    }

    private String name() {
        return namespace.getCollectionName();
    }

    private Codec<T> codec() {
        return registry.get(documentClass);
    }

    private BsonDocument doc(Bson bson) {
        return Bsons.toDocument(bson, documentClass, registry);
    }

    private BsonDocument filter(Bson filter) {
        if (filter == null) {
            throw new IllegalArgumentException("the filter is null");
        }
        return doc(filter);
    }

    private BsonDocument readConcernDocument() {
        return readConcern.isServerDefault() ? null : readConcern.asDocument();
    }

    private BsonDocument writeConcernDocument() {
        BsonDocument holder = new BsonDocument();
        Bsons.writeConcern(holder, writeConcern);
        return holder.isEmpty() ? null : holder.getDocument("writeConcern");
    }

    private BsonDocument writeCommand(String verb, Boolean ordered, Boolean bypass,
            BsonValue comment, Bson let) {
        BsonDocument command = new BsonDocument(verb, new BsonString(name()));
        Bsons.put(command, "ordered", ordered);
        Bsons.put(command, "bypassDocumentValidation", bypass);
        Bsons.put(command, "comment", comment);
        Bsons.put(command, "let", let, documentClass, registry);
        Bsons.writeConcern(command, writeConcern);
        return command;
    }

    static UnsupportedOperationException sessions() {
        return new UnsupportedOperationException("explicit client sessions and transactions "
                + "are not supported by seclume's MongoDB driver yet");
    }

    private LogicalSession session(ClientSession session) {
        return SeclumeClientSession.of(session, topology);
    }

    private void primary(LogicalSession session, String database, BsonDocument command) {
        topology.command(session, ReadPreference.primary(), database, command);
    }

    // ---- settings -----------------------------------------------------------

    @Override
    public MongoNamespace getNamespace() {
        return namespace;
    }

    @Override
    public Class<T> getDocumentClass() {
        return documentClass;
    }

    @Override
    public CodecRegistry getCodecRegistry() {
        return registry;
    }

    @Override
    public ReadPreference getReadPreference() {
        return readPreference;
    }

    @Override
    public WriteConcern getWriteConcern() {
        return writeConcern;
    }

    @Override
    public ReadConcern getReadConcern() {
        return readConcern;
    }

    @Override
    public Long getTimeout(TimeUnit unit) {
        return null;
    }

    @Override
    public <N> MongoCollection<N> withDocumentClass(Class<N> type) {
        return new SeclumeCollection<>(topology, namespace, type, registry, readPreference,
                writeConcern, readConcern);
    }

    @Override
    public MongoCollection<T> withCodecRegistry(CodecRegistry codecRegistry) {
        return new SeclumeCollection<>(topology, namespace, documentClass, codecRegistry,
                readPreference, writeConcern, readConcern);
    }

    @Override
    public MongoCollection<T> withReadPreference(ReadPreference preference) {
        return new SeclumeCollection<>(topology, namespace, documentClass, registry, preference,
                writeConcern, readConcern);
    }

    @Override
    public MongoCollection<T> withWriteConcern(WriteConcern concern) {
        return new SeclumeCollection<>(topology, namespace, documentClass, registry,
                readPreference, concern, readConcern);
    }

    @Override
    public MongoCollection<T> withReadConcern(ReadConcern concern) {
        return new SeclumeCollection<>(topology, namespace, documentClass, registry,
                readPreference, writeConcern, concern);
    }

    @Override
    public MongoCollection<T> withTimeout(long timeout, TimeUnit unit) {
        throw Iterables.noTimeoutMode();
    }

    // ---- counting -----------------------------------------------------------

    @Override
    public long countDocuments() {
        return countDocuments(null, new BsonDocument(), new CountOptions());
    }

    @Override
    public long countDocuments(Bson filter) {
        return countDocuments(null, filter, new CountOptions());
    }

    @Override
    public long countDocuments(Bson filter, CountOptions options) {
        return countDocuments(null, filter, options);
    }

    @Override
    public long countDocuments(ClientSession session) {
        return countDocuments(session, new BsonDocument(), new CountOptions());
    }

    @Override
    public long countDocuments(ClientSession session, Bson filter) {
        return countDocuments(session, filter, new CountOptions());
    }

    /**
     * As the CRUD specification prescribes: an aggregation that matches,
     * skips, limits and counts - {@code count} itself is wrong on a sharded
     * cluster after an unclean shutdown, and on views.
     */
    @Override
    public long countDocuments(ClientSession session, Bson filter, CountOptions options) {
        LogicalSession s = session(session);
        BsonArray pipeline = new BsonArray();
        pipeline.add(new BsonDocument("$match", filter(filter)));
        if (options.getSkip() > 0) {
            pipeline.add(new BsonDocument("$skip", new BsonInt32(options.getSkip())));
        }
        if (options.getLimit() > 0) {
            pipeline.add(new BsonDocument("$limit", new BsonInt32(options.getLimit())));
        }
        pipeline.add(new BsonDocument("$group", new BsonDocument("_id", new BsonInt32(1))
                .append("n", new BsonDocument("$sum", new BsonInt32(1)))));
        BsonDocument command = new BsonDocument("aggregate", new BsonString(name()))
                .append("pipeline", pipeline).append("cursor", new BsonDocument());
        Bsons.hint(command, options.getHint(), options.getHintString(), documentClass, registry);
        Bsons.maxTime(command, options.getMaxTime(TimeUnit.MILLISECONDS));
        Bsons.put(command, "collation", options.getCollation());
        Bsons.put(command, "comment", options.getComment());
        Bsons.readConcern(command, readConcern);
        BsonArray batch = topology.read(s, readPreference, db(), command).document()
                .getDocument("cursor")
                .getArray("firstBatch");
        return batch.isEmpty() ? 0 : batch.get(0).asDocument().getNumber("n").longValue();
    }

    @Override
    public long estimatedDocumentCount() {
        return estimatedDocumentCount(new EstimatedDocumentCountOptions());
    }

    @Override
    public long estimatedDocumentCount(EstimatedDocumentCountOptions options) {
        BsonDocument command = new BsonDocument("count", new BsonString(name()));
        Bsons.maxTime(command, options.getMaxTime(TimeUnit.MILLISECONDS));
        Bsons.put(command, "comment", options.getComment());
        Bsons.readConcern(command, readConcern);
        try {
            return topology.read(null, readPreference, db(), command).document()
                    .getNumber("n").longValue();
        } catch (MongoCommandException e) {
            if (e.getErrorCode() == NAMESPACE_NOT_FOUND) {
                return 0;
            }
            throw e;
        }
    }

    // ---- reading ------------------------------------------------------------

    @Override
    public <R> DistinctIterable<R> distinct(String field, Class<R> type) {
        return distinct(null, field, null, type);
    }

    @Override
    public <R> DistinctIterable<R> distinct(String field, Bson filter, Class<R> type) {
        return distinct(null, field, filter, type);
    }

    @Override
    public <R> DistinctIterable<R> distinct(ClientSession session, String field, Class<R> type) {
        return distinct(session, field, null, type);
    }

    @Override
    public <R> DistinctIterable<R> distinct(ClientSession session, String field, Bson filter,
            Class<R> type) {
        LogicalSession s = session(session);
        return new Iterables.Distinct<>(topology, s, readPreference, registry.get(type), db(), name(), field, filter,
                documentClass, registry, this::readConcernDocument);
    }

    @Override
    public FindIterable<T> find() {
        return find(null, new BsonDocument(), documentClass);
    }

    @Override
    public <R> FindIterable<R> find(Class<R> type) {
        return find(null, new BsonDocument(), type);
    }

    @Override
    public FindIterable<T> find(Bson filter) {
        return find(null, filter, documentClass);
    }

    @Override
    public <R> FindIterable<R> find(Bson filter, Class<R> type) {
        return find(null, filter, type);
    }

    @Override
    public FindIterable<T> find(ClientSession session) {
        return find(session, new BsonDocument(), documentClass);
    }

    @Override
    public <R> FindIterable<R> find(ClientSession session, Class<R> type) {
        return find(session, new BsonDocument(), type);
    }

    @Override
    public FindIterable<T> find(ClientSession session, Bson filter) {
        return find(session, filter, documentClass);
    }

    @Override
    public <R> FindIterable<R> find(ClientSession session, Bson filter, Class<R> type) {
        LogicalSession s = session(session);
        return new Iterables.Find<>(topology, s, readPreference, registry.get(type), db(), name(), documentClass,
                registry, filter, this::readConcernDocument);
    }

    @Override
    public AggregateIterable<T> aggregate(List<? extends Bson> pipeline) {
        return aggregate(null, pipeline, documentClass);
    }

    @Override
    public <R> AggregateIterable<R> aggregate(List<? extends Bson> pipeline, Class<R> type) {
        return aggregate(null, pipeline, type);
    }

    @Override
    public AggregateIterable<T> aggregate(ClientSession session, List<? extends Bson> pipeline) {
        return aggregate(session, pipeline, documentClass);
    }

    @Override
    public <R> AggregateIterable<R> aggregate(ClientSession session,
            List<? extends Bson> pipeline, Class<R> type) {
        LogicalSession s = session(session);
        return new Iterables.Aggregate<>(topology, s, readPreference, registry.get(type), db(),
                new BsonString(name()), pipeline, documentClass, registry,
                this::readConcernDocument, this::writeConcernDocument);
    }

    // ---- not in this driver yet ---------------------------------------------

    static UnsupportedOperationException changeStreams() {
        return new UnsupportedOperationException("change streams are not supported by "
                + "seclume's MongoDB driver yet");
    }

    @Override
    public ChangeStreamIterable<T> watch() {
        throw changeStreams();
    }

    @Override
    public <R> ChangeStreamIterable<R> watch(Class<R> type) {
        throw changeStreams();
    }

    @Override
    public ChangeStreamIterable<T> watch(List<? extends Bson> pipeline) {
        throw changeStreams();
    }

    @Override
    public <R> ChangeStreamIterable<R> watch(List<? extends Bson> pipeline, Class<R> type) {
        throw changeStreams();
    }

    @Override
    public ChangeStreamIterable<T> watch(ClientSession session) {
        throw changeStreams();
    }

    @Override
    public <R> ChangeStreamIterable<R> watch(ClientSession session, Class<R> type) {
        throw changeStreams();
    }

    @Override
    public ChangeStreamIterable<T> watch(ClientSession session, List<? extends Bson> pipeline) {
        throw changeStreams();
    }

    @Override
    public <R> ChangeStreamIterable<R> watch(ClientSession session,
            List<? extends Bson> pipeline, Class<R> type) {
        throw changeStreams();
    }

    private static UnsupportedOperationException mapReduce() {
        return new UnsupportedOperationException("mapReduce is deprecated by MongoDB and not "
                + "supported by seclume's MongoDB driver; use aggregate");
    }

    @Override
    @SuppressWarnings("deprecation")
    public MapReduceIterable<T> mapReduce(String map, String reduce) {
        throw mapReduce();
    }

    @Override
    @SuppressWarnings("deprecation")
    public <R> MapReduceIterable<R> mapReduce(String map, String reduce, Class<R> type) {
        throw mapReduce();
    }

    @Override
    @SuppressWarnings("deprecation")
    public MapReduceIterable<T> mapReduce(ClientSession session, String map, String reduce) {
        throw mapReduce();
    }

    @Override
    @SuppressWarnings("deprecation")
    public <R> MapReduceIterable<R> mapReduce(ClientSession session, String map, String reduce,
            Class<R> type) {
        throw mapReduce();
    }

    private static UnsupportedOperationException searchIndexes() {
        return new UnsupportedOperationException("Atlas Search indexes are not supported by "
                + "seclume's MongoDB driver yet");
    }

    @Override
    public String createSearchIndex(String indexName, Bson definition) {
        throw searchIndexes();
    }

    @Override
    public String createSearchIndex(Bson definition) {
        throw searchIndexes();
    }

    @Override
    public List<String> createSearchIndexes(List<SearchIndexModel> models) {
        throw searchIndexes();
    }

    @Override
    public void updateSearchIndex(String indexName, Bson definition) {
        throw searchIndexes();
    }

    @Override
    public void dropSearchIndex(String indexName) {
        throw searchIndexes();
    }

    @Override
    public ListSearchIndexesIterable<Document> listSearchIndexes() {
        throw searchIndexes();
    }

    @Override
    public <R> ListSearchIndexesIterable<R> listSearchIndexes(Class<R> type) {
        throw searchIndexes();
    }

    // ---- inserting ----------------------------------------------------------

    @Override
    public InsertOneResult insertOne(T document) {
        return insertOne(null, document, new InsertOneOptions());
    }

    @Override
    public InsertOneResult insertOne(T document, InsertOneOptions options) {
        return insertOne(null, document, options);
    }

    @Override
    public InsertOneResult insertOne(ClientSession session, T document) {
        return insertOne(session, document, new InsertOneOptions());
    }

    @Override
    public InsertOneResult insertOne(ClientSession session, T document,
            InsertOneOptions options) {
        LogicalSession s = session(session);
        BsonDocument encoded = Bsons.encode(document, codec(), true);
        BsonDocument command = writeCommand("insert", null,
                options.getBypassDocumentValidation(), options.getComment(), null);
        Writes.Outcome outcome = Writes.run(topology, s, db(), command, "documents",
                List.of(encoded), true, true, 0, new Writes.Outcome());
        Writes.throwSingle(outcome, false);
        return InsertOneResult.acknowledged(encoded.get("_id"));
    }

    @Override
    public InsertManyResult insertMany(List<? extends T> documents) {
        return insertMany(null, documents, new InsertManyOptions());
    }

    @Override
    public InsertManyResult insertMany(List<? extends T> documents, InsertManyOptions options) {
        return insertMany(null, documents, options);
    }

    @Override
    public InsertManyResult insertMany(ClientSession session, List<? extends T> documents) {
        return insertMany(session, documents, new InsertManyOptions());
    }

    @Override
    public InsertManyResult insertMany(ClientSession session, List<? extends T> documents,
            InsertManyOptions options) {
        LogicalSession s = session(session);
        if (documents.isEmpty()) {
            throw new IllegalArgumentException("insertMany needs at least one document");
        }
        List<BsonDocument> encoded = new ArrayList<>(documents.size());
        for (T document : documents) {
            encoded.add(Bsons.encode(document, codec(), true));
        }
        BsonDocument command = writeCommand("insert", options.isOrdered(),
                options.getBypassDocumentValidation(), options.getComment(), null);
        Writes.Outcome outcome = Writes.run(topology, s, db(), command, "documents", encoded,
                options.isOrdered(), true, 0, new Writes.Outcome());
        Map<Integer, BsonValue> ids = new LinkedHashMap<>();
        List<BulkWriteInsert> inserts = new ArrayList<>();
        for (int i = 0; i < encoded.size(); i++) {
            ids.put(i, encoded.get(i).get("_id"));
            inserts.add(new BulkWriteInsert(i, encoded.get(i).get("_id")));
        }
        Writes.throwBulk(outcome, Writes.result(outcome.n, 0, 0, 0, List.of(),
                succeeded(inserts, outcome)));
        return InsertManyResult.acknowledged(ids);
    }

    /** The inserts that are not among the errors - and, ordered, not after the first. */
    private static List<BulkWriteInsert> succeeded(List<BulkWriteInsert> inserts,
            Writes.Outcome outcome) {
        java.util.Set<Integer> failed = new java.util.HashSet<>();
        outcome.errors.forEach(error -> failed.add(error.getIndex()));
        List<BulkWriteInsert> through = new ArrayList<>();
        for (BulkWriteInsert insert : inserts) {
            if (!failed.contains(insert.getIndex()) && through.size() < outcome.n) {
                through.add(insert);
            }
        }
        return through;
    }

    // ---- deleting -----------------------------------------------------------

    @Override
    public DeleteResult deleteOne(Bson filter) {
        return delete(null, filter, new DeleteOptions(), 1);
    }

    @Override
    public DeleteResult deleteOne(Bson filter, DeleteOptions options) {
        return delete(null, filter, options, 1);
    }

    @Override
    public DeleteResult deleteOne(ClientSession session, Bson filter) {
        return delete(session, filter, new DeleteOptions(), 1);
    }

    @Override
    public DeleteResult deleteOne(ClientSession session, Bson filter, DeleteOptions options) {
        return delete(session, filter, options, 1);
    }

    @Override
    public DeleteResult deleteMany(Bson filter) {
        return delete(null, filter, new DeleteOptions(), 0);
    }

    @Override
    public DeleteResult deleteMany(Bson filter, DeleteOptions options) {
        return delete(null, filter, options, 0);
    }

    @Override
    public DeleteResult deleteMany(ClientSession session, Bson filter) {
        return delete(session, filter, new DeleteOptions(), 0);
    }

    @Override
    public DeleteResult deleteMany(ClientSession session, Bson filter, DeleteOptions options) {
        return delete(session, filter, options, 0);
    }

    private BsonDocument deleteStatement(Bson filter, DeleteOptions options, int limit) {
        BsonDocument statement = new BsonDocument("q", filter(filter))
                .append("limit", new BsonInt32(limit));
        Bsons.put(statement, "collation", options.getCollation());
        Bsons.hint(statement, options.getHint(), options.getHintString(), documentClass,
                registry);
        return statement;
    }

    private DeleteResult delete(ClientSession session, Bson filter, DeleteOptions options,
            int limit) {
        LogicalSession s = session(session);
        BsonDocument command = writeCommand("delete", null, null, options.getComment(),
                options.getLet());
        Writes.Outcome outcome = Writes.run(topology, s, db(), command, "deletes",
                List.of(deleteStatement(filter, options, limit)), true, limit == 1, 0,
                new Writes.Outcome());
        Writes.throwSingle(outcome, false);
        return DeleteResult.acknowledged(outcome.n);
    }

    // ---- updating -----------------------------------------------------------

    @Override
    public UpdateResult replaceOne(Bson filter, T replacement) {
        return replaceOne(null, filter, replacement, new ReplaceOptions());
    }

    @Override
    public UpdateResult replaceOne(Bson filter, T replacement, ReplaceOptions options) {
        return replaceOne(null, filter, replacement, options);
    }

    @Override
    public UpdateResult replaceOne(ClientSession session, Bson filter, T replacement) {
        return replaceOne(session, filter, replacement, new ReplaceOptions());
    }

    @Override
    public UpdateResult replaceOne(ClientSession session, Bson filter, T replacement,
            ReplaceOptions options) {
        LogicalSession s = session(session);
        BsonDocument command = writeCommand("update", null,
                options.getBypassDocumentValidation(), options.getComment(), options.getLet());
        return update(s, command, replaceStatement(filter, replacement, options), true);
    }

    private BsonDocument replaceStatement(Bson filter, T replacement, ReplaceOptions options) {
        BsonDocument encoded = Bsons.encode(replacement, codec(), false);
        Bsons.checkReplacement(encoded);
        BsonDocument statement = new BsonDocument("q", filter(filter)).append("u", encoded);
        Bsons.putTrue(statement, "upsert", options.isUpsert());
        Bsons.put(statement, "collation", options.getCollation());
        Bsons.hint(statement, options.getHint(), options.getHintString(), documentClass,
                registry);
        Bsons.put(statement, "sort", options.getSort(), documentClass, registry);
        return statement;
    }

    @Override
    public UpdateResult updateOne(Bson filter, Bson update) {
        return update(null, filter, update, null, new UpdateOptions(), false);
    }

    @Override
    public UpdateResult updateOne(Bson filter, Bson update, UpdateOptions options) {
        return update(null, filter, update, null, options, false);
    }

    @Override
    public UpdateResult updateOne(ClientSession session, Bson filter, Bson update) {
        return update(session, filter, update, null, new UpdateOptions(), false);
    }

    @Override
    public UpdateResult updateOne(ClientSession session, Bson filter, Bson update,
            UpdateOptions options) {
        return update(session, filter, update, null, options, false);
    }

    @Override
    public UpdateResult updateOne(Bson filter, List<? extends Bson> update) {
        return update(null, filter, null, update, new UpdateOptions(), false);
    }

    @Override
    public UpdateResult updateOne(Bson filter, List<? extends Bson> update,
            UpdateOptions options) {
        return update(null, filter, null, update, options, false);
    }

    @Override
    public UpdateResult updateOne(ClientSession session, Bson filter,
            List<? extends Bson> update) {
        return update(session, filter, null, update, new UpdateOptions(), false);
    }

    @Override
    public UpdateResult updateOne(ClientSession session, Bson filter,
            List<? extends Bson> update, UpdateOptions options) {
        return update(session, filter, null, update, options, false);
    }

    @Override
    public UpdateResult updateMany(Bson filter, Bson update) {
        return update(null, filter, update, null, new UpdateOptions(), true);
    }

    @Override
    public UpdateResult updateMany(Bson filter, Bson update, UpdateOptions options) {
        return update(null, filter, update, null, options, true);
    }

    @Override
    public UpdateResult updateMany(ClientSession session, Bson filter, Bson update) {
        return update(session, filter, update, null, new UpdateOptions(), true);
    }

    @Override
    public UpdateResult updateMany(ClientSession session, Bson filter, Bson update,
            UpdateOptions options) {
        return update(session, filter, update, null, options, true);
    }

    @Override
    public UpdateResult updateMany(Bson filter, List<? extends Bson> update) {
        return update(null, filter, null, update, new UpdateOptions(), true);
    }

    @Override
    public UpdateResult updateMany(Bson filter, List<? extends Bson> update,
            UpdateOptions options) {
        return update(null, filter, null, update, options, true);
    }

    @Override
    public UpdateResult updateMany(ClientSession session, Bson filter,
            List<? extends Bson> update) {
        return update(session, filter, null, update, new UpdateOptions(), true);
    }

    @Override
    public UpdateResult updateMany(ClientSession session, Bson filter,
            List<? extends Bson> update, UpdateOptions options) {
        return update(session, filter, null, update, options, true);
    }

    /** The update itself: operators, or a pipeline. */
    private BsonValue updateValue(Bson update, List<? extends Bson> pipeline) {
        if (pipeline != null) {
            return Bsons.toArray(pipeline, documentClass, registry);
        }
        if (update == null) {
            throw new IllegalArgumentException("the update is null");
        }
        BsonDocument operators = doc(update);
        Bsons.checkUpdate(operators);
        return operators;
    }

    private BsonDocument updateStatement(Bson filter, Bson update, List<? extends Bson> pipeline,
            UpdateOptions options, boolean multi) {
        BsonDocument statement = new BsonDocument("q", filter(filter))
                .append("u", updateValue(update, pipeline));
        Bsons.putTrue(statement, "multi", multi);
        Bsons.putTrue(statement, "upsert", options.isUpsert());
        Bsons.put(statement, "collation", options.getCollation());
        if (options.getArrayFilters() != null) {
            statement.put("arrayFilters", Bsons.toArray(options.getArrayFilters(), documentClass,
                    registry));
        }
        Bsons.hint(statement, options.getHint(), options.getHintString(), documentClass,
                registry);
        if (!multi) {
            Bsons.put(statement, "sort", options.getSort(), documentClass, registry);
        }
        return statement;
    }

    private UpdateResult update(ClientSession session, Bson filter, Bson update,
            List<? extends Bson> pipeline, UpdateOptions options, boolean multi) {
        LogicalSession s = session(session);
        BsonDocument command = writeCommand("update", null,
                options.getBypassDocumentValidation(), options.getComment(), options.getLet());
        return update(s, command, updateStatement(filter, update, pipeline, options, multi),
                !multi);
    }

    private UpdateResult update(LogicalSession s, BsonDocument command, BsonDocument statement,
            boolean retryable) {
        Writes.Outcome outcome = Writes.run(topology, s, db(), command, "updates",
                List.of(statement), true, retryable, 0, new Writes.Outcome());
        Writes.throwSingle(outcome, true);
        // n counts the upserted document as matched; the API does not.
        long matched = outcome.n - outcome.upserts.size();
        return UpdateResult.acknowledged(matched, (long) outcome.modified, outcome.upsertedId);
    }

    // ---- find and modify ----------------------------------------------------

    private T findAndModify(LogicalSession s, BsonDocument command) {
        Bsons.writeConcern(command, writeConcern);
        Topology.Reply sent = topology.write(s, db(), command, null, null, true);
        BsonDocument reply = sent.document();
        if (reply.containsKey("writeConcernError")) {
            Writes.Outcome outcome = new Writes.Outcome();
            outcome.address = sent.server().address();
            Writes.read(reply, 0, outcome);
            Writes.throwSingle(outcome, true);
        }
        BsonValue value = reply.get("value");
        return value == null || value.isNull() ? null : Bsons.decode(value.asDocument(), codec());
    }

    private BsonDocument findAndModifyCommand(Bson filter, Bson projection, Bson sort,
            long maxTimeMillis, com.mongodb.client.model.Collation collation, Bson hint,
            String hintString, BsonValue comment, Bson let) {
        BsonDocument command = new BsonDocument("findAndModify", new BsonString(name()))
                .append("query", filter(filter));
        Bsons.put(command, "fields", projection, documentClass, registry);
        Bsons.put(command, "sort", sort, documentClass, registry);
        Bsons.maxTime(command, maxTimeMillis);
        Bsons.put(command, "collation", collation);
        Bsons.hint(command, hint, hintString, documentClass, registry);
        Bsons.put(command, "comment", comment);
        Bsons.put(command, "let", let, documentClass, registry);
        return command;
    }

    @Override
    public T findOneAndDelete(Bson filter) {
        return findOneAndDelete(null, filter, new FindOneAndDeleteOptions());
    }

    @Override
    public T findOneAndDelete(Bson filter, FindOneAndDeleteOptions options) {
        return findOneAndDelete(null, filter, options);
    }

    @Override
    public T findOneAndDelete(ClientSession session, Bson filter) {
        return findOneAndDelete(session, filter, new FindOneAndDeleteOptions());
    }

    @Override
    public T findOneAndDelete(ClientSession session, Bson filter,
            FindOneAndDeleteOptions options) {
        LogicalSession s = session(session);
        BsonDocument command = findAndModifyCommand(filter, options.getProjection(),
                options.getSort(), options.getMaxTime(TimeUnit.MILLISECONDS),
                options.getCollation(), options.getHint(), options.getHintString(),
                options.getComment(), options.getLet());
        command.put("remove", BsonBoolean.TRUE);
        return findAndModify(s, command);
    }

    @Override
    public T findOneAndReplace(Bson filter, T replacement) {
        return findOneAndReplace(null, filter, replacement, new FindOneAndReplaceOptions());
    }

    @Override
    public T findOneAndReplace(Bson filter, T replacement, FindOneAndReplaceOptions options) {
        return findOneAndReplace(null, filter, replacement, options);
    }

    @Override
    public T findOneAndReplace(ClientSession session, Bson filter, T replacement) {
        return findOneAndReplace(session, filter, replacement, new FindOneAndReplaceOptions());
    }

    @Override
    public T findOneAndReplace(ClientSession session, Bson filter, T replacement,
            FindOneAndReplaceOptions options) {
        LogicalSession s = session(session);
        BsonDocument encoded = Bsons.encode(replacement, codec(), false);
        Bsons.checkReplacement(encoded);
        BsonDocument command = findAndModifyCommand(filter, options.getProjection(),
                options.getSort(), options.getMaxTime(TimeUnit.MILLISECONDS),
                options.getCollation(), options.getHint(), options.getHintString(),
                options.getComment(), options.getLet());
        command.put("update", encoded);
        Bsons.putTrue(command, "new", options.getReturnDocument() == ReturnDocument.AFTER);
        Bsons.putTrue(command, "upsert", options.isUpsert());
        Bsons.put(command, "bypassDocumentValidation", options.getBypassDocumentValidation());
        return findAndModify(s, command);
    }

    @Override
    public T findOneAndUpdate(Bson filter, Bson update) {
        return findOneAndUpdate(null, filter, update, null, new FindOneAndUpdateOptions());
    }

    @Override
    public T findOneAndUpdate(Bson filter, Bson update, FindOneAndUpdateOptions options) {
        return findOneAndUpdate(null, filter, update, null, options);
    }

    @Override
    public T findOneAndUpdate(ClientSession session, Bson filter, Bson update) {
        return findOneAndUpdate(session, filter, update, null, new FindOneAndUpdateOptions());
    }

    @Override
    public T findOneAndUpdate(ClientSession session, Bson filter, Bson update,
            FindOneAndUpdateOptions options) {
        return findOneAndUpdate(session, filter, update, null, options);
    }

    @Override
    public T findOneAndUpdate(Bson filter, List<? extends Bson> update) {
        return findOneAndUpdate(null, filter, null, update, new FindOneAndUpdateOptions());
    }

    @Override
    public T findOneAndUpdate(Bson filter, List<? extends Bson> update,
            FindOneAndUpdateOptions options) {
        return findOneAndUpdate(null, filter, null, update, options);
    }

    @Override
    public T findOneAndUpdate(ClientSession session, Bson filter, List<? extends Bson> update) {
        return findOneAndUpdate(session, filter, null, update, new FindOneAndUpdateOptions());
    }

    @Override
    public T findOneAndUpdate(ClientSession session, Bson filter, List<? extends Bson> update,
            FindOneAndUpdateOptions options) {
        return findOneAndUpdate(session, filter, null, update, options);
    }

    private T findOneAndUpdate(ClientSession session, Bson filter, Bson update,
            List<? extends Bson> pipeline, FindOneAndUpdateOptions options) {
        LogicalSession s = session(session);
        BsonDocument command = findAndModifyCommand(filter, options.getProjection(),
                options.getSort(), options.getMaxTime(TimeUnit.MILLISECONDS),
                options.getCollation(), options.getHint(), options.getHintString(),
                options.getComment(), options.getLet());
        command.put("update", updateValue(update, pipeline));
        Bsons.putTrue(command, "new", options.getReturnDocument() == ReturnDocument.AFTER);
        Bsons.putTrue(command, "upsert", options.isUpsert());
        Bsons.put(command, "bypassDocumentValidation", options.getBypassDocumentValidation());
        if (options.getArrayFilters() != null) {
            command.put("arrayFilters", Bsons.toArray(options.getArrayFilters(), documentClass,
                    registry));
        }
        return findAndModify(s, command);
    }

    // ---- bulk ---------------------------------------------------------------

    @Override
    public BulkWriteResult bulkWrite(List<? extends WriteModel<? extends T>> requests) {
        return bulkWrite(null, requests, new BulkWriteOptions());
    }

    @Override
    public BulkWriteResult bulkWrite(List<? extends WriteModel<? extends T>> requests,
            BulkWriteOptions options) {
        return bulkWrite(null, requests, options);
    }

    @Override
    public BulkWriteResult bulkWrite(ClientSession session,
            List<? extends WriteModel<? extends T>> requests) {
        return bulkWrite(session, requests, new BulkWriteOptions());
    }

    /**
     * Consecutive writes of one kind go as one command; the kinds are not
     * reordered, ordered or not, so that an unordered bulk does what the same
     * writes one by one would - only without stopping at the first error.
     */
    @Override
    @SuppressWarnings("unchecked")
    public BulkWriteResult bulkWrite(ClientSession session,
            List<? extends WriteModel<? extends T>> requests, BulkWriteOptions options) {
        LogicalSession s = session(session);
        if (requests.isEmpty()) {
            throw new IllegalArgumentException("bulkWrite needs at least one write");
        }
        boolean ordered = options.isOrdered();
        int inserted = 0;
        int matched = 0;
        int deleted = 0;
        int modified = 0;
        List<BulkWriteUpsert> upserts = new ArrayList<>();
        List<BulkWriteInsert> inserts = new ArrayList<>();
        Writes.Outcome all = new Writes.Outcome();
        int at = 0;
        while (at < requests.size()) {
            String verb = verb(requests.get(at));
            int end = at;
            List<BsonDocument> statements = new ArrayList<>();
            List<BulkWriteInsert> theseInserts = new ArrayList<>();
            while (end < requests.size() && verb(requests.get(end)).equals(verb)) {
                WriteModel<? extends T> request = requests.get(end);
                BsonDocument statement = statement((WriteModel<T>) request);
                if (verb.equals("insert")) {
                    theseInserts.add(new BulkWriteInsert(end, statement.get("_id")));
                }
                statements.add(statement);
                end++;
            }
            BsonDocument command = writeCommand(verb, ordered,
                    options.getBypassDocumentValidation(), options.getComment(),
                    verb.equals("insert") ? null : options.getLet());
            String field = switch (verb) {
                case "insert" -> "documents";
                case "update" -> "updates";
                default -> "deletes";
            };
            int errorsBefore = all.errors.size();
            // A statement for many documents cannot be retried: the server would
            // not know which of them the first attempt changed.
            boolean retryable = statements.stream().noneMatch(statement ->
                    statement.getBoolean("multi", BsonBoolean.FALSE).getValue()
                            || (statement.containsKey("limit")
                                    && statement.getNumber("limit").intValue() == 0));
            Writes.Outcome outcome = Writes.run(topology, s, db(), command, field, statements,
                    ordered, retryable, at, new Writes.Outcome());
            if (outcome.address != null) {
                all.address = outcome.address;
            }
            all.errors.addAll(outcome.errors);
            all.labels.addAll(outcome.labels);
            if (outcome.concernError != null) {
                all.concernError = outcome.concernError;
            }
            switch (verb) {
                case "insert" -> {
                    inserted += outcome.n;
                    inserts.addAll(succeeded(theseInserts, outcome));
                }
                case "update" -> {
                    matched += outcome.n - outcome.upserts.size();
                    modified += outcome.modified;
                    upserts.addAll(outcome.upserts);
                }
                default -> deleted += outcome.n;
            }
            at = end;
            if (ordered && all.errors.size() > errorsBefore) {
                break;
            }
        }
        BulkWriteResult result = Writes.result(inserted, matched, deleted, modified, upserts,
                inserts);
        Writes.throwBulk(all, result);
        return result;
    }

    private static String verb(WriteModel<?> request) {
        if (request instanceof InsertOneModel<?>) {
            return "insert";
        }
        if (request instanceof UpdateOneModel<?> || request instanceof UpdateManyModel<?>
                || request instanceof ReplaceOneModel<?>) {
            return "update";
        }
        if (request instanceof DeleteOneModel<?> || request instanceof DeleteManyModel<?>) {
            return "delete";
        }
        throw new IllegalArgumentException("an unknown write: " + request);
    }

    private BsonDocument statement(WriteModel<T> request) {
        if (request instanceof InsertOneModel<T> insert) {
            return Bsons.encode(insert.getDocument(), codec(), true);
        }
        if (request instanceof UpdateOneModel<T> update) {
            return updateStatement(update.getFilter(), update.getUpdate(),
                    update.getUpdatePipeline(), update.getOptions(), false);
        }
        if (request instanceof UpdateManyModel<T> update) {
            return updateStatement(update.getFilter(), update.getUpdate(),
                    update.getUpdatePipeline(), update.getOptions(), true);
        }
        if (request instanceof ReplaceOneModel<T> replace) {
            return replaceStatement(replace.getFilter(), replace.getReplacement(),
                    replace.getReplaceOptions());
        }
        if (request instanceof DeleteOneModel<T> delete) {
            return deleteStatement(delete.getFilter(), delete.getOptions(), 1);
        }
        DeleteManyModel<T> delete = (DeleteManyModel<T>) request;
        return deleteStatement(delete.getFilter(), delete.getOptions(), 0);
    }

    // ---- the collection itself ----------------------------------------------

    @Override
    public void drop() {
        drop(null, new DropCollectionOptions());
    }

    @Override
    public void drop(ClientSession session) {
        drop(session, new DropCollectionOptions());
    }

    @Override
    public void drop(DropCollectionOptions options) {
        drop(null, options);
    }

    @Override
    public void drop(ClientSession session, DropCollectionOptions options) {
        LogicalSession s = session(session);
        if (options.getEncryptedFields() != null) {
            throw new UnsupportedOperationException("queryable encryption is not supported by "
                    + "seclume's MongoDB driver");
        }
        BsonDocument command = new BsonDocument("drop", new BsonString(name()));
        Bsons.writeConcern(command, writeConcern);
        try {
            primary(s, db(), command);
        } catch (MongoCommandException e) {
            if (e.getErrorCode() != NAMESPACE_NOT_FOUND) {
                throw e;
            }
        }
    }

    @Override
    public void renameCollection(MongoNamespace target) {
        renameCollection(null, target, new RenameCollectionOptions());
    }

    @Override
    public void renameCollection(MongoNamespace target, RenameCollectionOptions options) {
        renameCollection(null, target, options);
    }

    @Override
    public void renameCollection(ClientSession session, MongoNamespace target) {
        renameCollection(session, target, new RenameCollectionOptions());
    }

    @Override
    public void renameCollection(ClientSession session, MongoNamespace target,
            RenameCollectionOptions options) {
        LogicalSession s = session(session);
        BsonDocument command = new BsonDocument("renameCollection",
                new BsonString(namespace.getFullName()))
                .append("to", new BsonString(target.getFullName()));
        Bsons.putTrue(command, "dropTarget", options.isDropTarget());
        Bsons.writeConcern(command, writeConcern);
        primary(s, "admin", command);
    }

    // ---- indexes ------------------------------------------------------------

    @Override
    public String createIndex(Bson keys) {
        return createIndex(null, keys, new IndexOptions());
    }

    @Override
    public String createIndex(Bson keys, IndexOptions options) {
        return createIndex(null, keys, options);
    }

    @Override
    public String createIndex(ClientSession session, Bson keys) {
        return createIndex(session, keys, new IndexOptions());
    }

    @Override
    public String createIndex(ClientSession session, Bson keys, IndexOptions options) {
        return createIndexes(session, List.of(new IndexModel(keys, options)),
                new CreateIndexOptions()).get(0);
    }

    @Override
    public List<String> createIndexes(List<IndexModel> indexes) {
        return createIndexes(null, indexes, new CreateIndexOptions());
    }

    @Override
    public List<String> createIndexes(List<IndexModel> indexes, CreateIndexOptions options) {
        return createIndexes(null, indexes, options);
    }

    @Override
    public List<String> createIndexes(ClientSession session, List<IndexModel> indexes) {
        return createIndexes(session, indexes, new CreateIndexOptions());
    }

    @Override
    public List<String> createIndexes(ClientSession session, List<IndexModel> indexes,
            CreateIndexOptions options) {
        LogicalSession s = session(session);
        BsonArray specifications = new BsonArray();
        List<String> names = new ArrayList<>();
        for (IndexModel index : indexes) {
            BsonDocument specification = Indexes.specification(index, documentClass, registry);
            names.add(specification.getString("name").getValue());
            specifications.add(specification);
        }
        BsonDocument command = new BsonDocument("createIndexes", new BsonString(name()))
                .append("indexes", specifications);
        Bsons.maxTime(command, options.getMaxTime(TimeUnit.MILLISECONDS));
        if (options.getCommitQuorum() != null) {
            command.put("commitQuorum", options.getCommitQuorum().toBsonValue());
        }
        Bsons.writeConcern(command, writeConcern);
        primary(s, db(), command);
        return names;
    }

    @Override
    public ListIndexesIterable<Document> listIndexes() {
        return listIndexes(null, Document.class);
    }

    @Override
    public <R> ListIndexesIterable<R> listIndexes(Class<R> type) {
        return listIndexes(null, type);
    }

    @Override
    public ListIndexesIterable<Document> listIndexes(ClientSession session) {
        return listIndexes(session, Document.class);
    }

    @Override
    public <R> ListIndexesIterable<R> listIndexes(ClientSession session, Class<R> type) {
        LogicalSession s = session(session);
        return new Iterables.ListIndexes<>(topology, s, registry.get(type), db(), name());
    }

    @Override
    public void dropIndex(String indexName) {
        dropIndexBy(null, new BsonString(indexName), new DropIndexOptions());
    }

    @Override
    public void dropIndex(String indexName, DropIndexOptions options) {
        dropIndexBy(null, new BsonString(indexName), options);
    }

    @Override
    public void dropIndex(Bson keys) {
        dropIndexBy(null, doc(keys), new DropIndexOptions());
    }

    @Override
    public void dropIndex(Bson keys, DropIndexOptions options) {
        dropIndexBy(null, doc(keys), options);
    }

    @Override
    public void dropIndex(ClientSession session, String indexName) {
        dropIndexBy(session, new BsonString(indexName), new DropIndexOptions());
    }

    @Override
    public void dropIndex(ClientSession session, Bson keys) {
        dropIndexBy(session, doc(keys), new DropIndexOptions());
    }

    @Override
    public void dropIndex(ClientSession session, String indexName, DropIndexOptions options) {
        dropIndexBy(session, new BsonString(indexName), options);
    }

    @Override
    public void dropIndex(ClientSession session, Bson keys, DropIndexOptions options) {
        dropIndexBy(session, doc(keys), options);
    }

    @Override
    public void dropIndexes() {
        dropIndexBy(null, new BsonString("*"), new DropIndexOptions());
    }

    @Override
    public void dropIndexes(ClientSession session) {
        dropIndexBy(session, new BsonString("*"), new DropIndexOptions());
    }

    @Override
    public void dropIndexes(DropIndexOptions options) {
        dropIndexBy(null, new BsonString("*"), options);
    }

    @Override
    public void dropIndexes(ClientSession session, DropIndexOptions options) {
        dropIndexBy(session, new BsonString("*"), options);
    }

    private void dropIndexBy(ClientSession session, BsonValue index, DropIndexOptions options) {
        LogicalSession s = session(session);
        BsonDocument command = new BsonDocument("dropIndexes", new BsonString(name()))
                .append("index", index);
        Bsons.maxTime(command, options.getMaxTime(TimeUnit.MILLISECONDS));
        Bsons.writeConcern(command, writeConcern);
        primary(s, db(), command);
    }
}
