package space.seclume.mongodb.driver;

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonInt64;
import org.bson.BsonString;
import org.bson.Document;
import org.bson.codecs.configuration.CodecRegistry;
import org.bson.conversions.Bson;

import com.mongodb.MongoNamespace;
import com.mongodb.ReadConcern;
import com.mongodb.ReadPreference;
import com.mongodb.WriteConcern;
import com.mongodb.client.AggregateIterable;
import com.mongodb.client.ChangeStreamIterable;
import com.mongodb.client.ClientSession;
import com.mongodb.client.ListCollectionNamesIterable;
import com.mongodb.client.ListCollectionsIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.CreateCollectionOptions;
import com.mongodb.client.model.CreateViewOptions;
import com.mongodb.client.model.TimeSeriesOptions;
import com.mongodb.client.model.ValidationOptions;

import space.seclume.mongodb.driver.internal.LogicalSession;
import space.seclume.mongodb.driver.internal.Topology;

final class SeclumeDatabase implements MongoDatabase {

    private final Topology topology;
    private final String name;
    private final CodecRegistry registry;
    private final ReadPreference readPreference;
    private final WriteConcern writeConcern;
    private final ReadConcern readConcern;

    SeclumeDatabase(Topology topology, String name, CodecRegistry registry,
            ReadPreference readPreference, WriteConcern writeConcern, ReadConcern readConcern) {
        MongoNamespace.checkDatabaseNameValidity(name);
        this.topology = topology;
        this.name = name;
        this.registry = registry;
        this.readPreference = readPreference;
        this.writeConcern = writeConcern;
        this.readConcern = readConcern;
    }

    private LogicalSession session(ClientSession session) {
        return SeclumeClientSession.of(session, topology);
    }

    @Override
    public String getName() {
        return name;
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
    public MongoDatabase withCodecRegistry(CodecRegistry codecRegistry) {
        return new SeclumeDatabase(topology, name, codecRegistry, readPreference, writeConcern,
                readConcern);
    }

    @Override
    public MongoDatabase withReadPreference(ReadPreference preference) {
        return new SeclumeDatabase(topology, name, registry, preference, writeConcern,
                readConcern);
    }

    @Override
    public MongoDatabase withWriteConcern(WriteConcern concern) {
        return new SeclumeDatabase(topology, name, registry, readPreference, concern,
                readConcern);
    }

    @Override
    public MongoDatabase withReadConcern(ReadConcern concern) {
        return new SeclumeDatabase(topology, name, registry, readPreference, writeConcern,
                concern);
    }

    @Override
    public MongoDatabase withTimeout(long timeout, TimeUnit unit) {
        throw Iterables.noTimeoutMode();
    }

    @Override
    public MongoCollection<Document> getCollection(String collection) {
        return getCollection(collection, Document.class);
    }

    @Override
    public <T> MongoCollection<T> getCollection(String collection, Class<T> type) {
        MongoNamespace.checkCollectionNameValidity(collection);
        return new SeclumeCollection<>(topology, new MongoNamespace(name, collection), type,
                registry, readPreference, writeConcern, readConcern);
    }

    // ---- commands -----------------------------------------------------------

    @Override
    public Document runCommand(Bson command) {
        return runCommand(null, command, readPreference, Document.class);
    }

    @Override
    public Document runCommand(Bson command, ReadPreference preference) {
        return runCommand(null, command, preference, Document.class);
    }

    @Override
    public <R> R runCommand(Bson command, Class<R> type) {
        return runCommand(null, command, readPreference, type);
    }

    @Override
    public <R> R runCommand(Bson command, ReadPreference preference, Class<R> type) {
        return runCommand(null, command, preference, type);
    }

    @Override
    public Document runCommand(ClientSession session, Bson command) {
        return runCommand(session, command, readPreference, Document.class);
    }

    @Override
    public Document runCommand(ClientSession session, Bson command, ReadPreference preference) {
        return runCommand(session, command, preference, Document.class);
    }

    @Override
    public <R> R runCommand(ClientSession session, Bson command, Class<R> type) {
        return runCommand(session, command, readPreference, type);
    }

    /**
     * The command as given - no read or write concern added, as the official
     * driver does for {@code runCommand}. One server so far, so the read
     * preference chooses nothing yet.
     */
    @Override
    public <R> R runCommand(ClientSession session, Bson command, ReadPreference preference,
            Class<R> type) {
        LogicalSession s = session(session);
        BsonDocument reply = topology.command(s, preference, name,
                command.toBsonDocument(BsonDocument.class, registry)).document();
        return Bsons.decode(reply, registry.get(type));
    }

    @Override
    public void drop() {
        drop(null);
    }

    @Override
    public void drop(ClientSession session) {
        LogicalSession s = session(session);
        BsonDocument command = new BsonDocument("dropDatabase", new BsonInt32(1));
        Bsons.writeConcern(command, writeConcern);
        topology.command(s, ReadPreference.primary(), name, command);
    }

    // ---- collections --------------------------------------------------------

    @Override
    public ListCollectionNamesIterable listCollectionNames() {
        return listCollectionNames(null);
    }

    @Override
    public ListCollectionsIterable<Document> listCollections() {
        return listCollections(null, Document.class);
    }

    @Override
    public <R> ListCollectionsIterable<R> listCollections(Class<R> type) {
        return listCollections(null, type);
    }

    @Override
    public ListCollectionNamesIterable listCollectionNames(ClientSession session) {
        LogicalSession s = session(session);
        return new Iterables.ListCollectionNames(topology, s, name, registry);
    }

    @Override
    public ListCollectionsIterable<Document> listCollections(ClientSession session) {
        return listCollections(session, Document.class);
    }

    @Override
    public <R> ListCollectionsIterable<R> listCollections(ClientSession session, Class<R> type) {
        LogicalSession s = session(session);
        return new Iterables.ListCollections<>(topology, s, registry.get(type), name, false,
                registry);
    }

    @Override
    public void createCollection(String collection) {
        createCollection(null, collection, new CreateCollectionOptions());
    }

    @Override
    public void createCollection(String collection, CreateCollectionOptions options) {
        createCollection(null, collection, options);
    }

    @Override
    public void createCollection(ClientSession session, String collection) {
        createCollection(session, collection, new CreateCollectionOptions());
    }

    @Override
    public void createCollection(ClientSession session, String collection,
            CreateCollectionOptions options) {
        LogicalSession s = session(session);
        MongoNamespace.checkCollectionNameValidity(collection);
        if (options.getEncryptedFields() != null) {
            throw new UnsupportedOperationException("queryable encryption is not supported by "
                    + "seclume's MongoDB driver");
        }
        BsonDocument command = new BsonDocument("create", new BsonString(collection));
        Bsons.putTrue(command, "capped", options.isCapped());
        if (options.getSizeInBytes() > 0) {
            command.put("size", new BsonInt64(options.getSizeInBytes()));
        }
        if (options.getMaxDocuments() > 0) {
            command.put("max", new BsonInt64(options.getMaxDocuments()));
        }
        Bsons.put(command, "storageEngine", options.getStorageEngineOptions(), Document.class,
                registry);
        if (options.getIndexOptionDefaults().getStorageEngine() != null) {
            command.put("indexOptionDefaults", new BsonDocument("storageEngine",
                    Bsons.toDocument(options.getIndexOptionDefaults().getStorageEngine(),
                            Document.class, registry)));
        }
        ValidationOptions validation = options.getValidationOptions();
        Bsons.put(command, "validator", validation.getValidator(), Document.class, registry);
        if (validation.getValidationLevel() != null) {
            command.put("validationLevel",
                    new BsonString(validation.getValidationLevel().getValue()));
        }
        if (validation.getValidationAction() != null) {
            command.put("validationAction",
                    new BsonString(validation.getValidationAction().getValue()));
        }
        Bsons.put(command, "collation", options.getCollation());
        long expire = options.getExpireAfter(TimeUnit.SECONDS);
        if (expire > 0) {          // 0 is "not set" here, and refused by the server
            command.put("expireAfterSeconds", new BsonInt64(expire));
        }
        TimeSeriesOptions timeSeries = options.getTimeSeriesOptions();
        if (timeSeries != null) {
            BsonDocument series = new BsonDocument("timeField",
                    new BsonString(timeSeries.getTimeField()));
            Bsons.put(series, "metaField", timeSeries.getMetaField());
            if (timeSeries.getGranularity() != null) {
                series.put("granularity", new BsonString(
                        timeSeries.getGranularity().name().toLowerCase(java.util.Locale.ROOT)));
            }
            Long span = timeSeries.getBucketMaxSpan(TimeUnit.SECONDS);
            if (span != null) {
                series.put("bucketMaxSpanSeconds", new BsonInt64(span));
            }
            Long rounding = timeSeries.getBucketRounding(TimeUnit.SECONDS);
            if (rounding != null) {
                series.put("bucketRoundingSeconds", new BsonInt64(rounding));
            }
            command.put("timeseries", series);
        }
        if (options.getClusteredIndexOptions() != null) {
            var clustered = options.getClusteredIndexOptions();
            BsonDocument index = new BsonDocument("key", Bsons.toDocument(clustered.getKey(),
                    Document.class, registry))
                    .append("unique", org.bson.BsonBoolean.valueOf(clustered.isUnique()));
            Bsons.put(index, "name", clustered.getName());
            command.put("clusteredIndex", index);
        }
        if (options.getChangeStreamPreAndPostImagesOptions() != null) {
            command.put("changeStreamPreAndPostImages", new BsonDocument("enabled",
                    org.bson.BsonBoolean.valueOf(
                            options.getChangeStreamPreAndPostImagesOptions().isEnabled())));
        }
        Bsons.writeConcern(command, writeConcern);
        topology.command(s, ReadPreference.primary(), name, command);
    }

    @Override
    public void createView(String view, String on, List<? extends Bson> pipeline) {
        createView(null, view, on, pipeline, new CreateViewOptions());
    }

    @Override
    public void createView(String view, String on, List<? extends Bson> pipeline,
            CreateViewOptions options) {
        createView(null, view, on, pipeline, options);
    }

    @Override
    public void createView(ClientSession session, String view, String on,
            List<? extends Bson> pipeline) {
        createView(session, view, on, pipeline, new CreateViewOptions());
    }

    @Override
    public void createView(ClientSession session, String view, String on,
            List<? extends Bson> pipeline, CreateViewOptions options) {
        LogicalSession s = session(session);
        BsonDocument command = new BsonDocument("create", new BsonString(view))
                .append("viewOn", new BsonString(on))
                .append("pipeline", Bsons.toArray(pipeline, Document.class, registry));
        Bsons.put(command, "collation", options.getCollation());
        Bsons.writeConcern(command, writeConcern);
        topology.command(s, ReadPreference.primary(), name, command);
    }

    // ---- aggregation and change streams -------------------------------------

    @Override
    public ChangeStreamIterable<Document> watch() {
        throw SeclumeCollection.changeStreams();
    }

    @Override
    public <R> ChangeStreamIterable<R> watch(Class<R> type) {
        throw SeclumeCollection.changeStreams();
    }

    @Override
    public ChangeStreamIterable<Document> watch(List<? extends Bson> pipeline) {
        throw SeclumeCollection.changeStreams();
    }

    @Override
    public <R> ChangeStreamIterable<R> watch(List<? extends Bson> pipeline, Class<R> type) {
        throw SeclumeCollection.changeStreams();
    }

    @Override
    public ChangeStreamIterable<Document> watch(ClientSession session) {
        throw SeclumeCollection.changeStreams();
    }

    @Override
    public <R> ChangeStreamIterable<R> watch(ClientSession session, Class<R> type) {
        throw SeclumeCollection.changeStreams();
    }

    @Override
    public ChangeStreamIterable<Document> watch(ClientSession session,
            List<? extends Bson> pipeline) {
        throw SeclumeCollection.changeStreams();
    }

    @Override
    public <R> ChangeStreamIterable<R> watch(ClientSession session, List<? extends Bson> pipeline,
            Class<R> type) {
        throw SeclumeCollection.changeStreams();
    }

    @Override
    public AggregateIterable<Document> aggregate(List<? extends Bson> pipeline) {
        return aggregate(null, pipeline, Document.class);
    }

    @Override
    public <R> AggregateIterable<R> aggregate(List<? extends Bson> pipeline, Class<R> type) {
        return aggregate(null, pipeline, type);
    }

    @Override
    public AggregateIterable<Document> aggregate(ClientSession session,
            List<? extends Bson> pipeline) {
        return aggregate(session, pipeline, Document.class);
    }

    /** A database-level aggregation: {@code aggregate: 1}, for {@code $documents} and the like. */
    @Override
    public <R> AggregateIterable<R> aggregate(ClientSession session, List<? extends Bson> pipeline,
            Class<R> type) {
        LogicalSession s = session(session);
        return new Iterables.Aggregate<>(topology, s, readPreference, registry.get(type), name,
                new BsonInt32(1),
                pipeline, Document.class, registry,
                () -> readConcern.isServerDefault() ? null : readConcern.asDocument(),
                () -> {
                    BsonDocument holder = new BsonDocument();
                    Bsons.writeConcern(holder, writeConcern);
                    return holder.isEmpty() ? null : holder.getDocument("writeConcern");
                });
    }
}
