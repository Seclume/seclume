package space.seclume.mongodb.driver;

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.bson.Document;
import org.bson.codecs.configuration.CodecRegistry;
import org.bson.conversions.Bson;

import com.mongodb.ClientBulkWriteException;
import com.mongodb.ClientSessionOptions;
import com.mongodb.MongoDriverInformation;
import com.mongodb.ReadConcern;
import com.mongodb.ReadPreference;
import com.mongodb.WriteConcern;
import com.mongodb.client.ChangeStreamIterable;
import com.mongodb.client.ClientSession;
import com.mongodb.client.ListDatabasesIterable;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCluster;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.MongoIterable;
import com.mongodb.client.model.bulk.ClientBulkWriteOptions;
import com.mongodb.client.model.bulk.ClientBulkWriteResult;
import com.mongodb.client.model.bulk.ClientNamespacedWriteModel;
import com.mongodb.connection.ClusterConnectionMode;
import com.mongodb.connection.ClusterDescription;
import com.mongodb.connection.ClusterType;
import com.mongodb.connection.ServerConnectionState;
import com.mongodb.connection.ServerDescription;
import com.mongodb.connection.ServerType;

import com.mongodb.TransactionOptions;

import space.seclume.mongodb.driver.internal.Deadline;
import space.seclume.mongodb.driver.internal.LogicalSession;
import space.seclume.mongodb.driver.internal.Topology;

/**
 * The client: settings, databases, and the cluster the connections come
 * from. {@code with...} gives a view with other settings over the same
 * connections, as the official driver's {@code MongoCluster} does.
 */
final class SeclumeClient implements MongoClient {

    private final Topology topology;
    private final CodecRegistry registry;
    private final ReadPreference readPreference;
    private final WriteConcern writeConcern;
    private final ReadConcern readConcern;
    /** {@code timeoutMS} for each operation; null for none set. */
    Long timeoutMillis;

    SeclumeClient(Topology topology, CodecRegistry registry, ReadPreference readPreference,
            WriteConcern writeConcern, ReadConcern readConcern) {
        this.topology = topology;
        this.registry = registry;
        this.readPreference = readPreference;
        this.writeConcern = writeConcern;
        this.readConcern = readConcern;
    }

    private LogicalSession session(ClientSession session) {
        return SeclumeClientSession.of(session, topology);
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
        return timeoutMillis == null ? null : unit.convert(timeoutMillis, TimeUnit.MILLISECONDS);
    }

    private SeclumeClient inherit(SeclumeClient other) {
        other.timeoutMillis = timeoutMillis;
        return other;
    }

    private SeclumeDatabase inherit(SeclumeDatabase other) {
        other.timeoutMillis = timeoutMillis;
        return other;
    }

    @Override
    public MongoCluster withCodecRegistry(CodecRegistry codecRegistry) {
        return inherit(new SeclumeClient(topology, codecRegistry, readPreference, writeConcern,
                readConcern));
    }

    @Override
    public MongoCluster withReadPreference(ReadPreference preference) {
        return inherit(new SeclumeClient(topology, registry, preference, writeConcern, readConcern));
    }

    @Override
    public MongoCluster withWriteConcern(WriteConcern concern) {
        return inherit(new SeclumeClient(topology, registry, readPreference, concern, readConcern));
    }

    @Override
    public MongoCluster withReadConcern(ReadConcern concern) {
        return inherit(new SeclumeClient(topology, registry, readPreference, writeConcern, concern));
    }

    @Override
    public MongoCluster withTimeout(long timeout, TimeUnit unit) {
        SeclumeClient copy = inherit(new SeclumeClient(topology, registry, readPreference,
                writeConcern, readConcern));
        copy.timeoutMillis = Iterables.millis(timeout, unit);
        return copy;
    }

    @Override
    public MongoDatabase getDatabase(String name) {
        return inherit(new SeclumeDatabase(topology, name, registry, readPreference, writeConcern,
                readConcern));
    }

    @Override
    public ClientSession startSession() {
        return startSession(ClientSessionOptions.builder().build());
    }

    @Override
    public ClientSession startSession(ClientSessionOptions options) {
        Long defaultTimeout = options.getDefaultTimeout(TimeUnit.MILLISECONDS);
        return new SeclumeClientSession(topology, options, this, TransactionOptions.builder()
                .readConcern(readConcern).writeConcern(writeConcern)
                .readPreference(readPreference).build(),
                defaultTimeout != null ? defaultTimeout : timeoutMillis);
    }

    @Override
    public MongoIterable<String> listDatabaseNames() {
        return listDatabaseNames(null);
    }

    @Override
    public MongoIterable<String> listDatabaseNames(ClientSession session) {
        try (Deadline.Scope _ = Deadline.enter(timeoutMillis)) {
            LogicalSession s = session(session);
            return Iterables.timed(new Iterables.ListDatabases<>(topology, s,
                    registry.get(Document.class), registry, true), timeoutMillis)
                    .map(database -> database.getString("name"));
        }
    }

    @Override
    public ListDatabasesIterable<Document> listDatabases() {
        return listDatabases(null, Document.class);
    }

    @Override
    public ListDatabasesIterable<Document> listDatabases(ClientSession session) {
        return listDatabases(session, Document.class);
    }

    @Override
    public <R> ListDatabasesIterable<R> listDatabases(Class<R> type) {
        return listDatabases(null, type);
    }

    @Override
    public <R> ListDatabasesIterable<R> listDatabases(ClientSession session, Class<R> type) {
        try (Deadline.Scope _ = Deadline.enter(timeoutMillis)) {
            LogicalSession s = session(session);
            return Iterables.timed(new Iterables.ListDatabases<>(topology, s, registry.get(type),
                    registry, false), timeoutMillis);
        }
    }

    @Override
    public ChangeStreamIterable<Document> watch() {
        return watchOn(null, List.of(), Document.class);
    }

    @Override
    public <R> ChangeStreamIterable<R> watch(Class<R> type) {
        return watchOn(null, List.of(), type);
    }

    @Override
    public ChangeStreamIterable<Document> watch(List<? extends Bson> pipeline) {
        return watchOn(null, pipeline, Document.class);
    }

    @Override
    public <R> ChangeStreamIterable<R> watch(List<? extends Bson> pipeline, Class<R> type) {
        return watchOn(null, pipeline, type);
    }

    @Override
    public ChangeStreamIterable<Document> watch(ClientSession session) {
        return watchOn(session, List.of(), Document.class);
    }

    @Override
    public <R> ChangeStreamIterable<R> watch(ClientSession session, Class<R> type) {
        return watchOn(session, List.of(), type);
    }

    @Override
    public ChangeStreamIterable<Document> watch(ClientSession session,
            List<? extends Bson> pipeline) {
        return watchOn(session, pipeline, Document.class);
    }

    @Override
    public <R> ChangeStreamIterable<R> watch(ClientSession session, List<? extends Bson> pipeline,
            Class<R> type) {
        return watchOn(session, pipeline, type);
    }

    /** A change stream on the whole cluster ({@code allChangesForCluster}). */
    private <R> ChangeStreamIterable<R> watchOn(ClientSession session,
            List<? extends Bson> pipeline, Class<R> type) {
        LogicalSession s = session(session);
        return new ChangeStreams.Stream<>(topology, s, readPreference, registry, type,
                ChangeStreams.Target.cluster(), pipeline,
                () -> readConcern.isServerDefault() ? null : readConcern.asDocument(),
                timeoutMillis);
    }

    @Override
    public ClientBulkWriteResult bulkWrite(List<? extends ClientNamespacedWriteModel> models)
            throws ClientBulkWriteException {
        return bulkWrite(null, models, null);
    }

    @Override
    public ClientBulkWriteResult bulkWrite(List<? extends ClientNamespacedWriteModel> models,
            ClientBulkWriteOptions options) throws ClientBulkWriteException {
        return bulkWrite(null, models, options);
    }

    @Override
    public ClientBulkWriteResult bulkWrite(ClientSession session,
            List<? extends ClientNamespacedWriteModel> models) throws ClientBulkWriteException {
        return bulkWrite(session, models, null);
    }

    /** Writes to any collections in one command (MongoDB 8); see {@link ClientBulkWrites}. */
    @Override
    public ClientBulkWriteResult bulkWrite(ClientSession session,
            List<? extends ClientNamespacedWriteModel> models, ClientBulkWriteOptions options)
            throws ClientBulkWriteException {
        try (Deadline.Scope _ = Deadline.enter(timeoutMillis)) {
            LogicalSession s = session(session);
            return ClientBulkWrites.run(topology, s, registry, writeConcern, models, options);
        }
    }

    @Override
    public void close() {
        topology.close();
    }

    /** The servers as the monitor last saw them. */
    @Override
    public ClusterDescription getClusterDescription() {
        return topology.description();
    }

    /**
     * Accepted and not sent: a library that wraps the client announces itself
     * this way, and the server takes client metadata only in a connection's
     * first {@code hello}. seclume's connections name seclume.
     */
    @Override
    public void appendMetadata(MongoDriverInformation information) {
        // informational only; see above
    }
}
