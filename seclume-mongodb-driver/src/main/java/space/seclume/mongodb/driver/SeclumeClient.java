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

import space.seclume.mongodb.driver.internal.Cluster;

/**
 * The client: settings, databases, and the cluster the connections come
 * from. {@code with...} gives a view with other settings over the same
 * connections, as the official driver's {@code MongoCluster} does.
 */
final class SeclumeClient implements MongoClient {

    private final Cluster cluster;
    private final CodecRegistry registry;
    private final ReadPreference readPreference;
    private final WriteConcern writeConcern;
    private final ReadConcern readConcern;

    SeclumeClient(Cluster cluster, CodecRegistry registry, ReadPreference readPreference,
            WriteConcern writeConcern, ReadConcern readConcern) {
        this.cluster = cluster;
        this.registry = registry;
        this.readPreference = readPreference;
        this.writeConcern = writeConcern;
        this.readConcern = readConcern;
    }

    private static void noSession(ClientSession session) {
        if (session != null) {
            throw SeclumeCollection.sessions();
        }
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
    public MongoCluster withCodecRegistry(CodecRegistry codecRegistry) {
        return new SeclumeClient(cluster, codecRegistry, readPreference, writeConcern,
                readConcern);
    }

    @Override
    public MongoCluster withReadPreference(ReadPreference preference) {
        return new SeclumeClient(cluster, registry, preference, writeConcern, readConcern);
    }

    @Override
    public MongoCluster withWriteConcern(WriteConcern concern) {
        return new SeclumeClient(cluster, registry, readPreference, concern, readConcern);
    }

    @Override
    public MongoCluster withReadConcern(ReadConcern concern) {
        return new SeclumeClient(cluster, registry, readPreference, writeConcern, concern);
    }

    @Override
    public MongoCluster withTimeout(long timeout, TimeUnit unit) {
        throw Iterables.noTimeoutMode();
    }

    @Override
    public MongoDatabase getDatabase(String name) {
        return new SeclumeDatabase(cluster, name, registry, readPreference, writeConcern,
                readConcern);
    }

    @Override
    public ClientSession startSession() {
        throw SeclumeCollection.sessions();
    }

    @Override
    public ClientSession startSession(ClientSessionOptions options) {
        throw SeclumeCollection.sessions();
    }

    @Override
    public MongoIterable<String> listDatabaseNames() {
        return listDatabaseNames(null);
    }

    @Override
    public MongoIterable<String> listDatabaseNames(ClientSession session) {
        noSession(session);
        return new Iterables.ListDatabases<>(cluster, registry.get(Document.class), registry, true)
                .map(database -> database.getString("name"));
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
        noSession(session);
        return new Iterables.ListDatabases<>(cluster, registry.get(type), registry, false);
    }

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

    private static UnsupportedOperationException clientBulkWrite() {
        return new UnsupportedOperationException("the client-level bulkWrite (MongoDB 8) is "
                + "not supported by seclume's MongoDB driver yet; MongoCollection.bulkWrite is");
    }

    @Override
    public ClientBulkWriteResult bulkWrite(List<? extends ClientNamespacedWriteModel> models)
            throws ClientBulkWriteException {
        throw clientBulkWrite();
    }

    @Override
    public ClientBulkWriteResult bulkWrite(List<? extends ClientNamespacedWriteModel> models,
            ClientBulkWriteOptions options) throws ClientBulkWriteException {
        throw clientBulkWrite();
    }

    @Override
    public ClientBulkWriteResult bulkWrite(ClientSession session,
            List<? extends ClientNamespacedWriteModel> models) throws ClientBulkWriteException {
        throw clientBulkWrite();
    }

    @Override
    public ClientBulkWriteResult bulkWrite(ClientSession session,
            List<? extends ClientNamespacedWriteModel> models, ClientBulkWriteOptions options)
            throws ClientBulkWriteException {
        throw clientBulkWrite();
    }

    @Override
    public void close() {
        cluster.close();
    }

    /** The one server, described from its {@code hello}; a connection is opened for it if needed. */
    @Override
    public ClusterDescription getClusterDescription() {
        Cluster.Limits limits = cluster.limits();
        ServerType type = switch (limits.kind()) {
            case "mongos" -> ServerType.SHARD_ROUTER;
            case "primary" -> ServerType.REPLICA_SET_PRIMARY;
            case "secondary" -> ServerType.REPLICA_SET_SECONDARY;
            default -> ServerType.STANDALONE;
        };
        ServerDescription server = ServerDescription.builder()
                .address(cluster.address())
                .state(ServerConnectionState.CONNECTED)
                .ok(true)
                .type(type)
                .setName(limits.setName())
                .minWireVersion(limits.minWireVersion())
                .maxWireVersion(limits.maxWireVersion())
                .build();
        ClusterType clusterType = switch (type) {
            case SHARD_ROUTER -> ClusterType.SHARDED;
            case REPLICA_SET_PRIMARY, REPLICA_SET_SECONDARY -> ClusterType.REPLICA_SET;
            default -> ClusterType.STANDALONE;
        };
        return new ClusterDescription(ClusterConnectionMode.SINGLE, clusterType, List.of(server));
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
