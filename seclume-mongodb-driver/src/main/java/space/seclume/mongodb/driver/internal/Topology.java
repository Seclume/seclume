package space.seclume.mongodb.driver.internal;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import org.bson.BsonArray;
import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonInt64;
import org.bson.BsonString;
import org.bson.BsonTimestamp;
import org.bson.BsonValue;

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientException;
import com.mongodb.MongoCommandException;
import com.mongodb.MongoException;
import com.mongodb.MongoSocketException;
import com.mongodb.MongoTimeoutException;
import com.mongodb.ReadPreference;
import com.mongodb.ServerAddress;
import com.mongodb.Tag;
import com.mongodb.TagSet;
import com.mongodb.WriteConcern;
import com.mongodb.connection.ClusterConnectionMode;
import com.mongodb.connection.ClusterDescription;
import com.mongodb.connection.ClusterSettings;
import com.mongodb.connection.ClusterType;
import com.mongodb.connection.ServerConnectionState;
import com.mongodb.connection.ServerDescription;
import com.mongodb.connection.ServerSettings;
import com.mongodb.connection.ServerType;

import space.seclume.mongodb.MongoUrl;

/**
 * The servers a client talks to, what each of them is, and on which one a
 * command runs.
 *
 * <p>A monitor thread asks every known server {@code hello} every
 * {@code heartbeatFrequencyMS}, and at once when a command found a server not
 * to be what it was thought to be. A replica set is followed as the server
 * discovery and monitoring specification describes it (source/server-discovery-
 * and-monitoring): the primary's member list is the truth, a primary with an
 * older {@code (electionId, setVersion)} than one seen before is stale, a
 * server of another set is dropped. Which server serves a read is the read
 * preference's choice ({@link ReadPreference#choose}) within the latency
 * window, as server selection specifies.
 *
 * <p>Every command goes through {@link #read}, {@link #write}, {@link #command}
 * or {@link #on}: they add the session, the cluster time and the transaction
 * fields, and retry once where the retryable reads and writes specifications
 * allow it - a write keeps its {@code txnNumber}, so the server applies it at
 * most once.
 */
public final class Topology implements AutoCloseable {

    private static final int DEFAULT_MAX_POOL = 100;
    private static final long DEFAULT_MAX_WAIT_MILLIS = 120_000;
    private static final long DEFAULT_SELECTION_MILLIS = 30_000;
    private static final long DEFAULT_HEARTBEAT_MILLIS = 10_000;
    private static final long MIN_HEARTBEAT_MILLIS = 500;
    private static final long DEFAULT_LOCAL_THRESHOLD_MILLIS = 15;

    /** Not primary any more, or not yet: the topology is looked at again, and a retry may help. */
    private static final Set<Integer> NOT_PRIMARY = Set.of(10107, 13435, 10058);
    private static final Set<Integer> RECOVERING = Set.of(11600, 11602, 13436, 189, 91);
    private static final Set<Integer> SHUTTING_DOWN = Set.of(11600, 91);
    /** The retryable reads specification's codes; writes go by the server's label. */
    private static final Set<Integer> RETRYABLE_READ = Set.of(11600, 11602, 10107, 13435,
            13436, 189, 91, 7, 6, 89, 9001, 134, 262);
    /**
     * The retryable writes specification's label. Not
     * {@code MongoException.RETRYABLE_ERROR_LABEL}: that is another label
     * ("RetryableError"), and checking for it retried no write at all.
     */
    static final String RETRYABLE_WRITE_ERROR = "RetryableWriteError";
    private static final int MAX_TIME_EXPIRED = 50;

    private enum Kind { UNKNOWN, SINGLE, REPLICA_SET, SHARDED }

    private final MongoUrl url;
    private final ConnectionString options;
    private final int maxPool;
    private final long maxWaitMillis;
    private final long maxIdleMillis;
    private final long maxLifeMillis;
    private final long selectionMillis;
    private final long heartbeatMillis;
    private final long localThresholdMillis;
    private final boolean retryWrites;
    private final boolean retryReads;
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition changed = lock.newCondition();
    private final Condition checkNow = lock.newCondition();
    private final Map<ServerAddress, Server> servers = new LinkedHashMap<>();
    private final ArrayDeque<LogicalSession> sessionPool = new ArrayDeque<>();
    private final Thread monitor;
    private static final long RESCAN_NANOS = TimeUnit.SECONDS.toNanos(60);
    private Kind kind;
    private String setName;
    private String srv;
    private Srv.Resolver resolver;
    private long nextScan;
    private Integer maxSetVersion;
    private org.bson.types.ObjectId maxElectionId;
    private BsonDocument clusterTime;
    private boolean checkRequested;
    private volatile boolean closed;

    /** A server as last seen; {@code hello} is null while it is unknown. */
    private static final class Server {
        final ServerPool pool;
        ServerDescription description;
        BsonDocument hello;
        MongoSession monitorConnection;
        long averageRttNanos = -1;
        /** The newest {@code topologyVersion} the server told, by a reply or an error. */
        BsonDocument topologyVersion;

        Server(ServerPool pool) {
            this.pool = pool;
            this.description = unknown(pool.address(), null);
        }
    }

    private Topology(MongoUrl url, ConnectionString options) {
        this.url = url;
        this.options = options;
        Integer max = options.getMaxConnectionPoolSize();
        this.maxPool = max == null || max == 0 ? DEFAULT_MAX_POOL : max;
        Integer wait = options.getMaxWaitTime();
        this.maxWaitMillis = wait == null ? DEFAULT_MAX_WAIT_MILLIS : wait;
        Integer idleTime = options.getMaxConnectionIdleTime();
        this.maxIdleMillis = idleTime == null ? 0 : idleTime;
        Integer lifeTime = options.getMaxConnectionLifeTime();
        this.maxLifeMillis = lifeTime == null ? 0 : lifeTime;
        Integer selection = options.getServerSelectionTimeout();
        this.selectionMillis = selection == null ? DEFAULT_SELECTION_MILLIS : selection;
        Integer heartbeat = options.getHeartbeatFrequency();
        this.heartbeatMillis = heartbeat == null ? DEFAULT_HEARTBEAT_MILLIS
                : Math.max(heartbeat, MIN_HEARTBEAT_MILLIS);
        Integer threshold = options.getLocalThreshold();
        this.localThresholdMillis = threshold == null ? DEFAULT_LOCAL_THRESHOLD_MILLIS
                : threshold;
        this.retryWrites = options.getRetryWritesValue() == null || options.getRetryWritesValue();
        this.retryReads = options.getRetryReads() == null || options.getRetryReads();
        this.setName = options.getRequiredReplicaSetName();
        boolean direct = Boolean.TRUE.equals(options.isDirectConnection())
                || (options.getHosts().size() == 1 && setName == null
                        && options.isDirectConnection() == null);
        this.kind = direct ? Kind.SINGLE : setName != null ? Kind.REPLICA_SET : Kind.UNKNOWN;
        for (String host : options.getHosts()) {
            ServerAddress address = new ServerAddress(host);
            servers.put(address, new Server(pool(address)));
        }
        this.monitor = Thread.ofPlatform().daemon().name("seclume-mongodb-monitor")
                .unstarted(this::monitor);
    }

    private ServerPool pool(ServerAddress address) {
        return new ServerPool(url, address, maxPool, maxWaitMillis, maxIdleMillis,
                maxLifeMillis);
    }

    /** The connections to a server the topology knows, or {@code null}. */
    public ServerPool poolOf(ServerAddress address) {
        lock.lock();
        try {
            Server server = servers.get(address);
            return server == null ? null : server.pool;
        } finally {
            lock.unlock();
        }
    }

    /** No connection is opened here: the monitor starts, and commands wait for what it finds. */
    public static Topology of(MongoUrl url) {
        return of(url, Srv.dns());
    }

    /** The same, with the DNS lookups of a {@code mongodb+srv://} URL done by {@code resolver}. */
    public static Topology of(MongoUrl url, Srv.Resolver resolver) {
        String given = url.driverConnectionString();
        ConnectionString options = new ConnectionString(Srv.expand(given, resolver));
        for (com.mongodb.MongoCompressor compressor : options.getCompressorList()) {
            if (!compressor.getName().equalsIgnoreCase("zlib")) {
                throw new MongoClientException("compressor '" + compressor.getName()
                        + "' is not supported by seclume's MongoDB driver - only zlib, which "
                        + "needs no native library");
            }
        }
        if (Boolean.TRUE.equals(options.isLoadBalanced())) {
            throw new MongoClientException("loadBalanced is not supported by seclume's "
                    + "MongoDB driver yet");
        }
        Topology topology = new Topology(url, options);
        if (given.startsWith("mongodb+srv://")) {
            topology.srv = given;
            topology.resolver = resolver;
            topology.nextScan = System.nanoTime() + RESCAN_NANOS;
        }
        topology.monitor.start();
        return topology;
    }

    /** The URL's options, a {@code mongodb+srv://} URL's after its DNS lookups. */
    public ConnectionString options() {
        return options;
    }

    /**
     * A sharded cluster behind {@code mongodb+srv://} may gain or lose mongos:
     * its SRV records are asked again every minute and the routers follow
     * them (the polling SRV records for mongos discovery specification). A
     * replica set is followed by its own member lists instead.
     */
    private void rescan() {
        if (srv == null || System.nanoTime() < nextScan
                || (kind != Kind.SHARDED && kind != Kind.UNKNOWN)) {
            return;
        }
        nextScan = System.nanoTime() + RESCAN_NANOS;
        List<String> seeds;
        try {
            Srv.Name name = Srv.Name.of(srv);
            seeds = Srv.seeds(name.host(), name.service(), resolver);
        } catch (RuntimeException failed) {
            return;                      // DNS down or empty: keep what is known, as specified
        }
        Set<ServerAddress> wanted = new HashSet<>();
        for (String seed : seeds) {
            wanted.add(new ServerAddress(seed));
        }
        lock.lock();
        try {
            for (ServerAddress address : wanted) {
                servers.computeIfAbsent(address, a -> new Server(pool(a)));
            }
            for (Server server : new ArrayList<>(servers.values())) {
                if (!wanted.contains(server.pool.address())) {
                    remove(server);
                }
            }
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    // ---- monitoring ---------------------------------------------------------

    private void monitor() {
        while (!closed) {
            rescan();
            List<Server> now;
            lock.lock();
            try {
                now = new ArrayList<>(servers.values());
            } finally {
                lock.unlock();
            }
            for (Server server : now) {
                if (closed) {
                    return;
                }
                check(server);
            }
            lock.lock();
            try {
                if (!checkRequested && !closed
                        && !checkNow.await(heartbeatMillis, TimeUnit.MILLISECONDS)) {
                    // the heartbeat interval passed without a request: the next round anyway
                }
                checkRequested = false;
            } catch (InterruptedException e) {
                return;
            } finally {
                lock.unlock();
            }
            if (!closed) {
                // At most one round every half second, however often one is asked for.
                try {
                    Thread.sleep(MIN_HEARTBEAT_MILLIS);
                } catch (InterruptedException e) {
                    return;
                }
            }
        }
    }

    private void check(Server server) {
        BsonDocument hello;
        long rtt;
        try {
            if (server.monitorConnection == null || server.monitorConnection.isClosed()) {
                long start = System.nanoTime();
                server.monitorConnection = server.pool.openOwn();
                rtt = System.nanoTime() - start;
                hello = server.monitorConnection.helloReply();
            } else {
                long start = System.nanoTime();
                hello = server.monitorConnection.command("admin",
                        new BsonDocument("hello", new BsonInt32(1)));
                rtt = System.nanoTime() - start;
            }
        } catch (RuntimeException e) {
            if (server.monitorConnection != null) {
                server.monitorConnection.close();
                server.monitorConnection = null;
            }
            lock.lock();
            try {
                if (servers.get(server.pool.address()) == server) {
                    server.description = unknown(server.pool.address(), e);
                    server.hello = null;
                    server.averageRttNanos = -1;
                    server.pool.clear();
                    changed.signalAll();
                }
            } finally {
                lock.unlock();
            }
            return;
        }
        lock.lock();
        try {
            if (servers.get(server.pool.address()) != server) {
                return;                                    // removed while it was asked
            }
            if (older(hello.getDocument("topologyVersion", null), server.topologyVersion)) {
                // Asked before an error told something newer - a primary that
                // has stepped down, say: what it answered then is over.
                return;
            }
            server.topologyVersion = hello.getDocument("topologyVersion", null);
            server.averageRttNanos = server.averageRttNanos < 0 ? rtt
                    : (long) (0.2 * rtt + 0.8 * server.averageRttNanos);
            server.hello = hello;
            server.description = describe(server.pool.address(), hello,
                    server.averageRttNanos);
            apply(server);
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /** What a {@code hello} means for the topology, under the lock. */
    private void apply(Server server) {
        ServerDescription description = server.description;
        ServerType type = description.getType();
        if (kind == Kind.SINGLE) {
            return;
        }
        if (kind == Kind.UNKNOWN) {
            if (type == ServerType.SHARD_ROUTER) {
                kind = Kind.SHARDED;
            } else if (description.getSetName() != null) {
                kind = Kind.REPLICA_SET;
                setName = description.getSetName();
            } else if (type == ServerType.STANDALONE) {
                remove(server);                     // a standalone among several seeds
                return;
            }
        }
        if (kind == Kind.SHARDED) {
            if (type != ServerType.SHARD_ROUTER) {
                remove(server);
            }
            return;
        }
        // A replica set.
        if (type == ServerType.STANDALONE || type == ServerType.SHARD_ROUTER
                || (description.getSetName() != null && !description.getSetName().equals(setName))) {
            remove(server);
            return;
        }
        if (type == ServerType.REPLICA_SET_PRIMARY) {
            if (stale(description)) {
                server.description = unknown(server.pool.address(), null);
                server.hello = null;
                return;
            }
            for (Server other : servers.values()) {
                if (other != server
                        && other.description.getType() == ServerType.REPLICA_SET_PRIMARY) {
                    other.description = unknown(other.pool.address(), null);
                    other.hello = null;
                }
            }
            Set<ServerAddress> members = members(description);
            for (ServerAddress member : members) {
                servers.computeIfAbsent(member, address -> new Server(pool(address)));
            }
            for (Server other : new ArrayList<>(servers.values())) {
                if (!members.contains(other.pool.address())) {
                    remove(other);
                }
            }
        } else if (type == ServerType.REPLICA_SET_SECONDARY || type == ServerType.REPLICA_SET_ARBITER
                || type == ServerType.REPLICA_SET_OTHER) {
            if (primary() == null) {
                for (ServerAddress member : members(description)) {
                    servers.computeIfAbsent(member, address -> new Server(pool(address)));
                }
            }
        }
    }

    /** A primary elected before one already seen; its claim is out of date. */
    private boolean stale(ServerDescription primary) {
        Integer setVersion = primary.getSetVersion();
        org.bson.types.ObjectId electionId = primary.getElectionId();
        if (electionId != null && maxElectionId != null) {
            int byElection = electionId.compareTo(maxElectionId);
            if (byElection < 0 || (byElection == 0 && setVersion != null && maxSetVersion != null
                    && setVersion < maxSetVersion)) {
                return true;
            }
        }
        if (electionId != null && (maxElectionId == null || electionId.compareTo(maxElectionId) >= 0)) {
            maxElectionId = electionId;
            maxSetVersion = setVersion;
        }
        return false;
    }

    private static Set<ServerAddress> members(ServerDescription description) {
        Set<ServerAddress> members = new HashSet<>();
        for (String host : description.getHosts()) {
            members.add(new ServerAddress(host));
        }
        for (String host : description.getPassives()) {
            members.add(new ServerAddress(host));
        }
        for (String host : description.getArbiters()) {
            members.add(new ServerAddress(host));
        }
        return members;
    }

    private void remove(Server server) {
        servers.remove(server.pool.address());
        server.pool.close();
        if (server.monitorConnection != null) {
            server.monitorConnection.close();
        }
    }

    private Server primary() {
        for (Server server : servers.values()) {
            if (server.description.getType() == ServerType.REPLICA_SET_PRIMARY) {
                return server;
            }
        }
        return null;
    }

    private void requestCheck() {
        lock.lock();
        try {
            checkRequested = true;
            checkNow.signalAll();
        } finally {
            lock.unlock();
        }
    }

    static ServerDescription unknown(ServerAddress address, Throwable error) {
        return ServerDescription.builder().address(address)
                .state(ServerConnectionState.CONNECTING).type(ServerType.UNKNOWN)
                .exception(error).build();
    }

    static ServerDescription describe(ServerAddress address, BsonDocument hello, long rttNanos) {
        ServerType type;
        if ("isdbgrid".equals(hello.getString("msg", new BsonString("")).getValue())) {
            type = ServerType.SHARD_ROUTER;
        } else if (hello.containsKey("setName")) {
            if (hello.getBoolean("hidden", org.bson.BsonBoolean.FALSE).getValue()) {
                type = ServerType.REPLICA_SET_OTHER;
            } else if (hello.getBoolean("isWritablePrimary", org.bson.BsonBoolean.FALSE)
                    .getValue()) {
                type = ServerType.REPLICA_SET_PRIMARY;
            } else if (hello.getBoolean("secondary", org.bson.BsonBoolean.FALSE).getValue()) {
                type = ServerType.REPLICA_SET_SECONDARY;
            } else if (hello.getBoolean("arbiterOnly", org.bson.BsonBoolean.FALSE).getValue()) {
                type = ServerType.REPLICA_SET_ARBITER;
            } else {
                type = ServerType.REPLICA_SET_OTHER;
            }
        } else if (hello.getBoolean("isreplicaset", org.bson.BsonBoolean.FALSE).getValue()) {
            type = ServerType.REPLICA_SET_GHOST;
        } else {
            type = ServerType.STANDALONE;
        }
        ServerDescription.Builder builder = ServerDescription.builder().address(address)
                .state(ServerConnectionState.CONNECTED).ok(true).type(type)
                .roundTripTime(rttNanos, TimeUnit.NANOSECONDS)
                .minWireVersion(hello.getNumber("minWireVersion", new BsonInt32(0)).intValue())
                .maxWireVersion(hello.getNumber("maxWireVersion", new BsonInt32(0)).intValue())
                .maxDocumentSize(hello.getNumber("maxBsonObjectSize",
                        new BsonInt32(16 * 1024 * 1024)).intValue())
                .hosts(strings(hello, "hosts")).passives(strings(hello, "passives"))
                .arbiters(strings(hello, "arbiters"))
                .lastUpdateTimeNanos(System.nanoTime());
        if (hello.containsKey("setName")) {
            builder.setName(hello.getString("setName").getValue());
        }
        if (hello.containsKey("primary")) {
            builder.primary(hello.getString("primary").getValue());
        }
        if (hello.containsKey("setVersion")) {
            builder.setVersion(hello.getNumber("setVersion").intValue());
        }
        if (hello.containsKey("electionId")) {
            builder.electionId(hello.getObjectId("electionId").getValue());
        }
        if (hello.containsKey("logicalSessionTimeoutMinutes")) {
            builder.logicalSessionTimeoutMinutes(hello.getNumber("logicalSessionTimeoutMinutes")
                    .intValue());
        }
        if (hello.containsKey("tags")) {
            List<Tag> tags = new ArrayList<>();
            for (Map.Entry<String, BsonValue> tag : hello.getDocument("tags").entrySet()) {
                tags.add(new Tag(tag.getKey(), tag.getValue().asString().getValue()));
            }
            builder.tagSet(new TagSet(tags));
        }
        if (hello.containsKey("lastWrite")) {
            BsonDocument lastWrite = hello.getDocument("lastWrite");
            if (lastWrite.containsKey("lastWriteDate")) {
                builder.lastWriteDate(new Date(lastWrite.getDateTime("lastWriteDate")
                        .getValue()));
            }
        }
        return builder.build();
    }

    private static Set<String> strings(BsonDocument hello, String field) {
        Set<String> values = new HashSet<>();
        if (hello.containsKey(field)) {
            for (BsonValue value : hello.getArray(field)) {
                values.add(value.asString().getValue().toLowerCase(java.util.Locale.ROOT));
            }
        }
        return values;
    }

    // ---- selection ----------------------------------------------------------

    /** The topology as the API describes it. */
    public ClusterDescription description() {
        lock.lock();
        try {
            return describeLocked();
        } finally {
            lock.unlock();
        }
    }

    private ClusterDescription describeLocked() {
        List<ServerDescription> all = new ArrayList<>();
        for (Server server : servers.values()) {
            all.add(server.description);
        }
        ClusterType type = switch (kind) {
            case SINGLE -> all.isEmpty() || all.get(0).getType() == ServerType.UNKNOWN
                    ? ClusterType.UNKNOWN : all.get(0).getClusterType();
            case REPLICA_SET -> ClusterType.REPLICA_SET;
            case SHARDED -> ClusterType.SHARDED;
            case UNKNOWN -> ClusterType.UNKNOWN;
        };
        return new ClusterDescription(kind == Kind.SINGLE ? ClusterConnectionMode.SINGLE
                : ClusterConnectionMode.MULTIPLE, type, all,
                ClusterSettings.builder().applyConnectionString(options).build(),
                ServerSettings.builder().heartbeatFrequency(heartbeatMillis,
                        TimeUnit.MILLISECONDS).build());
    }

    /** A server for a command, waiting up to {@code serverSelectionTimeoutMS} for one. */
    ServerPool select(ReadPreference preference) {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(
                Deadline.bounded(selectionMillis));
        lock.lock();
        try {
            while (true) {
                if (closed) {
                    throw new IllegalStateException("the client is closed");
                }
                List<ServerDescription> eligible = eligible(preference);
                if (!eligible.isEmpty()) {
                    ServerDescription chosen = inWindow(eligible);
                    return servers.get(chosen.getAddress()).pool;
                }
                checkRequested = true;
                checkNow.signalAll();
                long left = deadline - System.nanoTime();
                if (left <= 0) {
                    MongoTimeoutException none = new MongoTimeoutException("no server for "
                            + preference + " within " + selectionMillis + " ms: " + summary());
                    if (Deadline.active() && Deadline.remainingMillis() == 0) {
                        throw Deadline.expired("selecting a server", none);
                    }
                    throw none;
                }
                if (changed.awaitNanos(left) <= 0) {
                    continue;                          // the deadline: the loop says so
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new com.mongodb.MongoInterruptedException("interrupted while selecting a "
                    + "server", e);
        } finally {
            lock.unlock();
        }
    }

    private List<ServerDescription> eligible(ReadPreference preference) {
        List<ServerDescription> eligible = new ArrayList<>();
        switch (kind) {
            case SINGLE -> {
                ServerDescription only = servers.values().iterator().next().description;
                if (only.isOk()) {
                    eligible.add(only);
                }
            }
            case SHARDED -> servers.values().stream().map(server -> server.description)
                    .filter(description -> description.getType() == ServerType.SHARD_ROUTER)
                    .forEach(eligible::add);
            case REPLICA_SET -> eligible.addAll(preference.choose(describeLocked()));
            case UNKNOWN -> {
                // nothing known yet
            }
        }
        return eligible;
    }

    private ServerDescription inWindow(List<ServerDescription> eligible) {
        long fastest = Long.MAX_VALUE;
        for (ServerDescription server : eligible) {
            fastest = Math.min(fastest, server.getRoundTripTimeNanos());
        }
        long limit = fastest + TimeUnit.MILLISECONDS.toNanos(localThresholdMillis);
        List<ServerDescription> window = new ArrayList<>();
        for (ServerDescription server : eligible) {
            if (server.getRoundTripTimeNanos() <= limit) {
                window.add(server);
            }
        }
        return window.get(ThreadLocalRandom.current().nextInt(window.size()));
    }

    private String summary() {
        StringBuilder all = new StringBuilder(kind.name().toLowerCase(java.util.Locale.ROOT));
        for (Server server : servers.values()) {
            all.append(", ").append(server.pool.address()).append(' ')
                    .append(server.description.getType());
            if (server.description.getException() != null) {
                all.append(" (").append(server.description.getException().getMessage())
                        .append(')');
            }
        }
        return all.toString();
    }

    /** The {@code hello} of the server writes go to: its limits. */
    public BsonDocument writableHello() {
        ServerPool pool = select(ReadPreference.primary());
        lock.lock();
        try {
            Server server = servers.get(pool.address());
            return server != null && server.hello != null ? server.hello : new BsonDocument();
        } finally {
            lock.unlock();
        }
    }

    private boolean sessionsSupported() {
        BsonDocument hello = writableHello();
        return hello.containsKey("logicalSessionTimeoutMinutes");
    }

    /** Whether writes can carry a {@code txnNumber}: not on a standalone. */
    private boolean retryableWritesSupported() {
        if (!retryWrites) {
            return false;
        }
        BsonDocument hello = writableHello();
        return hello.containsKey("logicalSessionTimeoutMinutes")
                && (hello.containsKey("setName")
                        || "isdbgrid".equals(hello.getString("msg", new BsonString("")).getValue()));
    }

    // ---- sessions -----------------------------------------------------------

    /** A server session from the pool, or a new one; see {@link LogicalSession}. */
    public LogicalSession acquire(boolean explicit, boolean causallyConsistent) {
        long timeoutNanos = TimeUnit.MINUTES.toNanos(sessionTimeoutMinutes() - 1);
        lock.lock();
        try {
            while (!sessionPool.isEmpty()) {
                LogicalSession session = sessionPool.pollFirst();
                if (System.nanoTime() - session.lastUsedNanos() < timeoutNanos) {
                    session.reuse(explicit, causallyConsistent);
                    return session;
                }
            }
        } finally {
            lock.unlock();
        }
        return new LogicalSession(explicit, causallyConsistent);
    }

    public void release(LogicalSession session) {
        if (session.dirty() || closed) {
            return;
        }
        session.used();
        lock.lock();
        try {
            sessionPool.addFirst(session);
        } finally {
            lock.unlock();
        }
    }

    private int sessionTimeoutMinutes() {
        lock.lock();
        try {
            for (Server server : servers.values()) {
                if (server.hello != null && server.hello.containsKey("logicalSessionTimeoutMinutes")) {
                    return server.hello.getNumber("logicalSessionTimeoutMinutes").intValue();
                }
            }
        } finally {
            lock.unlock();
        }
        return 30;
    }

    // ---- running commands ---------------------------------------------------

    /** A reply and the server it came from - a cursor stays with that server. */
    public record Reply(ServerPool server, BsonDocument document) {
    }

    /** A read: on the server the read preference chooses, retried once if that may help. */
    public Reply read(LogicalSession session, ReadPreference preference, String db,
            BsonDocument command) {
        boolean inTransaction = session != null && session.inTransaction();
        ReadPreference chosen = inTransaction && session.transactionOptions()
                .getReadPreference() != null ? session.transactionOptions().getReadPreference()
                : preference;
        boolean retry = retryReads && !inTransaction;
        int attempt = 0;
        while (true) {
            try {
                return once(session, chosen, db, command, null, null, true);
            } catch (MongoException failed) {
                // Once without timeoutMS; with it, as often as the time allows
                // (client-side operations timeout specification, "Retryability").
                if (!retry || !retryableRead(failed) || !again(++attempt)) {
                    throw failed;
                }
            }
        }
    }

    /** Whether a retryable operation may go once more after {@code attempts} failed ones. */
    private static boolean again(int attempts) {
        if (!Deadline.active()) {
            return attempts == 1;
        }
        return Deadline.remainingMillis() > 0;
    }

    /**
     * A write on the primary. {@code retryable} for the writes the
     * specification allows to retry (one document per statement): such a write
     * gets a {@code txnNumber} and is sent again once after a network error or
     * an error the server labels {@code RetryableWriteError}.
     */
    public Reply write(LogicalSession session, String db, BsonDocument command,
            String sequenceId, List<? extends BsonDocument> sequence, boolean retryable) {
        boolean inTransaction = session != null && session.inTransaction();
        boolean retry = retryable && !inTransaction && retryableWritesSupported();
        if (!retry) {
            return withImplicit(session, s -> once(s, ReadPreference.primary(), db, command,
                    sequenceId, sequence, false));
        }
        return withImplicit(session, s -> {
            BsonDocument numbered = command.clone();
            numbered.put("txnNumber", new BsonInt64(s.advanceTransactionNumber()));
            Reply reply;
            try {
                reply = once(s, ReadPreference.primary(), db, numbered, sequenceId, sequence,
                        false);
            } catch (MongoException first) {
                if (!retryableWrite(first)) {
                    throw first;
                }
                MongoException last = first;
                int attempt = 1;
                while (true) {
                    try {
                        return once(s, ReadPreference.primary(), db, numbered, sequenceId,
                                sequence, false);
                    } catch (MongoException again) {
                        // NoWritesPerformed: the retry did nothing, the earlier error says more.
                        last = again.hasErrorLabel("NoWritesPerformed") ? last : again;
                        if (!retryableWrite(again) || !again(++attempt)) {
                            throw last;
                        }
                    }
                }
            }
            if (concernRetryable(reply.document())) {
                return once(s, ReadPreference.primary(), db, numbered, sequenceId, sequence,
                        false);
            }
            return reply;
        });
    }

    /**
     * Commands that would change who a pooled connection is logged in as. The
     * login is seclume's - once, off the heap, as the URL's user - and a
     * borrower that logged the connection in as someone else, or out, would
     * leave that to whoever borrows it next.
     */
    private static final Set<String> LOGIN_COMMANDS = Set.of("saslstart", "saslcontinue",
            "authenticate", "logout", "getnonce");

    /**
     * A write with {@code w: 0}: sent, and nothing read. Not in an explicit
     * session - the sessions specification forbids it, since nothing would
     * say whether the session's state on the server moved - and with no
     * implicit session or retry either: there is no answer to retry on.
     */
    public void writeUnacknowledged(LogicalSession session, String db, BsonDocument command,
            String sequenceId, List<? extends BsonDocument> sequence) {
        if (session != null) {
            throw new IllegalArgumentException("an unacknowledged write (w: 0) cannot be part "
                    + "of a session");
        }
        ServerPool server = select(ReadPreference.primary());
        BsonDocument sent = command;
        BsonDocument gossip = clusterTime(null);
        if (gossip != null && kind != Kind.SINGLE) {
            sent = command.clone();
            sent.put("$clusterTime", gossip);
        }
        try {
            server.send(db, sent, sequenceId, sequence);
        } catch (MongoSocketException e) {
            failed(server, e);
            throw e;
        }
    }

    /** A command as given - {@code runCommand}, DDL: no retry. */
    public Reply command(LogicalSession session, ReadPreference preference, String db,
            BsonDocument command) {
        if (!command.isEmpty()
                && LOGIN_COMMANDS.contains(command.getFirstKey().toLowerCase(java.util.Locale.ROOT))) {
            throw new IllegalArgumentException("'" + command.getFirstKey() + "' is refused: "
                    + "the connections are logged in by seclume, as the URL's user, and a "
                    + "pooled connection is not logged in again or out");
        }
        return withImplicit(session, s -> once(s, preference, db, command, null, null, false));
    }

    /** A command for a server already chosen: {@code getMore}, {@code killCursors}. */
    public BsonDocument on(ServerPool server, LogicalSession session, String db,
            BsonDocument command) {
        return run(server, session, db, command, null, null, false);
    }

    private Reply withImplicit(LogicalSession session,
            java.util.function.Function<LogicalSession, Reply> work) {
        if (session != null || !sessionsSupported()) {
            return work.apply(session);
        }
        LogicalSession implicit = acquire(false, false);
        try {
            return work.apply(implicit);
        } finally {
            release(implicit);
        }
    }

    private Reply once(LogicalSession session, ReadPreference preference, String db,
            BsonDocument command, String sequenceId, List<? extends BsonDocument> sequence,
            boolean read) {
        ServerPool server;
        try {
            server = session != null && session.pinned() != null ? session.pinned()
                    : select(preference);
        } catch (MongoTimeoutException e) {
            if (session != null && session.inTransaction()) {
                e.addLabel(MongoException.TRANSIENT_TRANSACTION_ERROR_LABEL);
            }
            throw e;
        }
        if (session != null && session.inTransaction() && kind == Kind.SHARDED) {
            session.pin(server);
        }
        BsonDocument sent = command;
        BsonDocument readPreference = readPreferenceFor(server, preference);
        if (readPreference != null) {
            sent = command.clone();
            sent.put("$readPreference", readPreference);
        }
        if (Deadline.active()) {
            // What is left of the operation, less one round trip, for the
            // server to stop at; an operation with less than that left is
            // given up before it is sent.
            long left = Deadline.remainingMillis() - roundTripMillis(server);
            if (left <= 0) {
                throw Deadline.expired("about to send " + command.getFirstKey(), null);
            }
            // getMore and killCursors go through on() and get none: a cursor's
            // lifetime bounds the socket, not the server's work per batch.
            if (Deadline.serverLimit()) {
                if (sent == command) {
                    sent = command.clone();
                }
                sent.put("maxTimeMS", new BsonInt64(left));
            }
        }
        return new Reply(server, run(server, session, db, sent, sequenceId, sequence, read));
    }

    private long roundTripMillis(ServerPool server) {
        lock.lock();
        try {
            Server known = servers.get(server.address());
            return known == null || known.averageRttNanos < 0 ? 0
                    : TimeUnit.NANOSECONDS.toMillis(known.averageRttNanos);
        } finally {
            lock.unlock();
        }
    }

    /**
     * The {@code $readPreference} a command carries (server selection
     * specification, "Passing read preference to mongos and load balancers"
     * and OP_MSG): a secondary takes a read only with one that allows it, and
     * a server reached directly is asked with {@code primaryPreferred}, so
     * that a direct connection to a secondary can read.
     */
    private BsonDocument readPreferenceFor(ServerPool server, ReadPreference preference) {
        ServerType type;
        lock.lock();
        try {
            Server known = servers.get(server.address());
            type = known == null ? ServerType.UNKNOWN : known.description.getType();
        } finally {
            lock.unlock();
        }
        if (kind == Kind.SINGLE && type != ServerType.SHARD_ROUTER) {
            return preference.isSecondaryOk() ? preference.toDocument()
                    : ReadPreference.primaryPreferred().toDocument();
        }
        if (preference.equals(ReadPreference.primary())) {
            return null;
        }
        return preference.toDocument();
    }

    /** Whether an error's topologyVersion tells more than the one known: none, a restart, or later. */
    static boolean newer(BsonDocument error, BsonDocument known) {
        if (known == null || !error.get("processId").equals(known.get("processId"))) {
            return true;
        }
        return error.getNumber("counter").longValue() > known.getNumber("counter").longValue();
    }

    /** Whether {@code a} is an older topologyVersion of the same server process than {@code b}. */
    static boolean older(BsonDocument a, BsonDocument b) {
        if (a == null || b == null || !a.get("processId").equals(b.get("processId"))) {
            return false;
        }
        return a.getNumber("counter").longValue() < b.getNumber("counter").longValue();
    }

    private BsonDocument run(ServerPool server, LogicalSession session, String db,
            BsonDocument command, String sequenceId, List<? extends BsonDocument> sequence,
            boolean read) {
        BsonDocument decorated = command.clone();
        if (session != null) {
            session.decorate(decorated, read);
        }
        BsonDocument gossip = clusterTime(session);
        if (gossip != null && kind != Kind.SINGLE) {
            decorated.put("$clusterTime", gossip);
        }
        BsonDocument reply;
        try {
            reply = server.run(db, decorated, sequenceId, sequence);
        } catch (MongoCommandException e) {
            observe(session, e.getResponse());
            failed(server, e);
            if (session != null && session.inTransaction()) {
                session.transactionSent();
            }
            if (e.getErrorCode() == MAX_TIME_EXPIRED && Deadline.active()) {
                // The server stopped at the maxTimeMS the deadline gave it.
                throw Deadline.expired("the server ran " + command.getFirstKey(), e);
            }
            throw e;
        } catch (MongoSocketException e) {
            failed(server, e);
            if (session != null) {
                session.markDirty();
                if (session.inTransaction()) {
                    e.addLabel(MongoException.TRANSIENT_TRANSACTION_ERROR_LABEL);
                }
            }
            if (e instanceof com.mongodb.MongoSocketReadTimeoutException && Deadline.active()
                    && Deadline.remainingMillis() == 0) {
                throw Deadline.expired("waiting for " + command.getFirstKey(), e);
            }
            throw e;
        }
        observe(session, reply);
        if (session != null && session.inTransaction()) {
            session.transactionSent();
            if (reply.containsKey("recoveryToken")) {
                session.recoveryToken(reply.getDocument("recoveryToken"));
            }
        }
        return reply;
    }

    /** The cluster time and the operation time a reply tells. */
    private void observe(LogicalSession session, BsonDocument reply) {
        if (reply == null) {
            return;
        }
        if (session != null && session.isSnapshot()) {
            // find and aggregate name the point in their cursor, distinct at the top
            BsonValue at = reply.containsKey("cursor")
                    ? reply.getDocument("cursor").get("atClusterTime")
                    : reply.get("atClusterTime");
            if (at != null && at.isTimestamp()) {
                session.snapshotTime(at.asTimestamp());
            }
        }
        if (reply.containsKey("$clusterTime")) {
            BsonDocument time = reply.getDocument("$clusterTime");
            lock.lock();
            try {
                clusterTime = later(clusterTime, time);
            } finally {
                lock.unlock();
            }
            if (session != null) {
                session.advanceClusterTime(time);
            }
        }
        if (session != null && reply.containsKey("operationTime")) {
            session.advanceOperationTime(reply.getTimestamp("operationTime"));
        }
    }

    private BsonDocument clusterTime(LogicalSession session) {
        lock.lock();
        try {
            return later(clusterTime, session == null ? null : session.clusterTime());
        } finally {
            lock.unlock();
        }
    }

    static BsonDocument later(BsonDocument a, BsonDocument b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        BsonTimestamp at = a.getTimestamp("clusterTime");
        BsonTimestamp bt = b.getTimestamp("clusterTime");
        return bt.compareTo(at) > 0 ? b : a;
    }

    /**
     * What an error says about the server (the specification's error
     * handling): not primary or recovering - look again; shutting down or
     * gone - its connections are not trusted any more either.
     */
    private void failed(ServerPool server, MongoException e) {
        boolean network = e instanceof MongoSocketException;
        int code = e instanceof MongoCommandException command ? command.getErrorCode() : -1;
        if (!network && !NOT_PRIMARY.contains(code) && !RECOVERING.contains(code)) {
            return;
        }
        BsonDocument errorVersion = e instanceof MongoCommandException command
                ? command.getResponse().getDocument("topologyVersion", null) : null;
        lock.lock();
        try {
            Server known = servers.get(server.address());
            if (known != null && errorVersion != null
                    && !newer(errorVersion, known.topologyVersion)) {
                return;                // the monitor already saw this or something newer
            }
            if (known != null) {
                if (errorVersion != null) {
                    known.topologyVersion = errorVersion;
                }
                known.description = unknown(server.address(), e);
                known.hello = null;
                if (network || SHUTTING_DOWN.contains(code)) {
                    server.clear();
                }
            }
            checkRequested = true;
            checkNow.signalAll();
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    private static boolean retryableRead(MongoException e) {
        return e instanceof MongoSocketException
                || (e instanceof MongoCommandException command
                        && RETRYABLE_READ.contains(command.getErrorCode()))
                || e instanceof MongoTimeoutException;
    }

    private static boolean retryableWrite(MongoException e) {
        if (e instanceof MongoSocketException || e instanceof MongoTimeoutException) {
            e.addLabel(RETRYABLE_WRITE_ERROR);
            return true;
        }
        return e.hasErrorLabel(RETRYABLE_WRITE_ERROR);
    }

    /** A write that succeeded with a write concern error the server marks retryable. */
    private static boolean concernRetryable(BsonDocument reply) {
        if (!reply.containsKey("writeConcernError")) {
            return false;
        }
        BsonValue labels = reply.get("errorLabels");
        if (labels == null && reply.getDocument("writeConcernError").containsKey("errorLabels")) {
            labels = reply.getDocument("writeConcernError").get("errorLabels");
        }
        return labels instanceof BsonArray array
                && array.contains(new BsonString(RETRYABLE_WRITE_ERROR));
    }

    // ---- ending transactions ------------------------------------------------

    /**
     * Commits. A commit that was sent once and is sent again - a retry, or
     * {@code commitTransaction} called a second time - goes with
     * {@code w: "majority"}, as the specification requires, so that the
     * answer says the commit is durable whatever the first attempt did.
     */
    public void commit(LogicalSession session) {
        LogicalSession.Transaction state = session.transaction();
        if (state == LogicalSession.Transaction.NONE) {
            throw new IllegalStateException("there is no transaction to commit");
        }
        if (state == LogicalSession.Transaction.ABORTED) {
            throw new IllegalStateException("the transaction was aborted; it cannot be "
                    + "committed");
        }
        if (state == LogicalSession.Transaction.STARTING) {
            session.transactionEnded(LogicalSession.Transaction.COMMITTED);
            return;                                    // nothing was sent: nothing to commit
        }
        boolean again = state == LogicalSession.Transaction.COMMITTED;
        try {
            endTransaction(session, "commitTransaction", again);
        } catch (MongoException first) {
            if (!retryableWrite(first)) {
                labelCommit(first);
                throw first;
            }
            try {
                endTransaction(session, "commitTransaction", true);
            } catch (MongoException second) {
                labelCommit(second);
                throw second;
            }
        }
    }

    private static void labelCommit(MongoException e) {
        boolean unknown = e instanceof MongoSocketException || e instanceof MongoTimeoutException
                || e.hasErrorLabel(RETRYABLE_WRITE_ERROR)
                || (e instanceof MongoCommandException command
                        && (command.getErrorCode() == MAX_TIME_EXPIRED
                                || command.getErrorCode() == 64            // WriteConcernFailed
                                || command.getErrorCode() == 91));
        if (unknown) {
            e.addLabel(MongoException.UNKNOWN_TRANSACTION_COMMIT_RESULT_LABEL);
        }
    }

    /** Aborts; errors are ignored - the server aborts a transaction it no longer hears about. */
    public void abort(LogicalSession session) {
        LogicalSession.Transaction state = session.transaction();
        if (state == LogicalSession.Transaction.NONE) {
            throw new IllegalStateException("there is no transaction to abort");
        }
        if (state == LogicalSession.Transaction.COMMITTED) {
            throw new IllegalStateException("the transaction was committed; it cannot be "
                    + "aborted");
        }
        if (state == LogicalSession.Transaction.ABORTED) {
            throw new IllegalStateException("the transaction was already aborted");
        }
        if (state == LogicalSession.Transaction.STARTING) {
            session.transactionEnded(LogicalSession.Transaction.ABORTED);
            return;
        }
        try {
            endTransaction(session, "abortTransaction", false);
        } catch (MongoException first) {
            if (retryableWrite(first)) {
                try {
                    endTransaction(session, "abortTransaction", false);
                } catch (MongoException ignored) {
                    // see above
                }
            }
        } finally {
            session.transactionEnded(LogicalSession.Transaction.ABORTED);
        }
    }

    private void endTransaction(LogicalSession session, String verb, boolean majority) {
        BsonDocument command = new BsonDocument(verb, new BsonInt32(1))
                .append("lsid", session.lsid())
                .append("txnNumber", new BsonInt64(session.transactionNumber()))
                .append("autocommit", org.bson.BsonBoolean.FALSE);
        WriteConcern concern = session.transactionOptions().getWriteConcern();
        if (majority) {
            concern = (concern == null ? WriteConcern.MAJORITY : concern.withW("majority"))
                    .withWTimeout(concern != null && concern.getWTimeout(TimeUnit.MILLISECONDS) != null
                            ? concern.getWTimeout(TimeUnit.MILLISECONDS) : 10_000,
                            TimeUnit.MILLISECONDS);
        }
        if (concern != null && !concern.isServerDefault()) {
            command.put("writeConcern", concern.asDocument());
        }
        Long maxCommit = session.transactionOptions().getMaxCommitTime(TimeUnit.MILLISECONDS);
        if (verb.equals("commitTransaction") && maxCommit != null) {
            command.put("maxTimeMS", new BsonInt64(maxCommit));
        }
        if (session.recoveryToken() != null) {
            command.put("recoveryToken", session.recoveryToken());
        }
        ServerPool server = session.pinned() != null ? session.pinned()
                : select(ReadPreference.primary());
        BsonDocument gossip = clusterTime(session);
        if (gossip != null && kind != Kind.SINGLE) {
            command.put("$clusterTime", gossip);
        }
        try {
            BsonDocument reply = server.run("admin", command, null, null);
            observe(session, reply);
            if (reply.containsKey("writeConcernError")) {
                BsonDocument error = reply.getDocument("writeConcernError");
                throw MongoSession.refused(new BsonDocument("ok", new BsonInt32(0))
                        .append("code", error.get("code"))
                        .append("errmsg", error.get("errmsg", new BsonString("")))
                        .append("errorLabels", reply.getArray("errorLabels", new BsonArray())),
                        server.address());
            }
            if (verb.equals("commitTransaction")) {
                session.transactionEnded(LogicalSession.Transaction.COMMITTED);
            }
        } catch (MongoCommandException e) {
            observe(session, e.getResponse());
            failed(server, e);
            throw e;
        } catch (MongoSocketException e) {
            failed(server, e);
            session.markDirty();
            throw e;
        }
    }

    // ---- closing ------------------------------------------------------------

    /** Ends the pooled sessions on the server, then closes every connection. */
    @Override
    public void close() {
        if (closed) {
            return;
        }
        List<LogicalSession> ended;
        lock.lock();
        try {
            ended = new ArrayList<>(sessionPool);
            sessionPool.clear();
        } finally {
            lock.unlock();
        }
        if (!ended.isEmpty()) {
            try {
                BsonArray ids = new BsonArray();
                for (LogicalSession session : ended) {
                    ids.add(session.lsid());
                }
                select(ReadPreference.primaryPreferred()).run("admin",
                        new BsonDocument("endSessions", ids), null, null);
            } catch (RuntimeException ignored) {
                // the server ends them after their timeout
            }
        }
        lock.lock();
        try {
            closed = true;
            checkNow.signalAll();
            changed.signalAll();
            for (Server server : servers.values()) {
                server.pool.close();
                if (server.monitorConnection != null) {
                    server.monitorConnection.close();
                }
            }
        } finally {
            lock.unlock();
        }
        monitor.interrupt();
    }
}
