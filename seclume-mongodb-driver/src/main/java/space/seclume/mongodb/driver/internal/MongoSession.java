package space.seclume.mongodb.driver.internal;

import java.io.EOFException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedByInterruptException;
import java.sql.SQLException;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

import org.bson.BsonArray;
import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonString;
import org.bson.BsonValue;

import com.mongodb.MongoClientException;
import com.mongodb.MongoCommandException;
import com.mongodb.MongoException;
import com.mongodb.MongoInterruptedException;
import com.mongodb.MongoSecurityException;
import com.mongodb.MongoSocketClosedException;
import com.mongodb.MongoSocketOpenException;
import com.mongodb.MongoSocketReadException;
import com.mongodb.MongoSocketReadTimeoutException;
import com.mongodb.MongoSocketWriteException;
import com.mongodb.ServerAddress;

import space.seclume.Version;
import space.seclume.internal.Transports;
import space.seclume.internal.Transport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.mongodb.MongoUrl;
import space.seclume.mongodb.internal.CommandShape;
import space.seclume.mongodb.internal.MongoHandshake;

/**
 * One connection to one MongoDB server: TCP, seclume's TLS, {@code hello},
 * SCRAM-SHA-256 in native memory, and then commands - one at a time - as
 * OP_MSG.
 *
 * <p>What the connection is told in between stays: a command the server
 * refuses ({@code ok: 0}) is a {@link MongoCommandException} and the session
 * goes on; anything that leaves the stream in an unknown place - a read
 * timeout, a reply that cannot be parsed, a reply to another request, an
 * interrupt, {@link #abort} - closes it, because the next reply read from it
 * could be the answer to the command before.
 *
 * <p>The order on a new connection is the one the handshake specification
 * gives: {@code hello} first, with the client's metadata (the server takes
 * them only in the first {@code hello} of a connection - error 186 for a
 * second), and with {@code saslSupportedMechs}, so that a user the server
 * would log in only with SCRAM-SHA-1 is refused before anything is sent.
 */
public final class MongoSession implements AutoCloseable {

    /** MongoDB 5.0; older servers are past their end of life. */
    static final int MIN_WIRE_VERSION = 13;
    private static final int DEFAULT_LOGIN_TIMEOUT_MILLIS = 10_000;
    private static final int DEFAULT_MAX_MESSAGE_SIZE = 48_000_000;
    private static final int DEFAULT_MAX_BSON_SIZE = 16 * 1024 * 1024;
    private static final int DEFAULT_MAX_BATCH = 100_000;
    private static final AtomicInteger REQUEST_IDS = new AtomicInteger();

    private final ServerAddress address;
    private final Transport transport;
    private final TlsLayer tls;
    private final ReentrantLock lock = new ReentrantLock();
    private volatile boolean closed;
    private volatile boolean aborted;
    private volatile boolean handedOver;
    private int timeoutMillis;
    private BsonDocument hello;
    private int maxMessageSize = DEFAULT_MAX_MESSAGE_SIZE;
    /** The compressor commands go with - the first of the URL's the server agreed to - or null. */
    private OpMsg.Compressor compressor;
    /** All the server agreed to: a reply may come with any of them. */
    private java.util.Set<OpMsg.Compressor> agreed = java.util.Set.of();
    private int zlibLevel = -1;

    /**
     * Never compressed, whatever was agreed (compression specification): the
     * handshake and everything that carries a credential.
     */
    private static final java.util.Set<String> NEVER_COMPRESSED = java.util.Set.of("hello",
            "ismaster", "saslstart", "saslcontinue", "getnonce", "authenticate", "createuser",
            "updateuser", "copydbsaslstart", "copydbgetnonce", "copydb");

    private MongoSession(ServerAddress address, Transport transport, TlsLayer tls) {
        this.address = address;
        this.transport = transport;
        this.tls = tls;
    }

    /** The URL it logged in with - for a login again; null for a session taken up. */
    private MongoUrl url;

    /** The server's code for "log in again": an OIDC token expired under the connection. */
    private static final int REAUTHENTICATION_REQUIRED = 391;

    /**
     * Connects, logs in and returns the session; the URL's {@code connectTimeout}
     * bounds TCP, TLS, {@code hello} and the login together.
     */
    public static MongoSession open(MongoUrl url, String host, int port) {
        return open(url, host, port, false);
    }

    /**
     * The same through a load balancer: {@code hello} says so, and the server
     * behind it has to answer with the {@code serviceId} it is known by - the
     * pool tells the services apart by it.
     */
    public static MongoSession open(MongoUrl url, String host, int port, boolean loadBalanced) {
        ServerAddress address = new ServerAddress(host, port);
        space.seclume.jfr.SeclumeEvents.ConnectionOpen connecting =
                space.seclume.jfr.Observed.beginConnect();
        boolean connected = false;
        try {
            MongoSession session = connect(url, host, port, address, loadBalanced);
            connected = true;
            return session;
        } finally {
            space.seclume.jfr.Observed.endConnect(connecting, "mongodb", address.toString(),
                    url.authSource(), connected ? "TLSv1.3" : null, connected);
        }
    }

    private static MongoSession connect(MongoUrl url, String host, int port,
            ServerAddress address, boolean loadBalanced) {
        int connectTimeout = url.connectTimeout() > 0 ? url.connectTimeout()
                : DEFAULT_LOGIN_TIMEOUT_MILLIS;
        Transport transport;
        try {
            // The transport the URL names - socket, ffm, or one that carries
            // the connection elsewhere - as the JDBC drivers take it.
            transport = Transports.open(url.transport(), host, port, connectTimeout);
        } catch (IOException e) {
            throw new MongoSocketOpenException("cannot reach " + address + ": " + e.getMessage(),
                    address, e);
        }
        TlsLayer tls = null;
        try {
            // Transports.open has set the connect timeout as the bound on the
            // login, where the transport has one; a transport that carries
            // the connection elsewhere may not.
            tls = TrustChoice.using(url.trust(), () -> {
                try {
                    // A client certificate, when the URL names one: its key stays where
                    // ClientIdentities keeps it - native memory, a token, the OS store.
                    return TlsLayers.start(TlsStack.SECLUME, transport, host, port, true,
                            url.identity());
                } catch (IOException e) {
                    throw new SQLException(e.getMessage(), "08001", e);
                }
            });
        } catch (SQLException e) {
            transport.close();
            throw new MongoSocketOpenException("TLS with " + address + " failed: "
                    + e.getMessage(), address, e);
        }
        MongoSession session = new MongoSession(address, transport, tls);
        session.url = url;
        try {
            session.hello = session.hello(url, loadBalanced);
            space.seclume.jfr.SeclumeEvents.Authentication login =
                    space.seclume.jfr.Observed.beginLogin();
            boolean loggedIn = false;
            try {
                if (url.mechanism().equals(MongoUrl.X509)) {
                    session.x509(url);
                } else if (url.mechanism().equals(MongoUrl.OIDC)) {
                    space.seclume.mongodb.internal.MongoOidc.authenticate(tls, url.secret(),
                            host, port);
                } else if (url.mechanism().equals(MongoUrl.AWS)) {
                    space.seclume.mongodb.internal.MongoAws.authenticate(tls, url.aws(), host,
                            port);
                } else if (url.mechanism().equals(MongoUrl.SCRAM_SHA_256)) {
                    MongoHandshake.authenticate(tls, url, host, port);
                } else {
                    throw new MongoSecurityException(null, "authMechanism=" + url.mechanism()
                            + " is not supported by seclume's MongoDB driver: SCRAM-SHA-256, "
                            + "MONGODB-X509, MONGODB-AWS and MONGODB-OIDC are");
                }
                loggedIn = true;
            } catch (javax.net.ssl.SSLException | IllegalArgumentException e) {
                throw new MongoSecurityException(null, e.getMessage(), e);
            } catch (IOException e) {
                throw session.broke(e, "logging in");
            } finally {
                space.seclume.jfr.Observed.endLogin(login, "mongodb", address.toString(),
                        url.mechanism(), loggedIn);
            }
            Transports.loggedIn(transport);
            session.networkTimeout(url.timeout());
            return session;
        } catch (RuntimeException e) {
            session.close();
            throw e;
        }
    }

    private BsonDocument hello(MongoUrl url, boolean loadBalanced) {
        BsonDocument client = new BsonDocument()
                .append("driver", new BsonDocument()
                        .append("name", new BsonString("seclume"))
                        .append("version", new BsonString(Version.current())))
                .append("os", new BsonDocument()
                        .append("type", new BsonString(osType()))
                        .append("name", new BsonString(System.getProperty("os.name", "")))
                        .append("architecture", new BsonString(System.getProperty("os.arch", ""))))
                .append("platform", new BsonString("Java " + Runtime.version().feature()));
        BsonDocument command = new BsonDocument("hello", new BsonInt32(1))
                .append("helloOk", org.bson.BsonBoolean.TRUE)
                .append("client", client);
        if (url.mechanism().equals(MongoUrl.SCRAM_SHA_256)) {
            command.put("saslSupportedMechs", new BsonString(url.authSource() + "."
                    + url.user()));
        }
        Compression wanted = Compression.of(url.driverConnectionString());
        if (!wanted.compressors().isEmpty()) {
            command.put("compression", new org.bson.BsonArray(wanted.compressors().stream()
                    .map(c -> (BsonValue) new BsonString(c.wireName())).toList()));
        }
        if (loadBalanced) {
            command.put("loadBalanced", org.bson.BsonBoolean.TRUE);
        }
        BsonDocument reply = command("admin", command);
        if (loadBalanced && !reply.containsKey("serviceId")) {
            // Without it every error would distrust all servers behind the
            // balancer, or none; the load balancer specification refuses it.
            throw new MongoClientException("the server at " + address + " does not support "
                    + "loadBalanced=true: its hello has no serviceId - is it a mongos behind a "
                    + "load balancer, configured for one?");
        }
        int wire = intOf(reply.get("maxWireVersion"), 0);
        if (wire < MIN_WIRE_VERSION) {
            throw new MongoClientException("the server at " + address + " speaks wire version "
                    + wire + "; seclume needs " + MIN_WIRE_VERSION + " (MongoDB 5.0) or newer");
        }
        BsonValue mechanisms = reply.get("saslSupportedMechs");
        if (mechanisms instanceof BsonArray offered
                && !offered.contains(new BsonString("SCRAM-SHA-256"))) {
            // Nothing of the password has left yet: the server would log
            // this user in only with a mechanism seclume does not use.
            throw new MongoSecurityException(null, "the server at " + address
                    + " offers user '" + url.user() + "' only " + offered.getValues().stream()
                            .map(v -> v.isString() ? v.asString().getValue() : v.toString())
                            .toList()
                    + "; seclume logs in with SCRAM-SHA-256 only");
        }
        maxMessageSize = intOf(reply.get("maxMessageSizeBytes"), DEFAULT_MAX_MESSAGE_SIZE);
        if (reply.get("compression") instanceof org.bson.BsonArray offered) {
            java.util.EnumSet<OpMsg.Compressor> both = java.util.EnumSet.noneOf(
                    OpMsg.Compressor.class);
            for (OpMsg.Compressor mine : wanted.compressors()) {
                if (offered.contains(new BsonString(mine.wireName()))) {
                    both.add(mine);
                    if (compressor == null) {
                        compressor = mine;                // the URL's order is the preference
                    }
                }
            }
            agreed = both;
            zlibLevel = wanted.level();
        }
        return reply;
    }

    /**
     * MONGODB-X509: the TLS handshake has shown the certificate and proven the
     * key; the server takes the user from the certificate's subject. Nothing
     * secret goes in the command - the proof was the handshake.
     */
    private void x509(MongoUrl url) {
        BsonDocument command = new BsonDocument("authenticate", new BsonInt32(1))
                .append("mechanism", new BsonString(MongoUrl.X509));
        if (url.user() != null && !url.user().isEmpty()) {
            command.put("user", new BsonString(url.user()));
        }
        try {
            command("$external", command);
        } catch (MongoCommandException refused) {
            throw new MongoSecurityException(null, "the server at " + address + " refused the "
                    + "client certificate for MONGODB-X509: " + refused.getErrorMessage()
                    + " - is its subject a user in $external?", refused);
        }
    }

    private static String osType() {
        String name = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (name.startsWith("windows")) {
            return "Windows";
        }
        if (name.startsWith("linux")) {
            return "Linux";
        }
        if (name.startsWith("mac")) {
            return "Darwin";
        }
        return "unknown";
    }

    private static int intOf(BsonValue value, int otherwise) {
        return value != null && value.isNumber() ? value.asNumber().intValue() : otherwise;
    }

    /** Runs a command; {@code ok: 0} is a {@link MongoCommandException}. */
    public BsonDocument command(String db, BsonDocument command) {
        return command(db, command, null, null);
    }

    /**
     * Sends a write and reads nothing: {@code moreToCome} tells the server
     * not to answer. Nothing is known afterwards about what it did - that is
     * what {@code w: 0} asks for.
     */
    public void send(String db, BsonDocument command, String sequenceId,
            List<? extends BsonDocument> sequence) {
        lock.lock();
        try {
            if (closed || aborted) {
                boolean wasAborted = aborted;
                close();
                throw new MongoSocketClosedException(wasAborted ? "the session was aborted"
                        : "the session is closed", address);
            }
            ByteBuffer request = OpMsg.encode(REQUEST_IDS.incrementAndGet(), command, db,
                    sequenceId, sequence, maxMessageSize, OpMsg.MORE_TO_COME);
            try {
                tls.write(request);
            } catch (IOException e) {
                throw broke(e, "sending a command");
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Runs a command with one document sequence, the way {@code insert},
     * {@code update} and {@code delete} send their documents.
     */
    public BsonDocument command(String db, BsonDocument command, String sequenceId,
            List<? extends BsonDocument> sequence) {
        return command(db, command, sequenceId, sequence, false);
    }

    private BsonDocument command(String db, BsonDocument command, String sequenceId,
            List<? extends BsonDocument> sequence, boolean loggedInAgain) {
        lock.lock();
        try {
            if (closed || aborted) {
                boolean wasAborted = aborted;
                close();
                throw new MongoSocketClosedException(wasAborted ? "the session was aborted"
                        : "the session is closed", address);
            }
            space.seclume.jfr.Observed.Statement observed = CommandShape.recorded(command)
                    ? space.seclume.jfr.Observed.beginQuery("mongodb") : null;
            boolean failed = true;
            BsonDocument answered = null;
            try {
                answered = exchange(db, command, sequenceId, sequence, loggedInAgain);
                failed = false;
                return answered;
            } finally {
                if (observed != null) {
                    space.seclume.jfr.Observed.endQuery(observed, "mongodb",
                            CommandShape.shape(db, command),
                            space.seclume.QueryFingerprint.Dialect.GENERIC,
                            answered == null ? 0 : CommandShape.rows(answered), failed);
                }
            }
        } finally {
            lock.unlock();
        }
    }

    /** One command and its reply, under the lock; the server's refusal thrown. */
    private BsonDocument exchange(String db, BsonDocument command, String sequenceId,
            List<? extends BsonDocument> sequence, boolean loggedInAgain) {
        int requestId = REQUEST_IDS.incrementAndGet();
        ByteBuffer request = OpMsg.encode(requestId, command, db, sequenceId, sequence,
                maxMessageSize);
        if (compressor != null && !command.isEmpty() && !NEVER_COMPRESSED.contains(
                command.getFirstKey().toLowerCase(Locale.ROOT))) {
            request = OpMsg.compress(request, compressor, zlibLevel);
        }
        try {
            tls.write(request);
        } catch (IOException e) {
            throw broke(e, "sending a command");
        }
        BsonDocument reply;
        try {
            reply = OpMsg.parse(readMessage(), requestId);
        } catch (IOException e) {
            throw broke(e, "reading a reply");
        } catch (MongoException e) {
            close();
            throw e;
        }
        if (!isOk(reply) && intOf(reply.get("code"), 0) == REAUTHENTICATION_REQUIRED
                && !loggedInAgain && url != null && url.mechanism().equals(MongoUrl.OIDC)) {
            // The token the connection logged in with expired: a fresh one
            // from its source, the login again, and the command once more.
            space.seclume.jfr.SeclumeEvents.Authentication login =
                    space.seclume.jfr.Observed.beginLogin();
            boolean loggedIn = false;
            try {
                space.seclume.mongodb.internal.MongoOidc.authenticate(tls, url.secret(),
                        address.getHost(), address.getPort());
                loggedIn = true;
            } catch (javax.net.ssl.SSLException e) {
                close();
                throw new MongoSecurityException(null, e.getMessage(), e);
            } catch (IOException e) {
                throw broke(e, "logging in again");
            } finally {
                space.seclume.jfr.Observed.endLogin(login, "mongodb", address.toString(),
                        MongoUrl.OIDC, loggedIn);
            }
            return exchange(db, command, sequenceId, sequence, true);
        }
        if (!isOk(reply)) {
            throw refused(reply, address);
        }
        return reply;
    }

    /**
     * A refused command as the API's exception, with the server's error
     * labels on it: the exception's constructor does not take them from the
     * reply, and without {@code RetryableWriteError} or
     * {@code TransientTransactionError} nothing is retried that should be.
     */
    public static MongoCommandException refused(BsonDocument reply, ServerAddress address) {
        MongoCommandException refused = new MongoCommandException(reply, address);
        BsonValue labels = reply.get("errorLabels");
        if (labels instanceof BsonArray array) {
            for (BsonValue label : array) {
                if (label.isString()) {
                    refused.addLabel(label.asString().getValue());
                }
            }
        }
        return refused;
    }

    private ByteBuffer readMessage() throws IOException {
        ByteBuffer header = ByteBuffer.allocate(OpMsg.HEADER); // seclume-allow: a reply header - lengths and ids
        readFully(header);
        int length = OpMsg.length(header);
        if (length < OpMsg.HEADER || length > maxMessageSize) {
            throw new com.mongodb.MongoInternalException("the server announced a reply of "
                    + length + " bytes; at most " + maxMessageSize + " were agreed");
        }
        ByteBuffer message = ByteBuffer.allocate(length); // seclume-allow: a command reply, decoded into a BsonDocument on the heap for the API; the login's replies are read off the heap by MongoHandshake
        message.put(header.flip());
        readFully(message);
        message.flip();
        int opCode = message.duplicate().order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt(12);
        if (opCode == OpMsg.OP_COMPRESSED) {
            if (compressor == null) {
                throw new com.mongodb.MongoInternalException("the server sent a compressed "
                        + "reply, though no compression was agreed");
            }
            return OpMsg.decompress(message, maxMessageSize, agreed);
        }
        return message;
    }

    private void readFully(ByteBuffer into) throws IOException {
        while (into.hasRemaining()) {
            if (tls.read(into) < 0) {
                throw new EOFException("the server closed the connection");
            }
        }
    }

    private static boolean isOk(BsonDocument reply) {
        BsonValue ok = reply.get("ok");
        if (ok == null) {
            return false;
        }
        if (ok.isBoolean()) {
            return ok.asBoolean().getValue();
        }
        return ok.isNumber() && ok.asNumber().doubleValue() == 1.0;
    }

    /** Closes the session and says why, in the exception the driver API knows for it. */
    private MongoException broke(IOException e, String doing) {
        boolean wasAborted = aborted;
        close();
        if (wasAborted) {
            return new MongoSocketClosedException("the session was aborted while " + doing,
                    address);
        }
        if (e instanceof SocketTimeoutException) {
            return new MongoSocketReadTimeoutException("no answer from " + address + " within "
                    + timeoutMillis + " ms while " + doing, address, e);
        }
        if (e instanceof ClosedByInterruptException || e instanceof InterruptedIOException) {
            return new MongoInterruptedException("interrupted while " + doing, e);
        }
        if (doing.startsWith("sending")) {
            return new MongoSocketWriteException("the connection to " + address
                    + " failed while " + doing + ": " + e.getMessage(), address, e);
        }
        return new MongoSocketReadException("the connection to " + address + " failed while "
                + doing + ": " + e.getMessage(), address, e);
    }

    /** The read timeout for each reply in milliseconds, 0 for none. */
    public void networkTimeout(int millis) {
        try {
            transport.networkTimeout(millis);
            timeoutMillis = millis;
        } catch (IOException e) {
            if (millis != 0) {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
            timeoutMillis = 0;            // none asked for, and the transport has none
        }
    }

    public int networkTimeout() {
        return timeoutMillis;
    }

    /**
     * Ends the session from any thread, also while a command waits for its
     * reply: that command then fails with {@link MongoSocketClosedException}.
     * The wire protocol has no cancel of its own - {@code killOp} needs a
     * second connection and the operation's id - so this is how a command is
     * given up; the server ends the operation when it notices the connection
     * is gone.
     */
    public void abort() {
        if (handedOver) {
            return;                       // the stream is someone else's now
        }
        aborted = true;
        transport.close();          // the keys go with close(), under the session's lock
    }

    /** Whether commands on this connection go compressed. */
    public boolean compressed() {
        return compressor != null;
    }

    /** The compressor commands go with on this connection, or null. */
    public OpMsg.Compressor compressor() {
        return compressor;
    }

    /** {@code compressors} (in their order) and {@code zlibCompressionLevel} from a URL. */
    record Compression(List<OpMsg.Compressor> compressors, int level) {

        boolean zlib() {
            return compressors.contains(OpMsg.Compressor.ZLIB);
        }

        static Compression of(String url) {
            int question = url.indexOf('?');
            List<OpMsg.Compressor> compressors = new java.util.ArrayList<>();
            int level = -1;
            if (question < 0) {
                return new Compression(List.of(), level);
            }
            for (String pair : url.substring(question + 1).split("&")) {
                int equals = pair.indexOf('=');
                if (equals < 0) {
                    continue;
                }
                String key = pair.substring(0, equals).toLowerCase(Locale.ROOT);
                String value = java.net.URLDecoder.decode(pair.substring(equals + 1),
                        java.nio.charset.StandardCharsets.UTF_8);
                if (key.equals("compressors")) {
                    for (String name : value.split(",")) {
                        OpMsg.Compressor named = OpMsg.Compressor.byName(name);
                        if (named != null && !compressors.contains(named)) {
                            compressors.add(named);
                        }
                    }
                } else if (key.equals("zlibcompressionlevel")) {
                    level = Integer.parseInt(value.trim());
                }
            }
            return new Compression(List.copyOf(compressors), level);
        }
    }

    /** The server's {@code hello} reply from the login. */
    public BsonDocument helloReply() {
        return hello;
    }

    public ServerAddress serverAddress() {
        return address;
    }

    public int maxWireVersion() {
        return intOf(hello.get("maxWireVersion"), 0);
    }

    public int maxBsonObjectSize() {
        return intOf(hello.get("maxBsonObjectSize"), DEFAULT_MAX_BSON_SIZE);
    }

    public int maxMessageSize() {
        return maxMessageSize;
    }

    public int maxWriteBatchSize() {
        return intOf(hello.get("maxWriteBatchSize"), DEFAULT_MAX_BATCH);
    }

    public boolean isClosed() {
        return closed;
    }

    /**
     * What a logged-in connection consists of besides the socket: the TLS
     * layer that is live on it and the server's {@code hello} from the login
     * - its limits and what it is. Nothing else lives on a MongoDB
     * connection: the login does, and stays with the socket; a logical
     * session, a transaction and a cursor are named in each command and are
     * not the connection's.
     *
     * @param stream the socket, still logged in, between two messages
     */
    public record Detached(Transport stream, TlsLayer tls, BsonDocument hello,
                           ServerAddress address) {
    }

    /**
     * Hands the logged-in connection over and finishes this session: the
     * login happens once, where the credential is, and whoever takes the
     * stream up with {@link #resume} never needs one.
     *
     * <p>Only between two commands - with a reply half read nobody else could
     * take over - and only on seclume's own TLS, whose state can leave the
     * layer; afterwards this session reports itself closed and the transport
     * is the caller's.
     */
    public Detached detach() {
        if (!lock.tryLock()) {
            throw inFlight("handed over");
        }
        try {
            Detached detached = describe();
            handedOver = true;
            closed = true;
            return detached;
        } finally {
            lock.unlock();
        }
    }

    /**
     * What {@link #detach} hands out, without handing anything out: the
     * session goes on, and the stream and the layer are the live ones - to be
     * described, never used. Exact until the next command.
     */
    public Detached snapshot() {
        if (!lock.tryLock()) {
            throw inFlight("described");
        }
        try {
            return describe();
        } finally {
            lock.unlock();
        }
    }

    private static IllegalStateException inFlight(String what) {
        return new IllegalStateException("this session has a command in flight - it can only "
                + "be " + what + " between two commands");
    }

    /** Under the lock: no command can start in between. */
    private Detached describe() {
        if (closed || aborted) {
            throw new IllegalStateException("this session is closed");
        }
        if (!tls.movable()) {
            throw new IllegalStateException("this session's TLS state cannot leave its layer");
        }
        return new Detached(transport, tls, hello, address);
    }

    /** The same as {@link #resume(Detached)}, with the URL its login came from - for logging in again. */
    static MongoSession resume(Detached detached, MongoUrl url) {
        MongoSession session = resume(detached);
        session.url = url;
        return session;
    }

    /**
     * Takes a logged-in connection up: what {@link #detach} handed out. The
     * server is told nothing and notices nothing.
     */
    public static MongoSession resume(Detached detached) {
        MongoSession session = new MongoSession(detached.address(), detached.stream(),
                detached.tls());
        session.hello = detached.hello();
        session.maxMessageSize = intOf(detached.hello().get("maxMessageSizeBytes"),
                DEFAULT_MAX_MESSAGE_SIZE);
        return session;
    }

    /**
     * Closes the session and wipes its TLS keys. A command in flight on
     * another thread is cut off first and its thread lets go of the session:
     * the keys are not wiped under a read that is still using them.
     */
    @Override
    public void close() {
        if (!lock.tryLock()) {
            transport.close();
            lock.lock();
        }
        try {
            if (closed) {
                return;
            }
            closed = true;
            try {
                tls.close();
            } catch (RuntimeException ignored) {
                // the transport goes regardless
            } finally {
                transport.close();
            }
        } finally {
            lock.unlock();
        }
    }
}
