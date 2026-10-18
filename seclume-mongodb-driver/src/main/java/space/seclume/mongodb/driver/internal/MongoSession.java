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
import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.mongodb.MongoUrl;
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
    private final SocketTransport transport;
    private final TlsLayer tls;
    private final ReentrantLock lock = new ReentrantLock();
    private volatile boolean closed;
    private volatile boolean aborted;
    private int timeoutMillis;
    private BsonDocument hello;
    private int maxMessageSize = DEFAULT_MAX_MESSAGE_SIZE;

    private MongoSession(ServerAddress address, SocketTransport transport, TlsLayer tls) {
        this.address = address;
        this.transport = transport;
        this.tls = tls;
    }

    /**
     * Connects, logs in and returns the session; the URL's {@code connectTimeout}
     * bounds TCP, TLS, {@code hello} and the login together.
     */
    public static MongoSession open(MongoUrl url, String host, int port) {
        ServerAddress address = new ServerAddress(host, port);
        int connectTimeout = url.connectTimeout() > 0 ? url.connectTimeout()
                : DEFAULT_LOGIN_TIMEOUT_MILLIS;
        SocketTransport transport;
        try {
            transport = SocketTransport.connect(host, port, connectTimeout);
        } catch (IOException e) {
            throw new MongoSocketOpenException("cannot reach " + address + ": " + e.getMessage(),
                    address, e);
        }
        TlsLayer tls = null;
        try {
            transport.networkTimeout(connectTimeout);
            tls = TrustChoice.using(url.trust(), () -> {
                try {
                    return TlsLayers.start(TlsStack.SECLUME, transport, host, port, true);
                } catch (IOException e) {
                    throw new SQLException(e.getMessage(), "08001", e);
                }
            });
        } catch (IOException | SQLException e) {
            transport.close();
            throw new MongoSocketOpenException("TLS with " + address + " failed: "
                    + e.getMessage(), address, e);
        }
        MongoSession session = new MongoSession(address, transport, tls);
        try {
            session.hello = session.hello(url);
            try {
                MongoHandshake.authenticate(tls, url, host, port);
            } catch (javax.net.ssl.SSLException | IllegalArgumentException e) {
                throw new MongoSecurityException(null, e.getMessage(), e);
            } catch (IOException e) {
                throw session.broke(e, "logging in");
            }
            session.networkTimeout(url.timeout());
            return session;
        } catch (RuntimeException e) {
            session.close();
            throw e;
        }
    }

    private BsonDocument hello(MongoUrl url) {
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
                .append("client", client)
                .append("saslSupportedMechs", new BsonString(url.authSource() + "." + url.user()));
        BsonDocument reply = command("admin", command);
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
        return reply;
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
     * Runs a command with one document sequence, the way {@code insert},
     * {@code update} and {@code delete} send their documents.
     */
    public BsonDocument command(String db, BsonDocument command, String sequenceId,
            List<? extends BsonDocument> sequence) {
        lock.lock();
        try {
            if (closed || aborted) {
                boolean wasAborted = aborted;
                close();
                throw new MongoSocketClosedException(wasAborted ? "the session was aborted"
                        : "the session is closed", address);
            }
            int requestId = REQUEST_IDS.incrementAndGet();
            ByteBuffer request = OpMsg.encode(requestId, command, db, sequenceId, sequence,
                    maxMessageSize);
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
            if (!isOk(reply)) {
                throw new MongoCommandException(reply, address);
            }
            return reply;
        } finally {
            lock.unlock();
        }
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
        return message.flip();
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
                    + transport.timeoutMillis() + " ms while " + doing, address, e);
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
            throw new IllegalArgumentException(e.getMessage(), e);
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
        aborted = true;
        transport.close();          // the keys go with close(), under the session's lock
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
