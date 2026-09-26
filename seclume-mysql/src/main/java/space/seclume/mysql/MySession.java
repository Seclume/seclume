package space.seclume.mysql;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.sql.SQLException;
import java.sql.SQLNonTransientConnectionException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.RsaPublicKey;
import space.seclume.internal.WireBuffer;
import space.seclume.mysql.auth.CachingSha2Password;
import space.seclume.mysql.auth.NativePassword;
import space.seclume.mysql.auth.ServerPublicKey;
import space.seclume.mysql.wire.MyChannel;
import space.seclume.mysql.wire.MyPackets;
import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * A session with a MySQL or MariaDB server.
 *
 * <p>This is the layer below JDBC: handshake, login, commands, results. It
 * knows the protocol, but no {@code Connection}.
 *
 * <p>The password only lives for the duration of the login, inside a
 * {@link SecretScope}, and afterwards it is zeroed. The session does not hold
 * on to it - not even for a later reconnect; for that the
 * {@link SecretProvider} is asked again.
 */
public final class MySession implements AutoCloseable {

    // commands
    private static final byte COM_QUIT = 0x01;
    private static final byte COM_QUERY = 0x03;
    private static final byte COM_PING = 0x0e;
    private static final byte COM_STMT_PREPARE = 0x16;
    private static final byte COM_STMT_EXECUTE = 0x17;
    /** Asks the server to keep the rows and hand them out in blocks. */
    private static final byte CURSOR_TYPE_READ_ONLY = 0x01;
    private static final byte COM_STMT_FETCH = 0x1c;
    /** The EOF flag that says this block was the last one. */
    private static final int SERVER_STATUS_LAST_ROW_SENT = 0x0080;
    private static final byte COM_STMT_CLOSE = 0x19;
    private static final byte COM_STMT_RESET = 0x1a;
    private static final byte COM_RESET_CONNECTION = 0x1f;

    /** utf8mb4_general_ci - the character set this driver uses everywhere. */
    private static final byte CHARSET_UTF8MB4 = 45;

    /** One column of a result, as the server describes it. */
    public record Field(String schema, String table, String name, String originalName,
                        int charset, long columnLength, int type, int flags, int decimals) {

        public boolean unsigned() {
            return (flags & MyTypes.FLAG_UNSIGNED) != 0;
        }

        public boolean binary() {
            return (flags & MyTypes.FLAG_BINARY) != 0;
        }

        public boolean nullable() {
            return (flags & MyTypes.FLAG_NOT_NULL) == 0;
        }
    }

    /** The result of a {@code COM_STMT_PREPARE}. */
    public record Prepared(int statementId, int parameterCount, List<Field> fields) {
    }

    /** Connection settings. Not the password, only its source. */
    public record Settings(String host, int port, String database, String user,
                           SecretProvider secret, String applicationName,
                           int connectTimeoutMillis, boolean allowPublicKeyRetrieval,
                           HostList hosts, ResultLimit resultLimit, TlsMode tls,
                           space.seclume.internal.jdbc.TlsStack tlsStack,
                           space.seclume.tls.ClientIdentity identity,
                           boolean tinyInt1isBit) {

        /**
         * With everything but the boolean mapping, which almost nobody sets.
         *
         * <p>It defaults to <b>on</b>, which is what Connector/J does: a
         * {@code tinyint(1)} is how every ORM stores a boolean in MySQL, and a
         * driver that hands back an {@code Integer} there breaks code that
         * works against the vendor driver. See {@code MyTypes.isBooleanColumn}.
         */
        public Settings(String host, int port, String database, String user,
                        SecretProvider secret, String applicationName,
                        int connectTimeoutMillis, boolean allowPublicKeyRetrieval,
                        HostList hosts, ResultLimit resultLimit, TlsMode tls,
                        space.seclume.internal.jdbc.TlsStack tlsStack,
                        space.seclume.tls.ClientIdentity identity) {
            this(host, port, database, user, secret, applicationName, connectTimeoutMillis,
                    allowPublicKeyRetrieval, hosts, resultLimit, tls, tlsStack, identity, true);
        }

        /**
         * Without a client certificate - what almost every connection is.
         */
        public Settings(String host, int port, String database, String user,
                        SecretProvider secret, String applicationName,
                        int connectTimeoutMillis, boolean allowPublicKeyRetrieval,
                        HostList hosts, ResultLimit resultLimit, TlsMode tls,
                        space.seclume.internal.jdbc.TlsStack tlsStack) {
            this(host, port, database, user, secret, applicationName, connectTimeoutMillis,
                    allowPublicKeyRetrieval, hosts, resultLimit, tls, tlsStack, null);
        }

        /**
         * With a TLS mode but the ordinary stack.
         *
         * <p>Which implementation carries TLS is a separate decision from how
         * much TLS is asked for - see
         * {@link space.seclume.internal.jdbc.TlsStack} - and almost nobody
         * makes it, so it defaults here rather than at every call site.
         */
        public Settings(String host, int port, String database, String user,
                        SecretProvider secret, String applicationName,
                        int connectTimeoutMillis, boolean allowPublicKeyRetrieval,
                        HostList hosts, ResultLimit resultLimit, TlsMode tls) {
            this(host, port, database, user, secret, applicationName, connectTimeoutMillis,
                    allowPublicKeyRetrieval, hosts, resultLimit, tls,
                    space.seclume.internal.jdbc.TlsStack.JSSE, null);
        }

        /** Without a result limit - what a URL without the option means. */
        public Settings(String host, int port, String database, String user,
                        SecretProvider secret, String applicationName,
                        int connectTimeoutMillis, boolean allowPublicKeyRetrieval,
                        HostList hosts) {
            this(host, port, database, user, secret, applicationName, connectTimeoutMillis,
                    allowPublicKeyRetrieval, hosts, ResultLimit.NONE, TlsMode.PREFER);
        }

        /** With a result limit but the default TLS mode. */
        public Settings(String host, int port, String database, String user,
                        SecretProvider secret, String applicationName,
                        int connectTimeoutMillis, boolean allowPublicKeyRetrieval,
                        HostList hosts, ResultLimit resultLimit) {
            this(host, port, database, user, secret, applicationName, connectTimeoutMillis,
                    allowPublicKeyRetrieval, hosts, resultLimit, TlsMode.PREFER);
        }

        public Settings(String host, int port, String database, String user,
                        SecretProvider secret) {
            this(host, port, database, user, secret, "seclume", 10_000, false);
        }

        /** One server - the ordinary case, and what a URL without a comma means. */
        public Settings(String host, int port, String database, String user,
                        SecretProvider secret, String applicationName,
                        int connectTimeoutMillis, boolean allowPublicKeyRetrieval) {
            this(host, port, database, user, secret, applicationName, connectTimeoutMillis,
                    allowPublicKeyRetrieval, HostList.of(host, port));
        }

        /** The same settings pointed at another server of the list. */
        Settings at(HostList.Host server) {
            // Every component, and that is not a formality: this method has
            // already dropped a newly added one once, and because a missing
            // component becomes a default rather than an error, the feature
            // silently did nothing while every test stayed green.
            return new Settings(server.host(), server.port(), database, user, secret,
                    applicationName, connectTimeoutMillis, allowPublicKeyRetrieval, hosts,
                    resultLimit, tls, tlsStack, identity, tinyInt1isBit);
        }
    }

    /**
     * What an authenticated MySQL stream is, once it has left its session.
     *
     * <p>Beside the socket, the two facts a decoder cannot derive and would
     * otherwise have learnt while logging in: the capabilities the two sides
     * agreed on, and the connection id. The capabilities are not decoration -
     * whether a result set ends with an EOF packet or with an OK wearing an
     * EOF's header is a negotiated fact, and whoever reads the stream has to
     * know which. The connection id is what a {@code KILL QUERY} needs.
     *
     * @param stream the socket, still logged in, at a packet boundary
     */
    public record Detached(space.seclume.internal.Transport stream, int capabilities,
                           long connectionId, space.seclume.internal.TlsLayer tls) {

        /** A stream that was in the clear, and therefore carries no encryption. */
        public Detached(space.seclume.internal.Transport stream, int capabilities,
                        long connectionId) {
            this(stream, capabilities, connectionId, null);
        }
    }

    /**
     * Hands the authenticated stream over and finishes this session object.
     *
     * <p>The MySQL half of the hand-over PostgreSQL already has: the login
     * happens once, where the credential is, and whoever receives the stream
     * never needs one.
     *
     * <p>Two refusals, for the same reasons as there. Not at a quiescent
     * point, because a stream with an answer half read cannot be taken over.
     * And not while encrypted <b>on the JDK's TLS</b>, whose keys will not
     * leave the {@code SSLEngine} that holds them. On seclume's own stack the
     * encryption goes with the stream instead.
     */
    public Detached detach() throws SQLException {
        if (!channel.isIdle()) {
            throw new SQLException("this session has work in flight - a stream can only be "
                    + "handed over at a quiescent point", "25000");
        }
        if (channel.isEncrypted() && !channel.encryptionCanTravel()) {
            throw new SQLException("this session is encrypted on the JDK's TLS, whose keys "
                    + "cannot leave the SSLEngine that holds them - so the stream cannot be "
                    + "handed to another session. Open it on seclume's own TLS stack, or "
                    + "terminate TLS where the login happens", "0A000");
        }
        // A setting waiting for the next statement - the BEGIN of
        // setAutoCommit(false), an isolation, read-only - goes now. Left
        // behind, the other side would run in auto-commit while its connection
        // says it does not: every statement committed at once, and a rollback
        // that rolls back nothing. Found by handing a JDBC connection over
        // straight after setAutoCommit(false). One round trip, and only when
        // something waits.
        flushPending();
        space.seclume.internal.TlsLayer tls = channel.tlsLayer();
        Detached detached = new Detached(channel.transport(), capabilities, connectionId, tls);
        channel.release(tls != null);
        return detached;
    }

    /**
     * What {@link #detach()} hands out, <b>without handing anything out</b>:
     * the session goes on, and the stream and the encryption returned are the
     * live ones - to be described (the encryption's
     * {@link space.seclume.internal.TlsLayer#snapshot}), never used. The same
     * refusals as {@code detach}, and a setting waiting for the next
     * statement goes now, so the description says what the server has.
     *
     * <p>For a copy kept elsewhere against this process dying; taken at a
     * quiet moment, it is exact until the next statement.
     */
    public Detached snapshot() throws SQLException {
        if (!channel.isIdle()) {
            throw new SQLException("this session has work in flight - it can only be "
                    + "described at a quiescent point", "25000");
        }
        if (channel.isEncrypted() && !channel.encryptionCanTravel()) {
            throw new SQLException("this session is encrypted on the JDK's TLS, whose keys "
                    + "cannot leave the SSLEngine that holds them", "0A000");
        }
        flushPending();
        return new Detached(channel.transport(), capabilities, connectionId,
                channel.tlsLayer());
    }

    /**
     * Continues a session somebody else authenticated.
     *
     * <p>No handshake to run - the server is long past it - so what a driver
     * would have learnt there is handed in instead.
     *
     * <p>The stream has to be at a packet boundary, and only the caller can
     * know that: the first three bytes of a length look like anything else.
     */
    public static MySession resume(space.seclume.internal.Transport stream,
                                   int capabilities, long connectionId) {
        return resume(stream, capabilities, connectionId, null);
    }

    /**
     * The same, for a stream that was encrypted when it was handed over.
     *
     * <p>{@code tls} is the layer {@link #detach()} handed out: the same TLS
     * connection, still live, now under a different session. The server is
     * told nothing and notices nothing.
     *
     * @param tls the encryption to continue under, or {@code null} for a
     *            stream in the clear
     */
    public static MySession resume(space.seclume.internal.Transport stream,
                                   int capabilities, long connectionId,
                                   space.seclume.internal.TlsLayer tls) {
        return new MySession(tls == null
                ? MyChannel.over(stream)
                : MyChannel.over(stream, tls), capabilities, "resumed", connectionId, null);
    }

    /** The transport carrying this session, for whoever may take it apart. */
    public space.seclume.internal.Transport transport() {
        return channel.transport();
    }

    /** Whether the <b>driver</b> has nothing in flight - half the quiescent point. */
    public boolean isIdle() {
        return channel.isIdle();
    }

    /** Puts another transport under this session. */
    public void replaceTransport(space.seclume.internal.Transport replacement)
            throws SQLException {
        try {
            channel.replaceTransport(replacement);
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw new SQLNonTransientConnectionException(
                    "the transport could not be replaced: " + e.getMessage(), "08006", e);
        }
    }

    /** What the two sides agreed on - see {@link Detached}. */
    public int capabilities() {
        return capabilities;
    }

    /**
     * Whether a tinyint(1) is a boolean here - see
     * {@link MyTypes#isBooleanColumn}.
     *
     * <p>A connection setting rather than a session state: it changes nothing
     * on the wire and everything about what the result set answers.
     */
    public boolean tinyInt1isBit() {
        return tinyInt1isBit;
    }

    private boolean tinyInt1isBit = true;

    /** Receives the rows - without a copy, straight from the receive buffer. */
    @FunctionalInterface
    public interface RowHandler {
        void row(MyRow row) throws SQLException;
    }

    /** How many rows of a batch go out before the answers are read. */
    private static final int PIPELINE_ROWS = 256;
    /** And how many bytes, whichever comes first. */
    private static final int PIPELINE_BYTES = 64 * 1024;

    /** Whether a server-side cursor still has rows - see fetchFromCursor. */
    private boolean cursorOpen;
    /** Whether writes are being held back - see the pipeline block below. */
    private boolean pipelining;
    /** How many executions are waiting to be sent. */
    private int pipelineGroup;
    /** Whether a session setting rode along at the front of the group. */
    private boolean pipelineCarried;
    private long[] pipelineCounts = new long[0]; // seclume-allow: update counts, not a secret
    private int pipelineCount;
    private final java.util.List<String> pipelineSql = new java.util.ArrayList<>();
    private ResultLimit resultLimit = ResultLimit.NONE;
    private final MyChannel channel;
    /** A session setting that rides along with the next statement. */
    private final java.util.Map<String, String> pending = new java.util.LinkedHashMap<>();
    /** Plans to release with the next command - they need no answer. */
    private final java.util.List<Integer> pendingClose = new java.util.ArrayList<>();
    /**
     * The plans this connection has ready, by statement text.
     *
     * <p>Access order, so the oldest goes when the cache is full.
     */
    private final java.util.LinkedHashMap<String, Prepared> plans =
            new java.util.LinkedHashMap<>(16, 0.75f, true);
    /**
     * Runs a statement that answers one row of one column, and hands back that
     * value as text.
     *
     * <p>There is one caller - the host list asking a server what it is; see
     * {@code space.seclume.internal.jdbc.ServerRole}. It is deliberately not a
     * general query method: it takes no parameters, reads at most one value,
     * and is meant for a question the driver asks on its own behalf rather
     * than one an application asked for.
     *
     * @return the value, or {@code null} when the statement answered no rows
     */
    public String askOneValue(String sql) throws SQLException {
        String[] answer = new String[1];
        query(sql, row -> {
            if (answer[0] == null && row.fields().size() > 0 && !row.isNull(0)) {
                answer[0] = row.getString(0);
            }
        });
        return answer[0];
    }

    /**
     * What this server says it is, for a host list that was told to look for
     * one kind - see {@link space.seclume.internal.jdbc.TargetServer}.
     *
     * <p>One statement, run once, on a connection that is about to be kept or
     * given back. A server that refuses the question answers
     * {@code UNKNOWN} rather than failing the connect: an old version or an
     * account without the right is not a reason to refuse a server that works.
     */
    private static final HostList.Roles<MySession> ROLES = new HostList.Roles<>() {

        @Override
        public space.seclume.internal.jdbc.ServerRole of(MySession session) throws SQLException {
            try {
                return space.seclume.internal.jdbc.ServerRole.read(session.askOneValue(
                        space.seclume.internal.jdbc.ServerRole.MYSQL));
            } catch (SQLException refused) {
                return space.seclume.internal.jdbc.ServerRole.UNKNOWN;
            }
        }

        @Override
        public void giveBack(MySession session) {
            session.close();
        }
    };

    /** How many plans one connection keeps. */
    private static final int PLAN_CACHE_SIZE = 64;
    private final int capabilities;
    private final String serverVersion;
    private final long connectionId;
    private final String authenticationPlugin;
    /**
     * How this connection was made, kept for {@link #cancel()}.
     *
     * <p>Null on a session that was resumed rather than opened: whoever handed
     * the stream over knows where it came from and this object does not, so
     * cancellation on a resumed session says it cannot rather than guessing.
     */
    private Settings settings;
    private List<Field> fields = List.of();
    private long affectedRows;
    private long lastInsertId;
    private int statusFlags;
    private int warnings;

    private MySession(MyChannel channel, int capabilities, String serverVersion,
                      long connectionId, String authenticationPlugin) {
        this.channel = channel;
        this.capabilities = capabilities;
        this.serverVersion = serverVersion;
        this.connectionId = connectionId;
        this.authenticationPlugin = authenticationPlugin;
    }

    // ---- connecting and logging in ---------------------------------------

    public static MySession open(Settings settings) throws SQLException {
        // One server: a plain connect. Several: the next one when a server
        // cannot be reached - and only then, see HostList.
        // With several servers and a preference in the URL, each one is asked
        // what it is before its connection is kept - see TargetServer. With
        // one server, or none asked for, nothing is asked and this is the
        // connect it always was.
        MySession session;
        try {
            session = settings.hosts().open(server -> openOne(settings.at(server)), ROLES);
        } catch (SQLException noneFits) {
            // aurora=true and nothing known yet: the cluster endpoint leads to
            // the writer only, so a first "secondary" found none. Ask whichever
            // instance answers what the cluster looks like, and try once more.
            if (!(settings.hosts().topology()
                    instanceof space.seclume.internal.jdbc.AuroraTopology aurora)
                    || !aurora.hosts(space.seclume.internal.jdbc.TargetServer.ANY).isEmpty()) {
                throw noneFits;
            }
            MySession any = settings.hosts().looking(space.seclume.internal.jdbc.TargetServer.ANY)
                    .open(server -> openOne(settings.at(server)));
            try {
                learn(aurora, any);
            } finally {
                any.close();
            }
            if (aurora.hosts(space.seclume.internal.jdbc.TargetServer.ANY).isEmpty()) {
                throw noneFits;
            }
            session = settings.hosts().open(server -> openOne(settings.at(server)), ROLES);
        }
        if (settings.hosts().topology()
                instanceof space.seclume.internal.jdbc.AuroraTopology aurora && aurora.due()) {
            learn(aurora, session);
        }
        return session;
    }

    /** What the cluster says about itself, remembered - see AuroraTopology. */
    private static void learn(space.seclume.internal.jdbc.AuroraTopology aurora, MySession session) {
        try {
            aurora.learn(session.askOneValue(space.seclume.internal.jdbc.AuroraTopology.MYSQL));
        } catch (SQLException notAurora) {
            aurora.refused();
        }
    }

    private static MySession openOne(Settings settings) throws SQLException {
        // The expensive one: a physical connect, the TLS handshake and the
        // login. Recorded around the whole of it, because that is the number
        // a pool's warm-up time is made of. See space.seclume.jfr.
        space.seclume.jfr.SeclumeEvents.ConnectionOpen event =
                space.seclume.jfr.Observed.beginConnect();
        MySession opened = null;
        try {
            opened = connectAndLogIn(settings);
            space.seclume.internal.Transports.loggedIn(opened.transport());
            opened.tinyInt1isBit = settings.tinyInt1isBit();
            // The settings of this server, not of the list: cancellation has
            // to reach the same instance, and on a host list the one that
            // answered is not necessarily the first.
            opened.settings = settings;
            return opened;
        } finally {
            space.seclume.jfr.Observed.endConnect(event, "mysql",
                    settings.host() + ":" + settings.port(), settings.database(),
                    opened == null ? null : opened.tlsDescription(), opened != null);
        }
    }

    private static MySession connectAndLogIn(Settings settings) throws SQLException {
        MyChannel channel;
        try {
            channel = MyChannel.connect(settings.host(), settings.port(),
                    settings.connectTimeoutMillis());
            // Here and not after the login: a login that fails is exactly the
            // case where somebody wants to know what the server said, and by
            // then the session does not exist. Null asks the system property -
            // see space.seclume.Flight.
            channel.recordFlight(space.seclume.internal.FlightRecorder.from(null));
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw new SQLNonTransientConnectionException(
                    "cannot reach " + settings.host() + ":" + settings.port(), "08001", e);
        }
        try {
            return handshake(channel, settings);
        } catch (SQLException | RuntimeException e) {
            channel.close();
            throw e;
        }
    }

    private static MySession handshake(MyChannel channel, Settings settings) throws SQLException {
        try (Arena arena = Arena.ofConfined()) {
            // The scramble is needed until the end of the login: a plugin
            // switch sends a new one, the old holds until then.
            MemorySegment scramble = arena.allocate(NativePassword.SCRAMBLE_LENGTH);
            Handshake greeting = readHandshake(channel, scramble);

            int wanted = MyCapabilities.CLIENT_DEFAULTS;
            if (Boolean.TRUE.equals(LOCAL_DATA.get())) {
                wanted |= MyCapabilities.LOCAL_FILES;   // loadDataLocal=true - see loadData
            }
            int clientCapabilities = wanted & greeting.capabilities();
            if (!MyCapabilities.has(clientCapabilities, MyCapabilities.PROTOCOL_41)) {
                throw new SQLException(
                        "the server does not speak protocol 4.1 - seclume needs it "
                        + "(server version " + greeting.version() + ")", "08004");
            }
            if (!settings.database().isEmpty()) {
                clientCapabilities |= MyCapabilities.CONNECT_WITH_DB;
            }

            // TLS before the login answer, not after it: the password is in
            // that answer, so anything later would be too late.
            clientCapabilities = negotiateTls(channel, settings, clientCapabilities, greeting);

            String plugin = greeting.plugin();
            // From here on it is the login and nothing else - the greeting is
            // read and TLS is up. Timed apart because the three phases of an
            // open are slow for three different reasons; see
            // SeclumeEvents.Authentication.
            space.seclume.jfr.SeclumeEvents.Authentication login =
                    space.seclume.jfr.Observed.beginLogin();
            MySession session = null;
            // Not "session != null": the object exists before the server has
            // said OK, so a failure in finishAuthentication would otherwise be
            // recorded as a login that succeeded.
            boolean loggedIn = false;
            try {
                writeHandshakeResponse(channel, settings, clientCapabilities, plugin, scramble);

                session = new MySession(channel, clientCapabilities, greeting.version(),
                        greeting.connectionId(), plugin);
                session.finishAuthentication(settings, plugin, scramble, arena);
                session.setResultLimit(settings.resultLimit());
                loggedIn = true;
                return session;
            } finally {
                // The plugin the server named, where the login never got far
                // enough to record the one that settled it. Both are the
                // server's own word and neither is derived from what was sent.
                space.seclume.jfr.Observed.endLogin(login, "mysql",
                        settings.host() + ":" + settings.port(),
                        loggedIn ? session.authenticationMethod() : plugin, loggedIn);
            }
        } finally {
            // The send buffer was carrying the login answer.
            channel.clearSendBuffer();
        }
    }

    /**
     * Switches the connection to TLS, if it is wanted and offered.
     *
     * <p>MySQL does it with a packet of its own: the <b>first 32 bytes</b> of
     * the login answer - capabilities, packet size, character set, filler - and
     * nothing more. The server reads the SSL bit in them and starts the
     * handshake; the real login answer then goes out again in full, encrypted.
     * It is the same sequence of packets, so the sequence number keeps running
     * and is not touched here.
     *
     * @return the capabilities, with the SSL bit when TLS was switched on
     */
    private static int negotiateTls(MyChannel channel, Settings settings, int capabilities,
                                    Handshake greeting) throws SQLException {
        TlsMode mode = settings.tls();
        if (mode == TlsMode.OFF) {
            return capabilities;
        }
        if (!MyCapabilities.has(greeting.capabilities(), MyCapabilities.SSL)) {
            if (mode.demands()) {
                throw new SQLNonTransientConnectionException(
                        "the server at " + settings.host() + ":" + settings.port()
                        + " does not offer TLS, and tls=" + mode.name().toLowerCase(Locale.ROOT)
                        + " was asked for", "08001");
            }
            return capabilities;
        }
        int withSsl = capabilities | MyCapabilities.SSL;
        try {
            WireBuffer out = channel.beginPacket();
            out.putIntLe(withSsl);
            out.putIntLe(MyPackets.MAX_PAYLOAD);
            out.putByte(CHARSET_UTF8MB4);
            out.putZeroes(23);                     // filler, as the protocol wants it
            channel.end();
            channel.flush();
            channel.startTls(settings.host(), settings.port(), mode.verifies(),
                    settings.tlsStack(), settings.identity());
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw new SQLNonTransientConnectionException(
                    "TLS to " + settings.host() + ":" + settings.port() + " failed: "
                    + e.getMessage(), "08001", e);
        }
        return withSsl;
    }

    /** What the login used; set when the server finally says OK. */
    private String authenticationMethod = "unknown";

    /**
     * Which authentication plugin settled this login.
     *
     * <p>MySQL is the one of the four where this is a real question rather
     * than a constant: the server names a plugin in its greeting and may
     * switch to another one part-way through, so the answer is recorded when
     * the OK packet arrives instead of being assumed at the start.
     */
    public String authenticationMethod() {
        return authenticationMethod;
    }

    /** The certificate the server presented, or null in the clear. */
    public java.security.cert.X509Certificate serverCertificate() {
        space.seclume.internal.TlsLayer layer = channel.tlsLayer();
        try {
            return layer == null ? null : layer.peerCertificate();
        } catch (java.io.IOException e) {
            return null;
        }
    }


    /** What TLS this connection uses, or {@code null} without it. */
    public String tlsDescription() {
        return channel.tlsDescription();
    }

    /** What the greeting packet holds - the scramble sits beside it, off-heap. */
    private record Handshake(String version, long connectionId, int capabilities, String plugin) {
    }

    private static Handshake readHandshake(MyChannel channel, MemorySegment scramble)
            throws SQLException {
        try {
            int first = channel.nextPacket();
            WireBuffer in = channel.packet();
            if (first == MyPackets.ERR) {
                throw readError(in, "the server refused the connection");
            }
            int protocol = in.getByte() & 0xff;
            if (protocol != 10) {
                throw new SQLException(
                        "the server speaks handshake protocol " + protocol
                        + "; seclume implements version 10", "08004");
            }
            String version = in.readCString();
            long connectionId = in.getIntLe() & 0xffff_ffffL;

            MemorySegment part1 = in.slice(in.position(), 8);
            MemorySegment.copy(part1, 0, scramble, 0, 8);
            in.skip(8);
            in.skip(1);                       // Fueller

            int capabilities = in.getShortLe() & 0xffff;
            String plugin = "mysql_native_password";
            if (in.remaining() > 0) {
                in.skip(1);                   // Zeichensatz des Servers
                in.skip(2);                   // Statusbits
                capabilities |= (in.getShortLe() & 0xffff) << 16;
                int scrambleLength = in.getByte() & 0xff;
                in.skip(10);                  // reserviert
                // The rest of the scramble: at least 13 bytes, the last of
                // which is a terminator and does not belong to it.
                int rest = Math.max(13, scrambleLength - 8) - 1;
                MemorySegment part2 = in.slice(in.position(), Math.min(rest, 12));
                MemorySegment.copy(part2, 0, scramble, 8, Math.min(rest, 12));
                in.skip(Math.max(13, scrambleLength - 8));
                if (MyCapabilities.has(capabilities, MyCapabilities.PLUGIN_AUTH)
                        && in.remaining() > 0) {
                    plugin = in.readCString();
                }
            }
            channel.endPacket();
            return new Handshake(version, connectionId, capabilities, plugin);
        } catch (IOException e) {
            throw new SQLNonTransientConnectionException(
                    "the connection broke during the handshake", "08006", e);
        } catch (WireBuffer.Truncated e) {
            // Left alone on purpose where the blanket rule below was applied
            // everywhere else: this one says more than "the connection broke",
            // and it says it with the SQLState that fits a greeting rather
            // than a statement.
            // Anything that can answer on the port reaches this parser before
            // a single credential is exchanged, so it has to fail the way a
            // library fails. A greeting that runs out mid-field used to come
            // out as an IllegalStateException - not what a caller catches,
            // and not something it could have done anything about. Found by
            // pointing the driver at a server that sends an empty packet.
            throw new SQLNonTransientConnectionException(
                    "the server's greeting is not a MySQL handshake: " + e.getMessage(),
                    "08001", e);
        }
    }

    /**
     * Writes the login answer.
     *
     * <p>This is where the password passes through: from the
     * {@link SecretProvider} straight into native memory, from there through
     * the plugin into the send buffer, which is zeroed afterwards. No
     * {@code String}, no {@code char[]}, no {@code byte[]}.
     */
    private static void writeHandshakeResponse(MyChannel channel, Settings settings,
                                               int clientCapabilities, String plugin,
                                               MemorySegment scramble) throws SQLException {
        try {
            channel.nextPacketCarriesTheCredential();
            WireBuffer out = channel.beginPacket();
            out.putIntLe(clientCapabilities);
            out.putIntLe(MyPackets.MAX_PAYLOAD);   // groesstes Paket, das wir annehmen
            out.putByte(CHARSET_UTF8MB4);
            out.putZeroes(23);                     // Fueller, so will es das Protokoll
            out.putCString(settings.user());

            int lengthAt = out.position();
            out.putByte((byte) 0);                 // a placeholder for the length
            int written = writeAuthResponse(settings, plugin, scramble, out,
                    channel.isEncrypted());
            if (written > 250) {
                throw new SQLException(
                        "the authentication response is " + written + " bytes; seclume writes "
                        + "a one-byte length here and needs it to fit", "08004");
            }
            out.putByteAt(lengthAt, (byte) written);

            if (MyCapabilities.has(clientCapabilities, MyCapabilities.CONNECT_WITH_DB)) {
                out.putCString(settings.database());
            }
            if (MyCapabilities.has(clientCapabilities, MyCapabilities.PLUGIN_AUTH)) {
                out.putCString(plugin);
            }
            if (MyCapabilities.has(clientCapabilities, MyCapabilities.CONNECT_ATTRS)) {
                writeConnectAttributes(out, settings.applicationName());
            }
            channel.end();
            channel.flush();
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw new SQLNonTransientConnectionException(
                    "the connection broke while sending the login", "08006", e);
        }
    }

    /** Computes the answer of the respective plugin - in the buffer, not beside it. */
    private static int writeAuthResponse(Settings settings, String plugin,
                                         MemorySegment scramble, WireBuffer out,
                                         boolean encrypted)
            throws SQLException {
        int at = out.position();
        try (SecretScope password = SecretScope.fromProvider(settings.secret())) {
            // Room for a hash or, inside TLS, the secret itself - which can be
            // longer than any hash: an RDS IAM token is some 370 bytes, and a
            // fixed 256 broke every IAM login (found against RDS, 26.09.2026).
            out.putZeroes(Math.max(256, password.length() + 1));
            out.position(at);
            int written = switch (plugin) {
                case "mysql_native_password" -> NativePassword.response(
                        password.secret(), 0, password.length(), scramble, 0,
                        out.segment(), at);
                case "caching_sha2_password" -> CachingSha2Password.response(
                        password.secret(), 0, password.length(), scramble, 0,
                        out.segment(), at);
                case "sha256_password" ->
                        // Inside TLS this plugin wants the password itself;
                        // without TLS only the request for the key can stand
                        // here and the real answer follows in the exchange.
                        encrypted ? writeClearPassword(password, out, at) : 0;
                case "mysql_clear_password" -> {
                    if (!encrypted) {
                        throw new SQLException(
                                "the server asked for mysql_clear_password, which sends the "
                                + "password in the clear - seclume refuses that on an "
                                + "unencrypted connection. Use tls=require.", "28000");
                    }
                    yield writeClearPassword(password, out, at);
                }
                default -> throw new SQLException(
                        "the server asked for the authentication plugin '" + plugin
                        + "', which seclume does not implement", "08004");
            };
            out.position(at + written);
            return written;
        }
    }

    /**
     * The password itself, NUL-terminated - what every plugin falls back to
     * once the line is encrypted.
     *
     * <p>Callers have to have checked that it <b>is</b> encrypted. The bytes go
     * from the secret straight into the send buffer, which is zeroed after the
     * login like every other path here.
     */
    private static int writeClearPassword(SecretScope password, WireBuffer out, int at) {
        MemorySegment.copy(password.secret(), 0, out.segment(), at, password.length());
        out.putByteAt(at + password.length(), (byte) 0);
        return password.length() + 1;
    }

    /**
     * The second part of the login: everything the server still demands after
     * the first answer - plugin switch, full SHA-2 path, errors.
     */
    private void finishAuthentication(Settings settings, String plugin, MemorySegment scramble,
                                      Arena arena) throws SQLException {
        try {
            String currentPlugin = plugin;
            while (true) {
                int first = channel.nextPacket();
                WireBuffer in = channel.packet();
                switch (first) {
                    case MyPackets.OK -> {
                        readOk(in);
                        channel.endPacket();
                        // Whatever the exchange ended on, not what it started
                        // with: a server may switch the client to another
                        // plugin mid-login, and the one that actually settled
                        // it is the one worth reporting.
                        authenticationMethod = currentPlugin;
                        return;
                    }
                    case MyPackets.ERR -> {
                        SQLException failure = readError(in, "the server rejected the login");
                        channel.endPacket();
                        throw failure;
                    }
                    case MyPackets.AUTH_MORE_DATA -> {
                        in.skip(1);
                        currentPlugin = handleAuthMoreData(settings, currentPlugin, scramble,
                                in, arena);
                    }
                    case MyPackets.AUTH_SWITCH -> {
                        in.skip(1);
                        currentPlugin = in.readCString();
                        if (KERBEROS_PLUGIN.equals(currentPlugin)) {
                            String principal = in.readCString();
                            channel.endPacket();
                            kerberos(principal);
                            continue;
                        }
                        int available = Math.min(in.remaining(),
                                NativePassword.SCRAMBLE_LENGTH);
                        if (available > 0) {
                            MemorySegment.copy(in.slice(in.position(), available), 0,
                                    scramble, 0, available);
                        }
                        channel.endPacket();
                        sendAuthResponse(settings, currentPlugin, scramble);
                    }
                    default -> throw new SQLException(
                            "unexpected packet 0x" + Integer.toHexString(first)
                            + " during authentication", "08P01");
                }
            }
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw new SQLNonTransientConnectionException(
                    "the connection broke during authentication", "08006", e);
        }
    }

    /**
     * MariaDB's {@code auth_gssapi_client}: Kerberos, with the operating
     * system's ticket and no password anywhere. The server named its principal
     * in the switch; the tokens go back and forth as plain packets until the
     * library says the context stands, and the server's OK follows.
     */
    private static final String KERBEROS_PLUGIN = "auth_gssapi_client";

    private void kerberos(String principal) throws SQLException, IOException {
        if (!space.seclume.internal.Gssapi.available()) {
            throw new java.sql.SQLInvalidAuthorizationSpecException(
                    "the server asks for Kerberos (auth_gssapi_client), which seclume speaks "
                    + "through the system's GSSAPI library (libgssapi_krb5.so.2) on 64-bit "
                    + "Linux - it is not there", "28000");
        }
        try (space.seclume.internal.Gssapi.Context gss =
                     space.seclume.internal.Gssapi.initiatePrincipal(principal)) {
            byte[] token = gss.step(null, 0, 0);
            while (true) {
                if (token.length > 0) {
                    WireBuffer out = channel.beginPacket();
                    out.putBytes(MemorySegment.ofArray(token), 0, token.length);
                    channel.end();
                    channel.flush();
                }
                if (gss.complete()) {
                    return;
                }
                int first = channel.nextPacket();
                WireBuffer in = channel.packet();
                if (first == MyPackets.ERR) {
                    SQLException failure = readError(in, "the server rejected the login");
                    channel.endPacket();
                    throw failure;
                }
                // The server escapes a token that would look like a status
                // byte with a leading 0x01.
                long at = in.position();
                int length = channel.packetRemaining();
                if (first == MyPackets.AUTH_MORE_DATA) {
                    at++;
                    length--;
                }
                token = gss.step(in.segment(), at, length);
                channel.endPacket();
            }
        } catch (IllegalStateException e) {
            throw new java.sql.SQLInvalidAuthorizationSpecException(
                    "Kerberos login to " + principal + " failed: " + e.getMessage(), "28000", e);
        }
    }

    /**
     * {@code AuthMoreData} - with {@code caching_sha2_password} either "done"
     * or "I need the password", and the PEM block for the key request.
     */
    private String handleAuthMoreData(Settings settings, String plugin, MemorySegment scramble,
                                      WireBuffer in, Arena arena)
            throws SQLException, IOException {
        int marker = in.getByte(in.position()) & 0xff;
        if (marker == CachingSha2Password.FAST_AUTH_SUCCESS && in.remaining() == 1) {
            // The server knows the user; the OK packet follows right away.
            channel.endPacket();
            return plugin;
        }
        if (marker == CachingSha2Password.FULL_AUTH_REQUIRED && in.remaining() == 1) {
            channel.endPacket();
            if (channel.isEncrypted()) {
                // Inside TLS the password travels as it is - that is what the
                // encryption is for, and it is what every other client does
                // here. The RSA detour below exists only for the unencrypted
                // case.
                sendClearPassword(settings);
                return plugin;
            }
            if (!settings.allowPublicKeyRetrieval()) {
                throw new SQLException(
                        "the server needs the password itself (caching_sha2_password full "
                        + "authentication) but the connection is not encrypted. seclume can "
                        + "ask the server for its public key and encrypt with it, but asking "
                        + "an unauthenticated server for a key is exactly what a "
                        + "man-in-the-middle would answer - so it is off unless you set "
                        + "allowPublicKeyRetrieval=true. Use TLS instead where you can.",
                        "28000");
            }
            requestPublicKey(plugin);
            return plugin;
        }
        // Everything else is the public key in PEM format.
        int length = in.remaining();
        MemorySegment pem = in.slice(in.position(), length);
        RsaPublicKey key;
        try {
            key = ServerPublicKey.parsePem(pem, 0, length);
        } catch (IllegalArgumentException notAKey) {
            // The most sensitive refusal in this driver, and it used to leave
            // as an IllegalArgumentException out of open(). This is the point
            // where the password is about to be encrypted under a key the
            // *server* just supplied: a server that sends something which is
            // not a key is either broken or is not the server. Either way the
            // caller has to be able to catch it, and 28000 says what it is -
            // the authentication exchange, refused. Found by the login fuzz
            // corpus on 23.09.2026, and only by the full corpus: the sample
            // never produced a packet that reached this line.
            throw new java.sql.SQLInvalidAuthorizationSpecException(
                    "the server's public key cannot be used: " + notAKey.getMessage(),
                    "28000", notAKey);
        }
        channel.endPacket();
        try (key) {
            sendEncryptedPassword(settings, key, scramble, arena);
        }
        return plugin;
    }

    /** The password itself in a packet of its own - only ever inside TLS. */
    private void sendClearPassword(Settings settings) throws IOException {
        WireBuffer out = channel.beginPacket();
        int at = out.position();
        out.putZeroes(512);
        out.position(at);
        try (SecretScope password = SecretScope.fromProvider(settings.secret())) {
            out.position(at + writeClearPassword(password, out, at));
        }
        channel.end();
        channel.flush();
    }

    private void requestPublicKey(String plugin) throws IOException {
        byte request = "sha256_password".equals(plugin)
                ? 0x01 : CachingSha2Password.REQUEST_PUBLIC_KEY;
        WireBuffer out = channel.beginPacket();
        out.putByte(request);
        channel.end();
        channel.flush();
    }

    private void sendEncryptedPassword(Settings settings, RsaPublicKey key,
                                       MemorySegment scramble, Arena arena)
            throws SQLException, IOException {
        WireBuffer out = channel.beginPacket();
        int at = out.position();
        out.putZeroes(key.modulusBytes());
        try (SecretScope password = SecretScope.in(arena, 512)) {
            password.length(settings.secret().writeSecret(password.segment()));
            int written = CachingSha2Password.encryptedPassword(key, HashAlgorithm.SHA_1,
                    password.secret(), 0, password.length(), scramble, 0, out.segment(), at);
            out.position(at + written);
        }
        channel.end();
        channel.flush();
    }

    /** The answer to a plugin switch - the same computation, a new packet. */
    private void sendAuthResponse(Settings settings, String plugin, MemorySegment scramble)
            throws SQLException, IOException {
        channel.nextPacketCarriesTheCredential();
        WireBuffer out = channel.beginPacket();
        int at = out.position();
        try (SecretScope password = SecretScope.fromProvider(settings.secret())) {
            // Room for a hash or, inside TLS, the secret itself - which can be
            // longer than any hash: an RDS IAM token is some 370 bytes, and a
            // fixed 256 broke every IAM login (found against RDS, 26.09.2026).
            out.putZeroes(Math.max(256, password.length() + 1));
            out.position(at);
            int written = switch (plugin) {
                case "mysql_native_password" -> NativePassword.response(
                        password.secret(), 0, password.length(), scramble, 0, out.segment(), at);
                case "caching_sha2_password" -> CachingSha2Password.response(
                        password.secret(), 0, password.length(), scramble, 0, out.segment(), at);
                case "sha256_password", "mysql_clear_password" -> {
                    if (!channel.isEncrypted()) {
                        yield 0;     // the key exchange follows, see handleAuthMoreData
                    }
                    yield writeClearPassword(password, out, at);
                }
                default -> throw new SQLException(
                        "the server switched to the authentication plugin '" + plugin
                        + "', which seclume does not implement", "08004");
            };
            out.position(at + written);
        }
        channel.end();
        channel.flush();
    }

    private static void writeConnectAttributes(WireBuffer out, String applicationName) {
        int lengthAt = out.position();
        out.putByte((byte) 0);
        int start = out.position();
        MyPackets.writeLengthEncodedString(out, "_client_name");
        MyPackets.writeLengthEncodedString(out, "seclume");
        MyPackets.writeLengthEncodedString(out, "program_name");
        MyPackets.writeLengthEncodedString(out, applicationName);
        int length = out.position() - start;
        if (length > 250) {
            throw new IllegalStateException("the connection attributes do not fit in one byte");
        }
        out.putByteAt(lengthAt, (byte) length);
    }

    // ---- commands --------------------------------------------------------

    /** Runs a statement in the text protocol. */
    public void query(String sql, RowHandler handler) throws SQLException {
        // Anything that really needs an answer sends the block first - that is
        // the promise of the pipeline: it saves round trips nobody waited for,
        // never a value somebody asked for.
        flushPipeline();

        try {
            boolean carried = writePending();
            WireBuffer out = channel.beginCommand(COM_QUERY);
            out.putText(sql);
            channel.end();
            channel.flush();
            if (carried) {
                readCarriedSetting();
            }
            readResult(handler, false);
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
    }

    /** Short form for statements without a result. */
    public void execute(String sql) throws SQLException {
        query(sql, null);
    }

    // ---- LOAD DATA LOCAL -------------------------------------------------

    /** Set around opening a session that may answer LOCAL INFILE - see allowingLocalData. */
    private static final ThreadLocal<Boolean> LOCAL_DATA = new ThreadLocal<>();

    /**
     * Opens a session that offers LOCAL INFILE ({@code loadDataLocal=true}).
     * Off by default, because with it a server may ask the client for any
     * file - see MyCapabilities. Here it never gets one: the only data sent is
     * the stream handed to {@link #loadData}.
     */
    public static <T> T allowingLocalData(boolean on,
            space.seclume.internal.Transports.Opening<T> opening) throws SQLException {
        if (!on) {
            return opening.open();
        }
        LOCAL_DATA.set(Boolean.TRUE);
        try {
            return opening.open();
        } finally {
            LOCAL_DATA.remove();
        }
    }

    /** The stream a running loadData sends; null at any other time. */
    private java.io.InputStream localData;

    /**
     * {@code LOAD DATA LOCAL INFILE '...' INTO TABLE ...}, fed from
     * {@code data}. The file name in the statement is whatever the statement
     * says - it is not opened; the server gets {@code data}.
     *
     * @return the rows loaded
     */
    public long loadData(String sql, java.io.InputStream data) throws SQLException {
        if (!MyCapabilities.has(capabilities, MyCapabilities.LOCAL_FILES)) {
            throw new SQLException("LOAD DATA LOCAL needs loadDataLocal=true on the URL and "
                    + "local_infile=ON on the server - this session has not both", "42000");
        }
        localData = data;
        try {
            query(sql, null);
            return affectedRows;
        } finally {
            localData = null;
        }
    }

    /** How much of the stream goes into one packet. */
    private static final int LOCAL_CHUNK = 64 * 1024;

    /**
     * The answer to a LOCAL INFILE request: the stream of the running
     * loadData, or nothing. A stream that cannot be read breaks the
     * connection on purpose - an empty packet would end the file, and the
     * server would keep the rows sent so far; a broken connection makes it
     * roll the statement back.
     */
    private void sendLocalData() throws SQLException, IOException {
        java.io.InputStream data = localData;
        if (data != null) {
            byte[] chunk = new byte[LOCAL_CHUNK]; // seclume-allow: the caller's bulk data, not a secret
            java.lang.foreign.MemorySegment view = java.lang.foreign.MemorySegment.ofArray(chunk);
            while (true) {
                int read;
                try {
                    read = data.read(chunk);
                } catch (java.io.IOException failed) {
                    throw brokenConnection(new java.io.IOException("reading the data for "
                            + "LOAD DATA failed - the connection is closed so that the server "
                            + "keeps none of it: " + failed.getMessage(), failed));
                }
                if (read < 0) {
                    break;
                }
                if (read > 0) {
                    WireBuffer out = channel.beginPacket();
                    out.putBytes(view, 0, read);
                    channel.end();
                    channel.flush();
                }
            }
        }
        channel.beginPacket();                      // the empty packet: end of file
        channel.end();
        channel.flush();
    }

    /**
     * A plan for this statement - from the cache if it is already there.
     *
     * <p>Frameworks build a fresh {@code PreparedStatement} for every call and
     * throw it away afterwards; Hibernate does, Spring's {@code JdbcTemplate}
     * does. Without a cache every one of those calls pays a round trip to
     * prepare a statement the server has seen a thousand times.
     *
     * <p>MySQL Connector/J has such a cache and keeps it <b>off</b> by
     * default. Here it is on, bounded, and per connection - which is the only
     * place it can be, because a plan belongs to a session.
     */
    public Prepared prepareCached(String sql) throws SQLException {
        Prepared cached = plans.get(sql);
        // Recorded by fingerprint, like everything else: a cache report that
        // listed the statements by their text would carry every value in
        // them, which is precisely the report nobody could then share.
        space.seclume.jfr.Observed.statementCache(sql,
                space.seclume.QueryFingerprint.Dialect.MYSQL, cached != null);
        if (cached != null) {
            return cached;
        }
        Prepared fresh = prepare(sql);
        if (plans.size() >= PLAN_CACHE_SIZE) {
            // Oldest out. A cache that grows without bound is a leak with a
            // friendly name.
            String oldest = plans.keySet().iterator().next();
            Prepared dropped = plans.remove(oldest);
            if (dropped != null) {
                closeStatementLater(dropped.statementId());
            }
        }
        plans.put(sql, fresh);
        return fresh;
    }

    /**
     * Releases a plan - with the next command, not now.
     *
     * <p>{@code COM_STMT_CLOSE} has no answer at all, so nothing is lost by
     * letting it travel with whatever comes next; what is saved is the write
     * and the wake-up on the other side.
     */
    public void closeStatementLater(int statementId) {
        pendingClose.add(statementId);
    }

    /** Prepares a statement on the server. */
    public Prepared prepare(String sql) throws SQLException {
        try {
            // The settings that are waiting go first, here too: MySQL judges
            // some statements when it prepares them. An UPDATE prepared in a
            // session still read-only - because the "transaction_read_only =
            // 0" was waiting for the next execute - was refused with 1792 at
            // prepare time, the transaction after any read-only one. Found by
            // Spring Data JDBC, whose save follows its findById.
            boolean carried = writePending();
            WireBuffer out = channel.beginCommand(COM_STMT_PREPARE);
            out.putText(sql);
            channel.end();
            channel.flush();
            if (carried) {
                readCarriedSetting();
            }

            int first = channel.nextPacket();
            WireBuffer in = channel.packet();
            if (first == MyPackets.ERR) {
                SQLException failure = serverError(in, "the server rejected the statement");
                channel.endPacket();
                closeIfConnectionFailure(failure);
                throw failure;
            }
            in.skip(1);                              // 0x00
            int statementId = in.getIntLe();
            int columnCount = in.getShortLe() & 0xffff;
            int parameterCount = in.getShortLe() & 0xffff;
            channel.endPacket();

            // First the parameter descriptions, then the column ones.
            skipFieldDescriptions(parameterCount);
            List<Field> columns = readFieldDescriptions(columnCount);
            this.fields = columns;
            return new Prepared(statementId, parameterCount, columns);
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
    }

    /** Runs a prepared statement; the rows arrive in binary. */
    public void executePrepared(Prepared statement, MyParameters parameters, RowHandler handler)
            throws SQLException {
        flushPipeline();
        try {
            boolean carried = writePending();
            WireBuffer out = channel.beginCommand(COM_STMT_EXECUTE);
            out.putIntLe(statement.statementId());
            out.putByte((byte) 0);                   // no cursor
            out.putIntLe(1);                         // iterations, always 1
            parameters.write(out, statement.parameterCount());
            channel.end();
            channel.flush();
            if (carried) {
                readCarriedSetting();
            }
            readResult(handler, true);
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
    }

    /**
     * Runs a session setting with the <b>next</b> statement, not now.
     *
     * <p>{@code SET autocommit=0} on its own is a full round trip in which the
     * database does nothing, and a framework sends it twice per transaction -
     * once to open one and once to put the connection back as it found it.
     * Sent together with the statement that follows, it is free: two commands
     * in one flush, one wait.
     *
     * <p>Only settings go through here - things whose answer nobody looks
     * at - and they are collected as <b>assignments</b>, one per variable, and
     * sent as a single {@code SET a = ..., b = ...}. That is still one command
     * and one answer, which is what every caller of {@link #writePending}
     * counts on.
     *
     * <p>It used to hold one statement, and each new one replaced the last.
     * Spring prepares a transaction with {@code setReadOnly},
     * {@code setTransactionIsolation} and {@code setAutoCommit(false)}, in that
     * order - so only {@code set autocommit=0} ever reached the server, and a
     * read-only or serializable transaction ran as an ordinary one while
     * {@code isReadOnly()} and {@code getTransactionIsolation()} said
     * otherwise. Found by the Spring JDBC suite. A later assignment to the
     * same variable still replaces an earlier one, because that is what it
     * would have done on the server too.
     *
     * @param variable the session variable, {@code autocommit} or
     *                 {@code session transaction_isolation}
     * @param value    its new value, as SQL
     */
    public void runLater(String variable, String value) {
        pending.put(variable, value);
    }

    /**
     * Drops user variables not yet sent - a session context meant for the
     * borrower before a reset must not ride along with the next one's first
     * statement.
     */
    public void dropPendingVariables() {
        pending.keySet().removeIf(variable -> variable.startsWith("@"));
    }

    /** Whether a setting is waiting for a statement to ride along with. */
    public boolean hasPending() {
        return !pending.isEmpty();
    }

    /** Sends what is pending right now, for whoever cannot wait. */
    public void flushPending() throws SQLException {
        if (!pending.isEmpty()) {
            String sql = pendingStatement();
            pending.clear();
            query(sql, null);
        }
    }

    /** The waiting assignments as one {@code SET}. */
    private String pendingStatement() {
        StringBuilder sql = new StringBuilder("set ");
        pending.forEach((variable, value) -> {
            if (sql.length() > 4) {
                sql.append(", ");
            }
            sql.append(variable).append(" = ").append(value);
        });
        return sql.toString();
    }

    private boolean writePending() {
        for (int statementId : pendingClose) {
            WireBuffer out = channel.beginCommand(COM_STMT_CLOSE);
            out.putIntLe(statementId);
            channel.end();                       // COM_STMT_CLOSE gets no answer
        }
        pendingClose.clear();
        if (pending.isEmpty()) {
            return false;
        }
        WireBuffer out = channel.beginCommand(COM_QUERY);
        out.putText(pendingStatement());
        channel.end();
        pending.clear();
        return true;
    }


    /**
     * An upper bound for a single result - off unless it is configured.
     *
     * <p>See {@link ResultLimit}: a forgotten {@code where} should end in an
     * error that names the query, not in an {@code OutOfMemoryError} that
     * takes the application with it.
     */
    public void setResultLimit(ResultLimit limit) {
        this.resultLimit = limit;
    }

    public ResultLimit resultLimit() {
        return resultLimit;
    }

    /** How often this session has waited for the server. */
    public long roundTrips() {
        return channel.roundTrips();
    }


    // ---- the pipeline block ---------------------------------------------

    /**
     * From here on a write whose count nobody looks at is buffered.
     *
     * <p>See {@link space.seclume.Pipeline}. The mechanics are the
     * ones the batch already uses - several {@code COM_STMT_EXECUTE} into the
     * buffer, one flush, then the answers in order.
     *
     * <p><b>One difference to PostgreSQL, and it matters:</b> MySQL answers
     * every command of the group, even after one of them failed. So a failure
     * in the middle does <b>not</b> stop the rest - they ran. The message says
     * so, because the opposite assumption would be the expensive kind of
     * wrong.
     */
    public void beginPipeline() {
        pipelining = true;
        pipelineGroup = 0;
        pipelineCount = 0;
        pipelineCounts = new long[16]; // seclume-allow: update counts, not a secret
        pipelineSql.clear();
    }

    public boolean isPipelining() {
        return pipelining;
    }

    /**
     * Buffers one execution of a prepared statement.
     *
     * @return {@link java.sql.Statement#SUCCESS_NO_INFO} - the count is not
     *         known yet, and inventing one would be a lie
     */
    public int pipelineExecute(Prepared statement, MyParameters parameters, String sql)
            throws SQLException {
        if (pipelineGroup == 0) {
            pipelineCarried = writePending();
        }
        WireBuffer out = channel.beginCommand(COM_STMT_EXECUTE);
        out.putIntLe(statement.statementId());
        out.putByte((byte) 0);                    // no cursor
        out.putIntLe(1);                          // one repetition
        parameters.write(out, statement.parameterCount());
        channel.end();
        pipelineGroup++;
        pipelineSql.add(sql);
        // Bounded for the same reason the batch is: if both sides keep
        // writing, both buffers fill and both block.
        if (pipelineGroup >= PIPELINE_ROWS || channel.pending() >= PIPELINE_BYTES) {
            flushPipeline();
        }
        return java.sql.Statement.SUCCESS_NO_INFO;
    }

    /**
     * Sends what is buffered and reads the answers.
     *
     * <p>Called at the end of the block - and by the driver itself before
     * anything that really needs an answer.
     */
    public void flushPipeline() throws SQLException {
        if (pipelineGroup == 0) {
            return;
        }
        int group = pipelineGroup;
        int groupStart = pipelineCount;
        pipelineGroup = 0;
        SQLException failure = null;
        int failedAt = -1;
        try {
            channel.flush();
            if (pipelineCarried) {
                readCarriedSetting();
                pipelineCarried = false;
            }
            for (int i = 0; i < group; i++) {
                try {
                    readResult(null, true);
                    rememberPipelineCount(affectedRows);
                } catch (SQLException e) {
                    rememberPipelineCount(java.sql.Statement.EXECUTE_FAILED);
                    if (failure == null) {
                        failure = e;
                        failedAt = groupStart + i;
                    }
                }
            }
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
        if (failure != null) {
            throw pipelineFailure(failure, failedAt);
        }
    }

    /** Ends the block and hands back what the statements reported. */
    public long[] endPipeline() throws SQLException {
        try {
            flushPipeline();
        } finally {
            pipelining = false;
        }
        long[] result = java.util.Arrays.copyOf(pipelineCounts, pipelineCount);
        pipelineCount = 0;
        pipelineSql.clear();
        return result;
    }

    private SQLException pipelineFailure(SQLException cause, int at) {
        String statement = at >= 0 && at < pipelineSql.size() ? pipelineSql.get(at) : null;
        String message = "statement " + (at + 1) + " of the pipeline block failed"
                + (statement == null ? "" : " (" + shortenSql(statement) + ")")
                + ": " + cause.getMessage()
                + " - MySQL runs the rest of the group anyway, so the statements after it "
                + "did execute; the transaction decides what stays.";
        return new SQLException(message, cause.getSQLState(), cause.getErrorCode(), cause);
    }

    private static String shortenSql(String sql) {
        String text = sql == null ? "" : sql.strip();
        return text.length() <= 80 ? text : text.substring(0, 77) + "...";
    }

    private void rememberPipelineCount(long count) {
        if (pipelineCount == pipelineCounts.length) {
            pipelineCounts = java.util.Arrays.copyOf(pipelineCounts,
                    Math.max(16, pipelineCounts.length * 2));
        }
        pipelineCounts[pipelineCount++] = count;
    }


    /**
     * Runs a prepared statement with a <b>server-side cursor</b>.
     *
     * <p>The execute then brings the column descriptions and no rows at all -
     * the server keeps them and hands them out block by block on
     * {@code COM_STMT_FETCH}. That is what a fetch size is for: the memory of
     * a large query becomes the memory of one block.
     *
     * <p>Only for prepared statements, because only they have a statement id
     * for the server to hang the cursor on.
     */
    public void executePreparedWithCursor(Prepared statement, MyParameters parameters)
            throws SQLException {
        flushPipeline();
        try {
            boolean carried = writePending();
            WireBuffer out = channel.beginCommand(COM_STMT_EXECUTE);
            out.putIntLe(statement.statementId());
            out.putByte(CURSOR_TYPE_READ_ONLY);
            out.putIntLe(1);                         // one repetition
            parameters.write(out, statement.parameterCount());
            channel.end();
            channel.flush();
            if (carried) {
                readCarriedSetting();
            }
            readResult(null, true);
            // The execute answered with the descriptions and an EOF; whether
            // there are rows is what the first fetch says.
            cursorOpen = true;
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
    }

    /** Whether a server-side cursor still has rows in it. */
    public boolean isCursorOpen() {
        return cursorOpen;
    }

    /**
     * Reads the next block from a server-side cursor.
     *
     * <p>The server ends the block with an EOF, and that EOF carries the flag
     * that says whether it was the last one. Reading it is the whole trick:
     * without it a client either stops too early or asks once too often.
     */
    public void fetchFromCursor(Prepared statement, int rows, RowHandler handler)
            throws SQLException {
        try {
            WireBuffer out = channel.beginCommand(COM_STMT_FETCH);
            out.putIntLe(statement.statementId());
            out.putIntLe(rows);
            channel.end();
            channel.flush();
            readRowsOfBlock(handler);
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
    }

    /** Closes a cursor the caller stopped reading from. */
    public void closeCursor(Prepared statement) throws SQLException {
        if (!cursorOpen) {
            return;
        }
        cursorOpen = false;
        try {
            WireBuffer out = channel.beginCommand(COM_STMT_RESET);
            out.putIntLe(statement.statementId());
            channel.end();
            channel.flush();
            readOkOrError("closing the cursor");
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
    }

    /** Fills the parameters for one row of a batch. */
    @FunctionalInterface
    public interface BatchBinder {
        void bind(int row) throws SQLException;
    }

    /**
     * Runs one prepared statement over many parameter sets - <b>pipelined</b>.
     *
     * <p>The commands go out back to back and only then are the answers read.
     * MySQL processes them in order, so the n-th answer belongs to the n-th
     * row - and a batch of five hundred costs a handful of round trips instead
     * of five hundred.
     *
     * <p>That is not a small difference and it is not one that only shows in a
     * benchmark: over a network with half a millisecond of latency, five
     * hundred round trips are a quarter of a second in which the database does
     * nothing. <b>MySQL Connector/J sends them one by one by default</b>
     * ({@code rewriteBatchedStatements} is off), so this is the one place
     * where the difference is a factor and not a percentage.
     *
     * <p>The group is bounded, and not out of caution alone: if the client
     * keeps writing while the server keeps answering, both socket buffers can
     * fill and both sides block - a deadlock in which neither is at fault.
     *
     * <p>An error does not end the reading. The answers still in flight belong
     * to rows already sent, and a client that stops listening leaves the
     * connection in a state the next command no longer understands. The
     * failure is kept and raised once the group has been read to the end.
     */
    public long[] executePreparedBatch(Prepared statement, MyParameters parameters,
                                       int count, BatchBinder binder) throws SQLException {
        flushPipeline();
        long[] counts = new long[count]; // seclume-allow: update counts, not a secret
        int at = 0;
        SQLException failure = null;
        try {
            // The pending session setting goes FIRST, in the same flush.
            //
            // Leaving it out was a bug worth writing down: setAutoCommit(false)
            // only announces itself and rides along with the next statement, so
            // a batch that skipped it ran with autocommit still ON - and every
            // one of five hundred rows became its own durable transaction. The
            // round trips looked perfect (two for five hundred rows) while the
            // server paid an fsync per row: 1.9 ms each, measured, which made
            // the batch three times slower than Connector/J instead of faster.
            // A counter that only counts round trips cannot see this.
            boolean carried = writePending();
            while (at < count) {
                int start = at;
                int sent = 0;
                while (at < count && sent < PIPELINE_ROWS
                        && channel.pending() < PIPELINE_BYTES) {
                    binder.bind(at);
                    WireBuffer out = channel.beginCommand(COM_STMT_EXECUTE);
                    out.putIntLe(statement.statementId());
                    out.putByte((byte) 0);               // no cursor
                    out.putIntLe(1);                     // iterations, always 1
                    parameters.write(out, statement.parameterCount());
                    channel.end();
                    at++;
                    sent++;
                }
                channel.flush();
                if (carried) {
                    readCarriedSetting();
                    carried = false;
                }
                for (int i = 0; i < sent; i++) {
                    try {
                        readResult(null, true);
                        counts[start + i] = affectedRows;
                    } catch (SQLException e) {
                        if (failure == null) {
                            failure = e;
                        }
                        counts[start + i] = java.sql.Statement.EXECUTE_FAILED;
                    }
                }
            }
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
        if (failure != null) {
            // With the counts: the rows pipelined after the failing one ran
            // too, and a caller - Spring, Hibernate, a retry - has to know
            // which landed. EXECUTE_FAILED marks the ones that did not.
            throw new java.sql.BatchUpdateException(failure.getMessage(), failure.getSQLState(),
                    failure.getErrorCode(), counts, failure);
        }
        return counts;
    }

    /** Releases a prepared plan in the server again. */
    public void closeStatement(int statementId) throws SQLException {
        try {
            WireBuffer out = channel.beginCommand(COM_STMT_CLOSE);
            out.putIntLe(statementId);
            channel.end();
            channel.flush();
            // COM_STMT_CLOSE gets no answer - that is by design.
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
    }

    /** Throws away the parameters of a prepared statement in the server. */
    public void resetStatement(int statementId) throws SQLException {
        try {
            WireBuffer out = channel.beginCommand(COM_STMT_RESET);
            out.putIntLe(statementId);
            channel.end();
            channel.flush();
            readOkOrError("resetting the statement");
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
    }

    /**
     * Asks the server to stop whatever this connection is doing.
     *
     * <p>MySQL has no out-of-band message for this. What it has is a
     * statement - {@code KILL QUERY <id>} - and a statement needs a connection
     * to run on, which cannot be this one: it is blocked waiting for the
     * answer to the query being cancelled. So a second connection is opened,
     * logged in, used for one statement and closed again.
     *
     * <p><b>That is expensive and it is not an oversight.</b> A cancellation
     * costs a full handshake here, where PostgreSQL costs sixteen bytes, and
     * on {@code caching_sha2_password} it costs a key derivation as well. The
     * alternative would be to hold a spare connection open per session, which
     * doubles a pool's footprint to pay for something that almost never
     * happens. Connector/J makes the same trade.
     *
     * <p>{@code KILL QUERY} and not {@code KILL}: the first ends the running
     * statement, the second ends the session. A timeout that closed the
     * connection would turn a slow query into a lost connection, and in a pool
     * under load that is the worse of the two.
     *
     * <p>Safe from another thread - it touches nothing this session owns
     * except two values written once during the login.
     *
     * @throws SQLException if this session cannot be cancelled, or the second
     *                      connection could not be made
     */
    public void cancel() throws SQLException {
        Settings where = settings;
        if (where == null) {
            throw new SQLException("this session was resumed rather than opened, so it does "
                    + "not know which server to send a cancellation to", "0A000");
        }
        if (!channel.isAwaitingAnswer()) {
            // Nothing is running, so there is nothing to kill - and killing
            // anyway would stop the next statement instead. See
            // MyChannel#isAwaitingAnswer.
            return;
        }
        try (MySession aside = openOne(where)) {
            aside.execute("kill query " + connectionId);
        }
    }

    /** {@code COM_PING} - the cheapest way to ask whether the line still stands. */
    public void ping() throws SQLException {
        try {
            channel.beginCommand(COM_PING);
            channel.end();
            channel.flush();
            readOkOrError("ping");
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
    }

    /**
     * {@code COM_RESET_CONNECTION} - resets session variables, temporary
     * tables and prepared statements without logging in again. Exactly what a
     * pool needs when a connection comes back.
     */
    public void resetConnection() throws SQLException {
        try {
            channel.beginCommand(COM_RESET_CONNECTION);
            channel.end();
            channel.flush();
            readOkOrError("resetting the connection");
            // The server dropped every prepared statement with the rest. A
            // cached plan kept here would name a statement id that no longer
            // exists - "Unknown prepared statement handler" on its next use.
            plans.clear();
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
    }

    // ---- results ---------------------------------------------------------

    private void readResult(RowHandler handler, boolean binary)
            throws SQLException, IOException {
        int first = channel.nextPacket();
        WireBuffer in = channel.packet();
        if (first == MyPackets.NULL_LENGTH
                && MyCapabilities.has(capabilities, MyCapabilities.LOCAL_FILES)) {
            // LOCAL INFILE: the server asks for a file by name. The name is
            // never opened - see loadData. Answered with the caller's stream
            // during loadData, with an empty file at any other time.
            channel.endPacket();
            sendLocalData();
            readResult(handler, binary);
            return;
        }
        if (first == MyPackets.ERR) {
            SQLException failure = serverError(in, "the statement failed");
            channel.endPacket();
            closeIfConnectionFailure(failure);
            throw failure;
        }
        if (first == MyPackets.OK) {
            readOk(in);
            channel.endPacket();
            fields = List.of();
            return;
        }
        if (first == MyPackets.EOF && channel.packetRemaining() < 9) {
            // A short 0xfe packet is an EOF, not a result.
            channel.endPacket();
            fields = List.of();
            return;
        }
        int columnCount = (int) MyPackets.readLengthEncoded(in);
        channel.endPacket();
        fields = readFieldDescriptions(columnCount);
        readRows(handler, binary);
    }

    private List<Field> readFieldDescriptions(int count) throws SQLException, IOException {
        if (count == 0) {
            return List.of();
        }
        // The count is a length-encoded number off the wire. Negative reached
        // ArrayList's constructor as "Illegal Capacity: -1" - an
        // IllegalArgumentException out of executeQuery, which promises
        // SQLException. The upper bound is MySQL's own: a table cannot have
        // more than 4096 columns, so anything above it is not a result set.
        if (count < 0 || count > 4096) {
            // Through brokenConnection, and not a bare throw: an 08xxx that
            // leaves the session reporting itself open is a connection a pool
            // hands to the next caller, with a stream nobody can make sense
            // of. The first version of this check threw directly and the fuzz
            // contract caught it at once - which is what that requirement is
            // for.
            throw brokenConnection(new java.io.IOException(
                    "the server announced a result of " + count + " columns, which is not a "
                    + "result set"));
        }
        List<Field> list = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            channel.nextPacket();
            WireBuffer in = channel.packet();
            MyPackets.skipLengthEncodedString(in);            // Katalog, immer "def"
            String schema = MyPackets.readLengthEncodedString(in);
            String table = MyPackets.readLengthEncodedString(in);
            MyPackets.skipLengthEncodedString(in);            // Tabelle im Original
            String name = MyPackets.readLengthEncodedString(in);
            String originalName = MyPackets.readLengthEncodedString(in);
            MyPackets.readLengthEncoded(in);                  // Laenge des Restes, 0x0c
            int charset = in.getShortLe() & 0xffff;
            long columnLength = in.getIntLe() & 0xffff_ffffL;
            int type = in.getByte() & 0xff;
            int flags = in.getShortLe() & 0xffff;
            int decimals = in.getByte() & 0xff;
            channel.endPacket();
            list.add(new Field(schema, table, name, originalName, charset, columnLength,
                    type, flags, decimals));
        }
        if (!MyCapabilities.has(capabilities, MyCapabilities.DEPRECATE_EOF)) {
            channel.nextPacket();                             // das EOF nach den Spalten
            channel.endPacket();
        }
        return List.copyOf(list);
    }

    private void skipFieldDescriptions(int count) throws SQLException, IOException {
        readFieldDescriptions(count);
    }

    /**
     * One block of a server-side cursor.
     *
     * <p>The server closes a block with an EOF like any result, and the flags
     * of that EOF say whether it was the last one. That flag is the whole
     * difference between stopping too early and asking once too often.
     */
    private void readRowsOfBlock(RowHandler handler) throws SQLException, IOException {
        readRows(handler, true);
        cursorOpen = (statusFlags & SERVER_STATUS_LAST_ROW_SENT) == 0;
    }

    private void readRows(RowHandler handler, boolean binary)
            throws SQLException, IOException {
        MyRow row = new MyRow(channel.packet(), fields, binary);
        // A handler that refuses a row - a result limit, say - must not leave
        // the rest of the result on the wire: the session would be out of step
        // with the server from then on. So the reading goes on and the failure
        // waits for the end of the result.
        SQLException refused = null;
        while (true) {
            int first = channel.nextPacket();
            WireBuffer in = channel.packet();
            if (first == MyPackets.ERR) {
                SQLException failure = serverError(in, "the result was cut short");
                channel.endPacket();
                closeIfConnectionFailure(failure);
                throw failure;
            }
            // A 0xfe packet under nine bytes ends the result. Longer it
            // would be a row that happens to start with 0xfe - hence the
            // length check and not just the first byte.
            if (first == MyPackets.EOF && channel.packetRemaining() < 9) {
                in.skip(1);
                if (MyCapabilities.has(capabilities, MyCapabilities.DEPRECATE_EOF)) {
                    affectedRows = MyPackets.readLengthEncoded(in);
                    lastInsertId = MyPackets.readLengthEncoded(in);
                    statusFlags = in.getShortLe() & 0xffff;
                    channel.answerFinished();
                    warnings = in.getShortLe() & 0xffff;
                } else {
                    warnings = in.getShortLe() & 0xffff;
                    statusFlags = in.getShortLe() & 0xffff;
                    channel.answerFinished();
                }
                channel.endPacket();
                if (refused != null) {
                    throw refused;
                }
                return;
            }
            if (handler != null && refused == null) {
                row.start(in.position(), channel.packetRemaining());
                try {
                    handler.row(row);
                } catch (SQLException e) {
                    refused = e;
                }
            }
            channel.endPacket();
        }
    }

    private void readOk(WireBuffer in) {
        in.skip(1);
        affectedRows = MyPackets.readLengthEncoded(in);
        lastInsertId = MyPackets.readLengthEncoded(in);
        if (MyCapabilities.has(capabilities, MyCapabilities.PROTOCOL_41)) {
            statusFlags = in.getShortLe() & 0xffff;
            channel.answerFinished();
            warnings = in.getShortLe() & 0xffff;
        }
    }

    /**
     * The answer to a setting that rode in front of a statement.
     *
     * <p>Read like any OK - but it does not end the wait: the statement it
     * rode with has not answered yet. Ending it here made the cancellation
     * think nothing was running, so a query timeout inside a transaction
     * (whose {@code set autocommit=0} always rides along) never cancelled
     * anything and the statement ran to its end. Found by the Spring JDBC
     * suite.
     */
    private void readCarriedSetting() throws SQLException, IOException {
        try {
            readOkOrError("the session setting");
        } finally {
            channel.answerStillExpected();
        }
    }

    private void readOkOrError(String what) throws SQLException, IOException {
        int first = channel.nextPacket();
        WireBuffer in = channel.packet();
        if (first == MyPackets.ERR) {
            SQLException failure = serverError(in, what + " failed");
            channel.endPacket();
            closeIfConnectionFailure(failure);
            throw failure;
        }
        readOk(in);
        channel.endPacket();
    }

    /**
     * An error packet in an open session - see closeIfConnectionFailure: a SQLState of class 08 is the
     * server saying the connection itself is broken (08S01, a communication
     * failure, say) - so the session closes, rather than go on reporting
     * itself usable to a pool that would hand it out again. Found by Jazzer
     * on 25.09.2026: an error packet with state 08 left the session open.
     */
    private SQLException serverError(WireBuffer in, String context) {
        return readError(in, context);
    }

    /** After the error packet has been consumed: close on a connection-class state. */
    private void closeIfConnectionFailure(SQLException failure) {
        String state = failure.getSQLState();
        if (state != null && state.startsWith("08")) {
            channel.close();
        }
    }

    /** An error packet: number, SQLState and message. */
    private static SQLException readError(WireBuffer in, String context) {
        in.skip(1);
        int errorNumber = in.getShortLe() & 0xffff;
        String sqlState = "HY000";
        if (in.remaining() > 0 && in.getByte(in.position()) == '#') {
            in.skip(1);
            sqlState = in.readString(5);
        }
        String message = in.readString(in.remaining());
        return failure(context + ": " + message, sqlState, errorNumber);
    }

    /**
     * The server's error as the type an application catches.
     *
     * <p>A value that does not fit - out of range, too long, a division by
     * zero in strict mode - is a {@link java.sql.DataTruncation}, state 22001,
     * as Connector/J raises it; code that catches that type or checks 22001
     * for "the value did not fit" sees it here too. A state with a JDBC 4 type
     * of its own gets that type; anything else is a {@link MyException}.
     */
    static SQLException failure(String message, String sqlState, int errorNumber) {
        return switch (errorNumber) {
            case 1264, 1265, 1365, 1406 -> new MyDataTruncation(message, errorNumber);
            default -> switch (sqlState.substring(0, 2)) {
                case "22", "23", "28", "40", "42", "0A" ->
                        space.seclume.internal.jdbc.SqlErrors.of(message, sqlState, errorNumber);
                default -> new MyException(message, sqlState, errorNumber);
            };
        };
    }

    /**
     * The connection is gone, and the session with it.
     *
     * <p><b>Closing here is the point.</b> After an IO failure the protocol
     * state is unknown - a half-read packet, a command whose answer never
     * came - so every further call would fail the same way. Saying so through
     * {@code isClosed()} is what lets a pool throw the connection away instead
     * of handing it out again; without it a database that goes away for two
     * seconds takes the pool with it for as long as requests keep arriving.
     * Found by the chaos benchmark, where it happened on every request.

     * <p><b>And a second cause, which used to escape as an unchecked
     * exception.</b> {@code WireBuffer.Truncated} is an
     * {@code IllegalStateException} thrown when a message announces more bytes
     * than it brought, and nothing caught it - so a malformed answer came out
     * of {@code Statement.executeQuery}, a method whose signature promises
     * {@link SQLException} and nothing else. An application catches
     * {@code SQLException}; that is what a framework's retry and its
     * connection-health check are written against. It is the same fact as an
     * IO failure seen from one layer up: what follows the message is not where
     * the protocol says it is, so every byte after it would be read at the
     * wrong offset. Found by the fuzz corpus on 23.09.2026.
     */
    private SQLException brokenConnection(Exception cause) {
        channel.close();
        return new SQLNonTransientConnectionException(
                "the connection to the server broke", "08006", cause);
    }

    // ---- state -----------------------------------------------------------

    public List<Field> fields() {
        return fields;
    }

    public long affectedRows() {
        return affectedRows;
    }

    public long lastInsertId() {
        return lastInsertId;
    }

    public int warnings() {
        return warnings;
    }

    /** The server banner, {@code 8.4.0} or {@code 11.4.2-MariaDB} say. */
    public String serverVersion() {
        return serverVersion;
    }

    public long connectionId() {
        return connectionId;
    }

    /** The plugin the server started the login with. */
    public String authenticationPlugin() {
        return authenticationPlugin;
    }

    /** Whether a transaction is open - bit 0 of the status bits. */
    public boolean inTransaction() {
        return (statusFlags & 0x0001) != 0;
    }

    public boolean isMariaDb() {
        return serverVersion.contains("MariaDB");
    }

    /** What this connection last sent and received - see space.seclume.Flight. */
    public java.util.List<space.seclume.Flight.Message> recentMessages() {
        return channel.recentMessages();
    }

    /** How many packets have crossed this connection. */
    public long recordedMessages() {
        return channel.recordedMessages();
    }

    public boolean isOpen() {
        return channel.isOpen();
    }

    @Override
    public void close() {
        try {
            if (channel.isOpen()) {
                channel.beginCommand(COM_QUIT);
                channel.end();
                channel.flush();
            }
        } catch (IOException ignored) {
            // When hanging up an error has no consequences.
        } finally {
            channel.close();
        }
    }
}
