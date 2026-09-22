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
                           long connectionId) {
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
     * And not while encrypted, because the keys are in this process and the
     * records on that socket mean nothing anywhere else.
     */
    public Detached detach() throws SQLException {
        if (!channel.isIdle()) {
            throw new SQLException("this session has work in flight - a stream can only be "
                    + "handed over at a quiescent point", "25000");
        }
        if (channel.isEncrypted()) {
            throw new SQLException("this session is encrypted - its keys are in this process, "
                    + "so the stream cannot be handed to another one. Open the session "
                    + "without TLS, or terminate TLS where the login happens", "0A000");
        }
        Detached detached = new Detached(channel.transport(), capabilities, connectionId);
        channel.release();
        return detached;
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
        return new MySession(MyChannel.over(stream), capabilities, "resumed",
                connectionId, null);
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
        } catch (IOException e) {
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
    private String pending;
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
        return settings.hosts().open(server -> openOne(settings.at(server)), ROLES);
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
            opened.tinyInt1isBit = settings.tinyInt1isBit();
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
        } catch (IOException e) {
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

            int clientCapabilities = MyCapabilities.CLIENT_DEFAULTS & greeting.capabilities();
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
            writeHandshakeResponse(channel, settings, clientCapabilities, plugin, scramble);

            MySession session = new MySession(channel, clientCapabilities, greeting.version(),
                    greeting.connectionId(), plugin);
            session.finishAuthentication(settings, plugin, scramble, arena);
            session.setResultLimit(settings.resultLimit());
            return session;
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
        } catch (IOException e) {
            throw new SQLNonTransientConnectionException(
                    "TLS to " + settings.host() + ":" + settings.port() + " failed: "
                    + e.getMessage(), "08001", e);
        }
        return withSsl;
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
        } catch (IOException e) {
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
        out.putZeroes(256);      // room for a hash or, inside TLS, the password itself
        out.position(at);
        try (SecretScope password = SecretScope.fromProvider(settings.secret())) {
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
        } catch (IOException e) {
            throw new SQLNonTransientConnectionException(
                    "the connection broke during authentication", "08006", e);
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
        RsaPublicKey key = ServerPublicKey.parsePem(pem, 0, length);
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
        WireBuffer out = channel.beginPacket();
        int at = out.position();
        out.putZeroes(256);      // room for a hash or, inside TLS, the password itself
        out.position(at);
        try (SecretScope password = SecretScope.fromProvider(settings.secret())) {
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
                readOkOrError("the session setting");
            }
            readResult(handler, false);
        } catch (IOException e) {
            throw brokenConnection(e);
        }
    }

    /** Short form for statements without a result. */
    public void execute(String sql) throws SQLException {
        query(sql, null);
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
            WireBuffer out = channel.beginCommand(COM_STMT_PREPARE);
            out.putText(sql);
            channel.end();
            channel.flush();

            int first = channel.nextPacket();
            WireBuffer in = channel.packet();
            if (first == MyPackets.ERR) {
                SQLException failure = readError(in, "the server rejected the statement");
                channel.endPacket();
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
        } catch (IOException e) {
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
                readOkOrError("the session setting");
            }
            readResult(handler, true);
        } catch (IOException e) {
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
     * <p>Only one is ever pending, and only settings go through here - things
     * whose answer nobody looks at.
     */
    public void runLater(String sql) {
        this.pending = sql;
    }

    /** Whether a setting is waiting for a statement to ride along with. */
    public boolean hasPending() {
        return pending != null;
    }

    /** Sends what is pending right now, for whoever cannot wait. */
    public void flushPending() throws SQLException {
        if (pending != null) {
            String sql = pending;
            pending = null;
            query(sql, null);
        }
    }

    private boolean writePending() {
        for (int statementId : pendingClose) {
            WireBuffer out = channel.beginCommand(COM_STMT_CLOSE);
            out.putIntLe(statementId);
            channel.end();                       // COM_STMT_CLOSE gets no answer
        }
        pendingClose.clear();
        if (pending == null) {
            return false;
        }
        WireBuffer out = channel.beginCommand(COM_QUERY);
        out.putText(pending);
        channel.end();
        pending = null;
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
                readOkOrError("the session setting");
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
        } catch (IOException e) {
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
                readOkOrError("the session setting");
            }
            readResult(null, true);
            // The execute answered with the descriptions and an EOF; whether
            // there are rows is what the first fetch says.
            cursorOpen = true;
        } catch (IOException e) {
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
        } catch (IOException e) {
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
        } catch (IOException e) {
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
                    readOkOrError("the session setting");
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
        } catch (IOException e) {
            throw brokenConnection(e);
        }
        if (failure != null) {
            throw failure;
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
        } catch (IOException e) {
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
        } catch (IOException e) {
            throw brokenConnection(e);
        }
    }

    /** {@code COM_PING} - the cheapest way to ask whether the line still stands. */
    public void ping() throws SQLException {
        try {
            channel.beginCommand(COM_PING);
            channel.end();
            channel.flush();
            readOkOrError("ping");
        } catch (IOException e) {
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
        } catch (IOException e) {
            throw brokenConnection(e);
        }
    }

    // ---- results ---------------------------------------------------------

    private void readResult(RowHandler handler, boolean binary)
            throws SQLException, IOException {
        int first = channel.nextPacket();
        WireBuffer in = channel.packet();
        if (first == MyPackets.ERR) {
            SQLException failure = readError(in, "the statement failed");
            channel.endPacket();
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
                SQLException failure = readError(in, "the result was cut short");
                channel.endPacket();
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
                    warnings = in.getShortLe() & 0xffff;
                } else {
                    warnings = in.getShortLe() & 0xffff;
                    statusFlags = in.getShortLe() & 0xffff;
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
            warnings = in.getShortLe() & 0xffff;
        }
    }

    private void readOkOrError(String what) throws SQLException, IOException {
        int first = channel.nextPacket();
        WireBuffer in = channel.packet();
        if (first == MyPackets.ERR) {
            SQLException failure = readError(in, what + " failed");
            channel.endPacket();
            throw failure;
        }
        readOk(in);
        channel.endPacket();
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
        return new MyException(context + ": " + message, sqlState, errorNumber);
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
     */
    private SQLException brokenConnection(IOException cause) {
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
