package space.seclume.postgresql;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.sql.SQLNonTransientConnectionException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import space.seclume.postgresql.auth.Md5Password;
import space.seclume.postgresql.auth.ScramSha256;
import space.seclume.postgresql.wire.PgChannel;
import space.seclume.internal.WireBuffer;
import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * A session with a PostgreSQL server: connecting, logging in and running
 * statements.
 *
 * <p>This is the layer below JDBC. It knows the protocol, but no
 * {@code Connection}, no {@code ResultSet} semantics and no type conversion for
 * callers - that comes on top. This way the protocol stays testable on its own.
 *
 * <p>The password only lives for the duration of the login, inside a
 * {@link SecretScope}. Afterwards it is zeroed; the session does not hold on to
 * it, not even for a later reconnect - for that the {@link SecretProvider} is
 * asked again.
 */
public final class PgSession implements AutoCloseable {

    /** One column of a result row, as the server describes it. */
    public record Field(String name, int tableOid, short columnNumber, int typeOid,
                        short typeLength, int typeModifier, short format) {
    }

    /** Connection settings. Deliberately not the password, only its source. */
    public record Settings(String host, int port, String database, String user,
                           SecretProvider secret, String applicationName,
                           int connectTimeoutMillis, HostList hosts, ResultLimit resultLimit,
                           TlsMode tls,
                           space.seclume.internal.jdbc.TlsStack tlsStack,
                           space.seclume.tls.ClientIdentity identity) {

        /**
         * Without a client certificate - what almost every connection is.
         */
        public Settings(String host, int port, String database, String user,
                        SecretProvider secret, String applicationName,
                        int connectTimeoutMillis, HostList hosts, ResultLimit resultLimit,
                        TlsMode tls, space.seclume.internal.jdbc.TlsStack tlsStack) {
            this(host, port, database, user, secret, applicationName, connectTimeoutMillis,
                    hosts, resultLimit, tls, tlsStack, null);
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
                        int connectTimeoutMillis, HostList hosts, ResultLimit resultLimit,
                        TlsMode tls) {
            this(host, port, database, user, secret, applicationName, connectTimeoutMillis,
                    hosts, resultLimit, tls, space.seclume.internal.jdbc.TlsStack.JSSE, null);
        }

        /** Without a result limit - what a URL without the option means. */
        public Settings(String host, int port, String database, String user,
                        SecretProvider secret, String applicationName,
                        int connectTimeoutMillis, HostList hosts) {
            this(host, port, database, user, secret, applicationName, connectTimeoutMillis,
                    hosts, ResultLimit.NONE, TlsMode.PREFER);
        }

        /** With a result limit but the default TLS mode. */
        public Settings(String host, int port, String database, String user,
                        SecretProvider secret, String applicationName,
                        int connectTimeoutMillis, HostList hosts, ResultLimit resultLimit) {
            this(host, port, database, user, secret, applicationName, connectTimeoutMillis,
                    hosts, resultLimit, TlsMode.PREFER);
        }

        public Settings(String host, int port, String database, String user, SecretProvider secret) {
            this(host, port, database, user, secret, "seclume", 10_000);
        }

        /** One server - the ordinary case, and what every URL without a comma means. */
        public Settings(String host, int port, String database, String user,
                        SecretProvider secret, String applicationName,
                        int connectTimeoutMillis) {
            this(host, port, database, user, secret, applicationName, connectTimeoutMillis,
                    HostList.of(host, port));
        }

        /**
         * The same settings pointed at another server of the list.
         *
         * <p>Every component has to be carried across, including the ones
         * added later. This one quietly dropped the TLS stack when it was
         * added, and because a single-host list goes through here too, that
         * was not a failover bug - it was every connection losing the choice.
         */
        Settings at(HostList.Host server) {
            return new Settings(server.host(), server.port(), database, user, secret,
                    applicationName, connectTimeoutMillis, hosts, resultLimit, tls, tlsStack,
                    identity);
        }
    }

    /** Receives the rows of a query - without a copy, straight from the receive buffer. */
    @FunctionalInterface
    public interface RowHandler {
        void row(Row row) throws SQLException;
    }

    /** How many rows of a batch go out before a Sync closes the group. */
    private static final int PIPELINE_ROWS = 256;
    /** And how many bytes, whichever comes first. */
    private static final int PIPELINE_BYTES = 64 * 1024;

    /** Whether writes are being held back - see the pipeline block below. */
    private boolean pipelining;
    /** How many executions are waiting for their Sync. */
    private int pipelineGroup;
    /** Answers that ride along with the group and belong to nobody. */
    private int pipelineCarried;
    private long[] pipelineCounts = new long[0]; // seclume-allow: update counts, not a secret
    private int pipelineCount;
    private final java.util.List<String> pipelineSql = new java.util.ArrayList<>();
    /** Set when the server stopped at a row limit - see executeMore. */
    private boolean portalSuspended;
    private ResultLimit resultLimit = ResultLimit.NONE;
    /** The database this session is connected to - what getCatalog() answers. */
    private String database = "";
    private final PgChannel channel;
    private final Map<String, String> parameters = new HashMap<>();
    private List<Field> fields = List.of();

    /**
     * The one row window of this session, plus its index arrays.
     *
     * <p>Reused for every row - a {@link Row} is only valid until the next one
     * arrives, so building a new one per row would be three objects for
     * nothing.
     */
    private Row row;
    private int[] rowOffsets = new int[0]; // seclume-allow: column offsets of a row, not a secret
    private int[] rowLengths = new int[0]; // seclume-allow: column lengths of a row, not a secret
    private int backendProcessId;
    private int backendSecretKey;
    private char transactionStatus = 'I';
    /** Settings that ride along with the next statement - see runLater. */
    private final List<String> pending = new ArrayList<>();
    /** Plans to be released with the next block - see writePendingCloses. */
    private final List<String> pendingCloses = new ArrayList<>();
    /** A prepared plan announced but not yet parsed - see parseLater. */
    private String pendingParseName;
    private String pendingParseSql;
    /** More than this many settings waiting means: send them now. */
    private static final int PENDING_LIMIT = 16;
    /**
     * Whether settings and parses may ride along with the next statement.
     *
     * <p>On by default, because it is what makes the common shapes cheap. It
     * changes one thing one may not want, and it is about <b>when</b> an error
     * appears: a statement with a syntax error is refused at its first
     * execution instead of at {@code prepareStatement}. Whoever needs the
     * strict order sets {@code deferSessionState=false} and pays a round trip
     * for every setting.
     */
    private boolean defer = true;

    /** Switches the riding-along off - see {@link #defer}. */
    public void setDeferSessionState(boolean defer) throws SQLException {
        this.defer = defer;
        if (!defer) {
            flushPending();
        }
    }
    private String lastCommandTag = "";
    /** Which login method the server demanded - for diagnosis and tests. */
    private String authenticationMethod = "trust";

    private PgSession(PgChannel channel) {
        this.channel = channel;
    }

    /**
     * Continues a session somebody else authenticated.
     *
     * <p>The opposite of {@link #detach()}: somewhere else logged in, and this
     * process picks the stream up. A driver doing that cannot do what a driver
     * normally does first - there is no startup to run, the server is long
     * past it - so what it would have learnt there arrives as an argument
     * instead.
     *
     * <p>{@code parameters} is what the server announced while logging in:
     * the client encoding, the date style, whether timestamps are integers. A
     * decoder that guesses those is a decoder that is wrong about dates, which
     * is why they are required rather than defaulted.
     *
     * <p><b>The stream has to be at a message boundary</b>, and the caller is
     * the only one who can know that. There is no check here that could tell
     * the difference between the middle of a message and the start of one -
     * the first four bytes of a length look like anything else.
     *
     * @param stream a connection to a server that has already accepted a login
     * @param parameters what that server announced while it did
     */
    public static PgSession resume(space.seclume.internal.Transport stream,
                                   java.util.Map<String, String> parameters,
                                   int backendProcessId, int backendSecretKey) {
        PgSession session = new PgSession(PgChannel.over(stream));
        session.parameters.putAll(parameters);
        session.backendProcessId = backendProcessId;
        session.backendSecretKey = backendSecretKey;
        return session;
    }

    /**
     * Opens the connection and logs in.
     *
     * @throws SQLException if the server refuses or demands a method this
     *         driver does not speak
     */
    public static PgSession open(Settings settings) throws SQLException {
        // With one server this is a plain connect; with several it takes the
        // next one when a server cannot be reached. Nothing else fails over -
        // see HostList for why a rejected password does not.
        return settings.hosts().open(server -> openOne(settings.at(server)));
    }

    private static PgSession openOne(Settings settings) throws SQLException {
        // The expensive one: a physical connect, the TLS handshake and the
        // login. Recorded around the whole of it, because that is the number
        // a pool's warm-up time is made of. See space.seclume.jfr.
        space.seclume.jfr.SeclumeEvents.ConnectionOpen event =
                space.seclume.jfr.Observed.beginConnect();
        PgSession opened = null;
        try {
            opened = connectAndLogIn(settings);
            return opened;
        } finally {
            space.seclume.jfr.Observed.endConnect(event, "postgresql",
                    settings.host() + ":" + settings.port(), settings.database(),
                    opened == null ? null : opened.tlsDescription(), opened != null);
        }
    }

    private static PgSession connectAndLogIn(Settings settings) throws SQLException {
        PgChannel channel;
        try {
            channel = PgChannel.connect(settings.host(), settings.port(),
                    settings.connectTimeoutMillis());
        } catch (IOException e) {
            throw new SQLNonTransientConnectionException(
                    "cannot reach " + settings.host() + ":" + settings.port(), "08001", e);
        }
        PgSession session = new PgSession(channel);
        session.setResultLimit(settings.resultLimit());
        try {
            session.negotiateTls(channel, settings);
            session.startup(settings);
            return session;
        } catch (SQLException | RuntimeException e) {
            channel.close();
            throw e;
        }
    }

    /**
     * Asks for TLS before anything else happens on the connection.
     *
     * <p>The order is not ours to choose: the login has to travel inside TLS,
     * so the switch happens before the startup message and after nothing.
     */
    private void negotiateTls(PgChannel channel, Settings settings) throws SQLException {
        TlsMode mode = settings.tls();
        if (mode == TlsMode.OFF) {
            return;
        }
        try {
            if (!channel.requestTls()) {
                if (mode.demands()) {
                    throw new SQLNonTransientConnectionException(
                            "the server at " + settings.host() + ":" + settings.port()
                            + " does not offer TLS, and tls=" + mode.name().toLowerCase()
                            + " was asked for", "08001");
                }
                return;
            }
            channel.startTls(settings.host(), settings.port(), mode.verifies(),
                    settings.tlsStack(), settings.identity());
        } catch (IOException e) {
            throw new SQLNonTransientConnectionException(
                    "TLS to " + settings.host() + ":" + settings.port() + " failed: "
                    + e.getMessage(), "08001", e);
        }
    }

    /** What TLS this connection uses, or {@code null} without it. */
    public String tlsDescription() {
        return channel.tlsDescription();
    }

    private void startup(Settings settings) throws SQLException {
        // The server does not send the database back among its parameters, so
        // it is kept here - getCatalog() has to answer with something, and
        // guessing from the URL in the JDBC layer would be a second source of
        // truth for the same fact.
        this.database = settings.database();
        try {
            WireBuffer out = channel.beginUntagged();
            out.putInt(PgProtocol.VERSION_3);
            out.putCString("user").putCString(settings.user());
            out.putCString("database").putCString(settings.database());
            out.putCString("application_name").putCString(settings.applicationName());
            out.putCString("client_encoding").putCString("UTF8");
            out.putByte((byte) 0);
            channel.end();
            channel.flush();

            authenticate(settings);
            waitForReady();
        } catch (IOException e) {
            throw new SQLNonTransientConnectionException(
                    "the connection failed during startup", "08006", e);
        }
    }

    /**
     * Runs the login, whichever method the server demands.
     *
     * <p>The {@link SecretScope} wraps the whole procedure: several methods
     * only need the password in the second step, and every reload would be a
     * second reach into the secret source.
     */
    private void authenticate(Settings settings) throws IOException, SQLException {
        try (SecretScope secret = SecretScope.fromProvider(settings.secret());
             ScramSha256 scram = new ScramSha256()) {
            boolean scramStarted = false;
            while (true) {
                byte tag = channel.nextMessage();
                WireBuffer in = channel.message();
                if (tag == PgProtocol.ERROR_RESPONSE) {
                    throw readError();
                }
                if (tag != PgProtocol.AUTHENTICATION) {
                    // ParameterStatus and friends may already arrive here.
                    handleAsynchronous(tag);
                    if (tag == PgProtocol.READY_FOR_QUERY) {
                        return;
                    }
                    continue;
                }
                int code = in.getInt();
                switch (code) {
                    case PgProtocol.AUTH_OK -> {
                        channel.endMessage();
                        return;
                    }
                    case PgProtocol.AUTH_CLEARTEXT -> {
                        authenticationMethod = "password";
                        channel.endMessage();
                        sendPassword(secret.secret());
                    }
                    case PgProtocol.AUTH_MD5 -> {
                        authenticationMethod = "md5";
                        MemorySegment salt = in.slice(in.position(), 4);
                        sendMd5(settings.user(), secret.secret(), salt);
                        channel.endMessage();
                    }
                    case PgProtocol.AUTH_SASL -> {
                        String mechanism = chooseMechanism(in, scram);
                        authenticationMethod = mechanism.toLowerCase(java.util.Locale.ROOT);
                        channel.endMessage();
                        startScram(scram, mechanism);
                        scramStarted = true;
                    }
                    case PgProtocol.AUTH_SASL_CONTINUE -> {
                        if (!scramStarted) {
                            throw protocolError("the server continued a SASL exchange "
                                    + "that never started");
                        }
                        continueScram(scram, secret.secret());
                    }
                    case PgProtocol.AUTH_SASL_FINAL -> {
                        int length = channel.messageRemaining();
                        scram.verifyServerFinal(in.segment(), in.position(), length);
                        channel.endMessage();
                    }
                    case PgProtocol.AUTH_GSS, PgProtocol.AUTH_SSPI,
                         PgProtocol.AUTH_GSS_CONTINUE, PgProtocol.AUTH_KERBEROS_V5 ->
                            throw new SQLException(
                                    "this server asks for GSSAPI/SSPI authentication, which "
                                    + "seclume does not implement yet - it is planned as the "
                                    + "preferred mode, see the README", "28000");
                    default -> throw new SQLException(
                            "unknown authentication request " + code, "28000");
                }
            }
        }
    }

    private void sendPassword(MemorySegment password) throws IOException {
        WireBuffer out = channel.begin(PgProtocol.PASSWORD);
        out.putBytes(password);
        out.putByte((byte) 0);
        channel.end();
        channel.flush();
    }

    private void sendMd5(String user, MemorySegment password, MemorySegment salt)
            throws IOException {
        try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
            byte[] userBytes = user.getBytes(StandardCharsets.UTF_8); // seclume-allow: the user name is configuration, not a secret
            MemorySegment userSegment = arena.allocate(userBytes.length);
            MemorySegment.copy(MemorySegment.ofArray(userBytes), 0, userSegment, 0,
                    userBytes.length);
            MemorySegment response = arena.allocate(Md5Password.RESPONSE_LENGTH);
            try {
                int length = Md5Password.response(password, userSegment, salt, response);
                WireBuffer out = channel.begin(PgProtocol.PASSWORD);
                out.putBytes(response, 0, length);
                channel.end();
                channel.flush();
            } finally {
                response.fill((byte) 0);
            }
        }
    }

    /**
     * Picks the mechanism and tells the exchange what to say about channel
     * binding.
     *
     * <p>Three cases, and the middle one is the interesting one:
     *
     * <ul>
     *   <li>encrypted and PLUS offered - bind to this connection's
     *       certificate;</li>
     *   <li>encrypted and PLUS <b>not</b> offered - plain SCRAM, but the GS2
     *       header says {@code y}: „I can do this, you did not offer it". A
     *       server that can do it sees the contradiction and refuses, which is
     *       what catches somebody who stripped the PLUS from the list on the
     *       way;</li>
     *   <li>not encrypted - {@code n}, because there is nothing to bind
     *       to.</li>
     * </ul>
     */
    private String chooseMechanism(WireBuffer in, ScramSha256 scram) throws SQLException {
        List<String> mechanisms = new ArrayList<>();
        while (channel.messageRemaining() > 0) {
            int length = in.cStringLength();
            if (length == 0) {
                break;
            }
            mechanisms.add(in.readCString());
        }
        if (!mechanisms.contains("SCRAM-SHA-256")
                && !mechanisms.contains("SCRAM-SHA-256-PLUS")) {
            throw new SQLException(
                    "the server offers " + mechanisms + ", but seclume speaks SCRAM-SHA-256 "
                    + "and SCRAM-SHA-256-PLUS", "28000");
        }
        if (channel.tlsDescription() == null) {
            return "SCRAM-SHA-256";
        }
        if (!mechanisms.contains("SCRAM-SHA-256-PLUS")) {
            scram.channelBindingNotOffered();
            return "SCRAM-SHA-256";
        }
        try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
            MemorySegment fingerprint =
                    arena.allocate(space.seclume.internal.ChannelBinding.MAX_LENGTH);
            int length = space.seclume.internal.ChannelBinding.endPoint(
                    channel.peerCertificate(), fingerprint);
            scram.useChannelBinding(fingerprint, length);
            return "SCRAM-SHA-256-PLUS";
        } catch (IOException | IllegalArgumentException e) {
            throw new SQLException(
                    "the server offers channel binding, but seclume cannot compute it for "
                    + "this connection: " + e.getMessage(), "28000", e);
        }
    }

    /**
     * What the login said about channel binding - {@code used},
     * {@code supported-not-offered} or {@code not-possible}.
     *
     * <p>A name and not the enum, because the enum lives in a package this
     * module does not export and the answer belongs in a log line anyway.
     */
    public String channelBinding() {
        return channelBinding.name().toLowerCase(java.util.Locale.ROOT).replace('_', '-');
    }

    private ScramSha256.Binding channelBinding = ScramSha256.Binding.NOT_POSSIBLE;

    private void startScram(ScramSha256 scram, String mechanism) throws IOException {
        try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
            MemorySegment first = arena.allocate(256);
            int length = scram.clientFirst(first);
            this.channelBinding = scram.binding();
            WireBuffer out = channel.begin(PgProtocol.PASSWORD);
            out.putCString(mechanism);
            out.putInt(length);
            out.putBytes(first, 0, length);
            channel.end();
            channel.flush();
        }
    }

    private void continueScram(ScramSha256 scram, MemorySegment password)
            throws IOException {
        WireBuffer in = channel.message();
        int length = channel.messageRemaining();
        scram.serverFirst(in.segment(), in.position(), length);
        channel.endMessage();

        try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
            MemorySegment message = arena.allocate(512);
            try {
                int written = scram.clientFinal(message, password);
                WireBuffer out = channel.begin(PgProtocol.PASSWORD);
                out.putBytes(message, 0, written);
                channel.end();
                channel.flush();
            } finally {
                message.fill((byte) 0);
            }
        }
    }

    /** Reads up to the ReadyForQuery - after that the session is usable. */
    private void waitForReady() throws IOException, SQLException {
        while (true) {
            byte tag = channel.nextMessage();
            if (tag == PgProtocol.READY_FOR_QUERY) {
                transactionStatus = (char) channel.message().getByte();
                channel.endMessage();
                return;
            }
            if (tag == PgProtocol.ERROR_RESPONSE) {
                throw readError();
            }
            handleAsynchronous(tag);
        }
    }

    /**
     * Runs a statement in the simple protocol.
     *
     * <p>Without parameters and without preparation - for everything the driver
     * issues itself ({@code SET}, {@code BEGIN}) and for callers who want
     * exactly that. Parameters belong in the extended protocol; otherwise they
     * would have to be built into the text, and that is the road to SQL
     * injection.
     */
    public void simpleQuery(String sql, RowHandler handler) throws SQLException {
        // Anything that really needs an answer sends the block first - that
        // is the promise of the pipeline: it saves round trips nobody waited
        // for, never a value somebody asked for.
        flushPipeline();

        try {
            int carried = writePending();
            WireBuffer out = channel.begin(PgProtocol.QUERY);
            out.putCString(sql);
            channel.end();
            channel.flush();
            for (int i = 0; i < carried; i++) {
                runUntilReady(null);              // the answers to what rode along
            }

            SQLException failure = null;
            while (true) {
                byte tag = channel.nextMessage();
                switch (tag) {
                    case PgProtocol.ROW_DESCRIPTION -> readRowDescription();
                    case PgProtocol.DATA_ROW -> {
                        Row row = readDataRow();
                        if (handler != null && failure == null) {
                            // A handler that refuses the row - a result limit,
                            // say - must not leave the rest of the answer on
                            // the wire: the session would be out of step with
                            // the server from then on. So the reading goes on
                            // and the failure waits for the end.
                            try {
                                handler.row(row);
                            } catch (SQLException e) {
                                failure = e;
                            }
                        }
                        channel.endMessage();
                    }
                    case PgProtocol.COMMAND_COMPLETE -> {
                        lastCommandTag = channel.message().readCString();
                        channel.endMessage();
                    }
                    case PgProtocol.EMPTY_QUERY -> channel.endMessage();
                    case PgProtocol.ERROR_RESPONSE -> {
                        SQLException error = readError();
                        // After an error a ReadyForQuery still follows;
                        // breaking off here leaves the session in the dark.
                        if (failure == null) {
                            failure = error;
                        }
                    }
                    case PgProtocol.READY_FOR_QUERY -> {
                        transactionStatus = (char) channel.message().getByte();
                        channel.endMessage();
                        if (failure != null) {
                            throw failure;
                        }
                        return;
                    }
                    default -> handleAsynchronous(tag);
                }
            }
        } catch (IOException e) {
            throw new SQLNonTransientConnectionException(
                    "the connection broke while running a statement", "08006", e);
        }
    }

    // ---- extended protocol -----------------------------------------------

    /**
     * Announces a prepared plan; it is parsed with its first execution.
     *
     * <p>{@code Parse} on its own is a round trip, and the server has nothing
     * to say about it that the first execution would not carry anyway. Sent
     * together with {@code Bind} and {@code Execute} it costs nothing - and
     * that halves what the first use of a prepared statement costs, which is
     * the normal case wherever a pool hands out fresh connections.
     */
    public void parseLater(String name, String sql) throws SQLException {
        if (!defer) {
            fields = parse(name, sql);
            return;
        }
        this.pendingParseName = name;
        this.pendingParseSql = sql;
    }

    /** Whether a plan is announced but not yet parsed. */
    public boolean hasPendingParse() {
        return pendingParseSql != null;
    }

    private int writePendingParse() {
        if (pendingParseSql == null) {
            return 0;
        }
        WireBuffer out = channel.begin(PgProtocol.PARSE);
        out.putCString(pendingParseName);
        out.putCString(pendingParseSql);
        out.putShort((short) 0);              // Typen ueberlaesst der Treiber dem Server
        channel.end();

        out = channel.begin(PgProtocol.DESCRIBE);
        out.putByte((byte) 'S');
        out.putCString(pendingParseName);
        channel.end();

        // No Sync of its own. PostgreSQL flushes its output at every Sync, so
        // a second one turns what the driver sends in a single write into two
        // or three separate answers on the wire - measured as three socket
        // reads for the first use of a statement where one is enough, some
        // thirty microseconds on a loopback connection. The Sync that closes
        // the caller's own block covers these answers too: ParseComplete,
        // ParameterDescription and RowDescription all pass through
        // runUntilReady on their way to it.
        //
        // It is also the better behaviour on failure. With two Syncs a broken
        // statement is reported twice - once for the Parse, then again for a
        // Bind against a statement that was never created. With one, the
        // server skips to the Sync and the caller gets the one error that
        // actually happened.
        pendingParseSql = null;
        pendingParseName = null;
        return 0;
    }

    /**
     * Parses now and answers what the statement will return.
     *
     * <p>A named plan stays in the session until {@link #closeStatement(String)}.
     * That is where the gain over the simple protocol lies: the server parses
     * and plans once, not on every execution. Whoever does not need the answer
     * right away uses {@link #parseLater} and pays nothing for it.
     *
     * @return the columns the statement returns - empty for INSERT/UPDATE
     */
    public List<Field> parse(String name, String sql) throws SQLException {
        try {
            WireBuffer out = channel.begin(PgProtocol.PARSE);
            out.putCString(name);
            out.putCString(sql);
            out.putShort((short) 0);          // Typen ueberlaesst der Treiber dem Server
            channel.end();

            out = channel.begin(PgProtocol.DESCRIBE);
            out.putByte((byte) 'S');
            out.putCString(name);
            channel.end();

            channel.begin(PgProtocol.SYNC);
            channel.end();
            channel.flush();

            fields = List.of();
            runUntilReady(null);
            return fields;
        } catch (IOException e) {
            throw new SQLNonTransientConnectionException(
                    "the connection broke while preparing a statement", "08006", e);
        }
    }

    /**
     * Runs a prepared statement, asking the server to describe the result.
     *
     * @param maxRows 0 = all rows; otherwise the server stops after that many
     */
    public void bindAndExecute(String statement, PgParameters parameters, int maxRows,
                               RowHandler handler) throws SQLException {
        bindAndExecute(statement, parameters, maxRows, handler, null);
    }

    /**
     * Runs a prepared statement whose result shape is already known.
     *
     * <p>{@code known} is the row description from the first execution. With
     * it the {@code DESCRIBE} is left out and the server stops answering with
     * the whole description on every execution - which is where the column
     * names and the {@code Field} objects were being rebuilt each time, some
     * five hundred bytes per execution measured on a one-row query.
     *
     * @param known the fields of an earlier execution, or {@code null} to ask
     * @param maxRows 0 = all rows; otherwise the server stops after that many
     */
    public void bindAndExecute(String statement, PgParameters parameters, int maxRows,
                               RowHandler handler, List<Field> known) throws SQLException {
        // Anything that really needs an answer sends the block first - that
        // is the promise of the pipeline: it saves round trips nobody waited
        // for, never a value somebody asked for.
        flushPipeline();
        try {
            int carried = writePending() + writePendingParse();
            WireBuffer out = channel.begin(PgProtocol.BIND);
            out.putCString("");                       // the unnamed portal
            out.putCString(statement);
            parameters.write(out);
            out.putShort((short) 0);                  // results as text
            channel.end();

            if (known == null) {
                // Only the first time. Parse already described the statement,
                // and a prepared statement's result shape cannot change under
                // it: PostgreSQL refuses the execution with "cached plan must
                // not change result type" rather than answering with a
                // different one. That guarantee is what makes it safe to stop
                // asking - and it holds today too, because the plan has been
                // cached on the server all along.
                out = channel.begin(PgProtocol.DESCRIBE);
                out.putByte((byte) 'P');
                out.putCString("");
                channel.end();
            }

            out = channel.begin(PgProtocol.EXECUTE);
            out.putCString("");
            out.putInt(maxRows);
            channel.end();

            channel.begin(PgProtocol.SYNC);
            channel.end();
            channel.flush();

            for (int i = 0; i < carried; i++) {
                runUntilReady(null);              // the answers to what rode along
            }
            if (known != null) {
                // After the carried answers, before the rows: without a
                // DESCRIBE nothing sets this, and what stands here otherwise
                // belongs to whatever ran last on this connection.
                fields = known;
            }
            runUntilReady(handler);
        } catch (IOException e) {
            throw new SQLNonTransientConnectionException(
                    "the connection broke while running a prepared statement", "08006", e);
        }
    }

    /**
     * Starts a stretch in which the receive buffer must not move.
     *
     * <p>While it lasts, whoever reads the rows may write down <b>where</b>
     * each value is instead of copying it out. The buffer therefore grows to
     * hold the whole answer - the same memory a copy would have needed, minus
     * the copy.
     */
    public void beginCollect() {
        channel.keepBuffer(true);
    }

    /** Ends it; from here the buffer may be moved and reused again. */
    public void endCollect() {
        channel.keepBuffer(false);
    }

    /**
     * Hands the buffer holding the answer over and takes another in its place.
     *
     * @param spare an empty buffer the session reads into from now on
     * @return the buffer with the rows in it
     */
    public WireBuffer exchangeBuffer(WireBuffer spare) {
        return channel.exchange(spare);
    }

    /**
     * Runs a statement with the <b>next</b> one, not now.
     *
     * <p>Everything that only <i>sets</i> something - opening a transaction,
     * the isolation level, read-only, releasing a prepared plan - costs a full
     * round trip of its own if it is sent on its own, and in that round trip
     * the database does nothing. Sent along with the statement that follows,
     * it is free: two messages in one flush, one wait for the answer.
     *
     * <p>That is what turns the most common shape there is - a
     * {@code @Transactional} method that runs one statement - from seven round
     * trips into two. A framework opens a transaction, sets the isolation
     * level, sets read-only, runs the statement, commits, and puts everything
     * back afterwards; only two of those seven need an answer.
     *
     * <p>Only statements whose answer nobody looks at go through here.
     */
    public void runLater(String sql) throws SQLException {
        if (!defer) {
            execute(sql);
            return;
        }
        // In front of a waiting BEGIN, not behind it. A setting that lands
        // inside the transaction it was meant to configure is a setting that
        // does nothing - "set session characteristics" changes the default for
        // the next transaction, not for the running one.
        int begin = pending.indexOf("BEGIN");
        if (begin < 0) {
            pending.add(sql);
        } else {
            pending.add(begin, sql);
        }
        if (pending.size() > PENDING_LIMIT) {
            // Somebody is only ever setting and never running. Send them, or
            // the list grows without bound.
            flushPending();
        }
    }

    /** Opens a transaction with the next statement. */
    public void beginLater() throws SQLException {
        if (!defer) {
            execute("BEGIN");
            return;
        }
        if (!pending.contains("BEGIN")) {
            pending.add("BEGIN");
        }
    }

    /**
     * Takes back a transaction that was announced but never opened.
     *
     * @return whether there was one - then nothing ran in it and there is
     *         nothing to commit
     */
    public boolean cancelPendingBegin() {
        return pending.remove("BEGIN");
    }

    /** Whether a transaction was announced but not yet opened. */
    public boolean hasPendingBegin() {
        return pending.contains("BEGIN");
    }

    /** Whether anything at all is waiting to ride along. */
    public boolean hasPending() {
        return !pending.isEmpty() || !pendingCloses.isEmpty();
    }

    /** Sends what is waiting right now, for whoever cannot wait. */
    public void flushPending() throws SQLException {
        if (pending.isEmpty() && pendingCloses.isEmpty()) {
            return;
        }
        try {
            int carried = writePending();
            if (carried == 0) {
                // Only Closes went out. They answer with CloseComplete, and
                // nothing would collect that without a Sync to close the block.
                channel.begin(PgProtocol.SYNC);
                channel.end();
                carried = 1;
            }
            channel.flush();
            for (int i = 0; i < carried; i++) {
                runUntilReady(null);
            }
        } catch (IOException e) {
            throw new SQLNonTransientConnectionException(
                    "the connection broke while setting the session up", "08006", e);
        }
    }

    /**
     * Writes everything pending into the same buffer.
     *
     * @return how many extra answers have to be read
     */
    private int writePending() {
        int carried = pending.size();
        for (String sql : pending) {
            WireBuffer out = channel.begin(PgProtocol.QUERY);
            out.putCString(sql);
            channel.end();
        }
        pending.clear();
        writePendingCloses();
        return carried;
    }

    /**
     * Releases plans nobody needs any more - with the protocol's own Close.
     *
     * <p>Not with {@code deallocate}, which is what this used to send. The two
     * are not interchangeable: {@code DEALLOCATE} on a name the server does not
     * know is an error, while Close on an unknown name is explicitly not one.
     * That difference was a real defect. A prepared statement whose deferred
     * Parse had failed - a typo in the SQL is enough - was still deallocated
     * when it was closed, and because that rides along with the next statement,
     * the error surfaced on an innocent query some way away: {@code 26000,
     * prepared statement "seclume_1" does not exist}. To the pool that is a
     * connection failing a health check for no reason anybody could see.
     *
     * <p>Close needs no Sync of its own; the CloseComplete travels with
     * whatever answer the block is waiting for anyway.
     */
    private void writePendingCloses() {
        for (String name : pendingCloses) {
            WireBuffer out = channel.begin(PgProtocol.CLOSE);
            out.putByte((byte) 'S');
            out.putCString(name);
            channel.end();
        }
        pendingCloses.clear();
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
     * <p>See {@link space.seclume.Pipeline} for what this is for.
     * The mechanics are the ones the batch already uses: {@code Bind} and
     * {@code Execute} go out back to back and only the group is closed with a
     * {@code Sync}. New is only the bookkeeping - which statement was the
     * n-th, so that a failure can say which one it was.
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
     * <p>The parameters are written to the wire <b>now</b> - they live in a
     * buffer the statement reuses, so keeping them for later would mean
     * copying them. Only the sending waits.
     *
     * @return {@link java.sql.Statement#SUCCESS_NO_INFO}, because the count is
     *         genuinely not known yet and inventing one would be a lie
     */
    public int pipelineBindAndExecute(String statement, PgParameters parameters, String sql)
            throws SQLException {
        if (pipelineGroup == 0) {
            pipelineCarried = writePending() + writePendingParse();
        }
        writeBindAndExecute(statement, parameters);
        pipelineGroup++;
        pipelineSql.add(sql);
        // The group is bounded for the same reason the batch is: if both sides
        // keep writing, both buffers fill and both block.
        if (pipelineGroup >= PIPELINE_ROWS || channel.pending() >= PIPELINE_BYTES) {
            flushPipeline();
        }
        return java.sql.Statement.SUCCESS_NO_INFO;
    }

    /**
     * Sends what is buffered and reads the answers.
     *
     * <p>Called by the block at its end - and by the driver itself before
     * anything that really needs an answer. That is the whole promise: the
     * block saves round trips nobody was waiting for and never a value
     * somebody asked for.
     */
    public void flushPipeline() throws SQLException {
        if (pipelineGroup == 0) {
            return;
        }
        int group = pipelineGroup;
        pipelineGroup = 0;                        // before reading: a failure ends the group too
        try {
            channel.begin(PgProtocol.SYNC);
            channel.end();
            channel.flush();
            for (int i = 0; i < pipelineCarried; i++) {
                runUntilReady(null);              // the answers to what rode along
            }
            pipelineCarried = 0;
            readPipelineAnswers(group, pipelineCount);
        } catch (IOException e) {
            throw new SQLNonTransientConnectionException(
                    "the connection broke while sending the pipeline", "08006", e);
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

    /**
     * The answers of one group, and which statement a failure belongs to.
     *
     * <p>After an error the server skips the rest of the group - so the
     * statements behind the failed one did <b>not</b> run, and the message
     * says so. "Something in the block went wrong" is not something anybody
     * can act on.
     */
    private void readPipelineAnswers(int expected, int groupStart)
            throws IOException, SQLException {
        int seen = 0;
        SQLException failure = null;
        int failedAt = -1;
        while (true) {
            byte tag = channel.nextMessage();
            switch (tag) {
                case PgProtocol.ROW_DESCRIPTION -> readRowDescription();
                case PgProtocol.DATA_ROW -> {
                    readDataRow();                // a write that returns rows: not kept
                    channel.endMessage();
                }
                case PgProtocol.COMMAND_COMPLETE -> {
                    lastCommandTag = channel.message().readCString();
                    if (seen < expected) {
                        rememberPipelineCount(affectedRowsOf(lastCommandTag));
                        seen++;
                    }
                    channel.endMessage();
                }
                case PgProtocol.ERROR_RESPONSE -> {
                    SQLException error = readError();
                    if (failure == null) {
                        failure = error;
                        failedAt = seen;
                    }
                }
                case PgProtocol.READY_FOR_QUERY -> {
                    transactionStatus = (char) channel.message().getByte();
                    channel.endMessage();
                    if (failure != null) {
                        throw pipelineFailure(failure, groupStart + failedAt,
                                expected - failedAt - 1);
                    }
                    return;
                }
                case PgProtocol.PARSE_COMPLETE, PgProtocol.BIND_COMPLETE,
                     PgProtocol.CLOSE_COMPLETE, PgProtocol.EMPTY_QUERY,
                     PgProtocol.PORTAL_SUSPENDED, PgProtocol.PARAMETER_DESCRIPTION,
                     PgProtocol.NO_DATA -> channel.endMessage();
                default -> handleAsynchronous(tag);
            }
        }
    }

    /**
     * @param at      which statement of the whole block it was, counted from 0
     * @param skipped how many behind it the server threw away unread
     */
    private SQLException pipelineFailure(SQLException cause, int at, int skipped) {
        String statement = at >= 0 && at < pipelineSql.size()
                ? pipelineSql.get(at) : null;
        String message = "statement " + (at + 1) + " of the pipeline block failed"
                + (statement == null ? "" : " (" + shorten(statement) + ")")
                + ": " + cause.getMessage()
                + (skipped > 0 ? " - the " + skipped + " statement(s) after it were skipped "
                        + "by the server and did not run" : "");
        SQLException failure = new SQLException(message, cause.getSQLState(),
                cause.getErrorCode(), cause);
        return failure;
    }

    private static String shorten(String sql) {
        String text = sql == null ? "" : sql.strip();
        return text.length() <= 80 ? text : text.substring(0, 77) + "...";
    }

    private void rememberPipelineCount(long count) {
        if (pipelineCount == pipelineCounts.length) {
            pipelineCounts = java.util.Arrays.copyOf(pipelineCounts, pipelineCounts.length * 2);
        }
        pipelineCounts[pipelineCount++] = count;
    }


    /**
     * Whether the server stopped at the row limit and the portal is still open.
     *
     * <p>That is what block cursors are made of: an {@code Execute} with a
     * limit answers with {@code PortalSuspended} instead of
     * {@code CommandComplete}, and the next {@code Execute} on the same portal
     * carries on where it left off.
     */
    public boolean isPortalSuspended() {
        return portalSuspended;
    }

    /**
     * Reads the next block from the portal that is still open.
     *
     * <p>Only meaningful after an execution that ended suspended. The portal
     * is the unnamed one, which lives until the end of the transaction - and
     * that is why a fetch size only works inside one. Outside, the
     * {@code Sync} ends the implicit transaction and takes the portal with it.
     */
    public void executeMore(int rows, RowHandler handler) throws SQLException {
        flushPipeline();
        try {
            WireBuffer out = channel.begin(PgProtocol.EXECUTE);
            out.putCString("");
            out.putInt(rows);
            channel.end();
            channel.begin(PgProtocol.SYNC);
            channel.end();
            channel.flush();
            runUntilReady(handler);
        } catch (IOException e) {
            throw new SQLNonTransientConnectionException(
                    "the connection broke while reading the next block of rows", "08006", e);
        }
    }

    /**
     * Closes a portal that is still open - a result set given back early.
     *
     * <p>Without this the rest of the rows would sit in the server until the
     * transaction ends, and the next statement on the unnamed portal would
     * silently throw them away.
     */
    public void closePortal() throws SQLException {
        if (!portalSuspended) {
            return;
        }
        try {
            WireBuffer out = channel.begin(PgProtocol.CLOSE);
            out.putByte((byte) 'P');
            out.putCString("");
            channel.end();
            channel.begin(PgProtocol.SYNC);
            channel.end();
            channel.flush();
            runUntilReady(null);
            portalSuspended = false;
        } catch (IOException e) {
            throw new SQLNonTransientConnectionException(
                    "the connection broke while closing a portal", "08006", e);
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
     * <p>This is the difference between a batch and a loop. Sent row by row,
     * every row costs a full round trip: at five hundred rows that is five
     * hundred times the latency of the network, and the database is idle for
     * almost all of it. Here the {@code Bind} and {@code Execute} messages go
     * out back to back and only the group is closed with a {@code Sync} - one
     * round trip for a whole group instead of one per row.
     *
     * <p>The group is bounded, and not out of caution alone: if the client
     * keeps writing while the server keeps answering, both buffers can fill up
     * and both sides block - a deadlock in which neither is at fault. A group
     * of at most {@value #PIPELINE_ROWS} rows or {@value #PIPELINE_BYTES}
     * bytes stays far below what the two socket buffers hold.
     */
    public long[] bindAndExecuteBatch(String statement, PgParameters parameters, int count,
                                      BatchBinder binder) throws SQLException {
        // Anything that really needs an answer sends the block first - that
        // is the promise of the pipeline: it saves round trips nobody waited
        // for, never a value somebody asked for.
        flushPipeline();
        long[] counts = new long[count]; // seclume-allow: update counts, not a secret
        int at = 0;
        int carried = 0;
        try {
            while (at < count) {
                int start = at;
                int sent = 0;
                if (at == 0) {
                    carried = writePending() + writePendingParse();
                }
                while (at < count && sent < PIPELINE_ROWS
                        && channel.pending() < PIPELINE_BYTES) {
                    binder.bind(at);
                    writeBindAndExecute(statement, parameters);
                    at++;
                    sent++;
                }
                channel.begin(PgProtocol.SYNC);
                channel.end();
                channel.flush();
                for (int i = 0; i < carried; i++) {
                    runUntilReady(null);          // the answers to what rode along
                }
                carried = 0;
                readBatchAnswers(counts, start, sent);
            }
        } catch (IOException e) {
            throw new SQLNonTransientConnectionException(
                    "the connection broke while running a batch", "08006", e);
        }
        return counts;
    }

    /** Bind and Execute for one row - without the Sync that would end the group. */
    private void writeBindAndExecute(String statement, PgParameters parameters)
            throws SQLException {
        WireBuffer out = channel.begin(PgProtocol.BIND);
        out.putCString("");                       // the unnamed portal
        out.putCString(statement);
        parameters.write(out);
        out.putShort((short) 0);                  // the result in text format
        channel.end();

        out = channel.begin(PgProtocol.EXECUTE);
        out.putCString("");
        out.putInt(0);
        channel.end();
    }

    /**
     * Reads the answers of one group.
     *
     * <p>One {@code CommandComplete} per row, in order, and a
     * {@code ReadyForQuery} at the end. An error is kept and thrown after the
     * {@code ReadyForQuery}: the server skips the rest of the group by itself,
     * and a client that breaks off early leaves the session in a state the
     * next call no longer understands.
     */
    private void readBatchAnswers(long[] counts, int from, int expected)
            throws IOException, SQLException {
        int index = from;
        SQLException failure = null;
        while (true) {
            byte tag = channel.nextMessage();
            switch (tag) {
                case PgProtocol.ROW_DESCRIPTION -> readRowDescription();
                case PgProtocol.DATA_ROW -> {
                    readDataRow();                // a batch of selects: rows are not kept
                    channel.endMessage();
                }
                case PgProtocol.COMMAND_COMPLETE -> {
                    lastCommandTag = channel.message().readCString();
                    if (index < from + expected && index < counts.length) {
                        counts[index++] = affectedRowsOf(lastCommandTag);
                    }
                    channel.endMessage();
                }
                case PgProtocol.ERROR_RESPONSE -> {
                    SQLException error = readError();
                    if (failure == null) {
                        failure = error;
                    }
                }
                case PgProtocol.READY_FOR_QUERY -> {
                    transactionStatus = (char) channel.message().getByte();
                    channel.endMessage();
                    if (failure != null) {
                        throw failure;
                    }
                    return;
                }
                case PgProtocol.PARSE_COMPLETE, PgProtocol.BIND_COMPLETE,
                     PgProtocol.CLOSE_COMPLETE, PgProtocol.EMPTY_QUERY,
                     PgProtocol.PORTAL_SUSPENDED, PgProtocol.PARAMETER_DESCRIPTION,
                     PgProtocol.NO_DATA -> channel.endMessage();
                default -> handleAsynchronous(tag);
            }
        }
    }

    /**
     * The number at the end of a command tag - {@code INSERT 0 1} means one
     * row. Parsed here rather than in the JDBC layer because the batch has to
     * report a count per row and never builds a result out of it.
     */
    private static long affectedRowsOf(String tag) {
        if (tag == null || tag.isEmpty()) {
            return 0;
        }
        int space = tag.lastIndexOf(' ');
        if (space < 0) {
            return 0;
        }
        long value = 0;
        for (int i = space + 1; i < tag.length(); i++) {
            int digit = tag.charAt(i) - '0';
            if (digit < 0 || digit > 9) {
                return 0;
            }
            value = value * 10 + digit;
        }
        return value;
    }

    /**
     * Throws away what was queued but never sent.
     *
     * <p>Used by a rollback: everything waiting - settings, a deallocate for a
     * statement that was closed - belonged to the transaction being discarded.
     * Sending it first would be worse than pointless: after a failed statement
     * PostgreSQL refuses everything until the transaction ends, so the queue
     * would fail as a whole and hide the rollback behind its own error.
     */
    public void discardPending() {
        pending.clear();
        pendingParseName = null;
        pendingParseSql = null;
    }

    /**
     * Releases a prepared plan - with the next statement, not now.
     *
     * <p>Closing a statement returns nothing, so nobody has to wait for the
     * confirmation. It still arrives and is still checked, in the same round
     * trip as the next statement.
     */
    public void closeStatementLater(String name) throws SQLException {
        if (!defer) {
            closeStatement(name);
            return;
        }
        pendingCloses.add(name);
        if (pendingCloses.size() > PENDING_LIMIT) {
            // Somebody is only ever closing and never running.
            flushPending();
        }
    }

    /** Releases a prepared plan in the server again. */
    public void closeStatement(String name) throws SQLException {
        try {
            WireBuffer out = channel.begin(PgProtocol.CLOSE);
            out.putByte((byte) 'S');
            out.putCString(name);
            channel.end();
            channel.begin(PgProtocol.SYNC);
            channel.end();
            channel.flush();
            runUntilReady(null);
        } catch (IOException e) {
            throw new SQLNonTransientConnectionException(
                    "the connection broke while closing a statement", "08006", e);
        }
    }

    /**
     * Processes the answers up to the ReadyForQuery.
     *
     * <p>An error is remembered and only thrown at the end: after an
     * ErrorResponse the server still sends a ReadyForQuery, and breaking off
     * before that leaves the session in a state the next call no longer
     * understands.
     */
    private void runUntilReady(RowHandler handler) throws IOException, SQLException {
        SQLException failure = null;
        portalSuspended = false;
        while (true) {
            byte tag = channel.nextMessage();
            switch (tag) {
                case PgProtocol.ROW_DESCRIPTION -> readRowDescription();
                case PgProtocol.NO_DATA -> {
                    fields = List.of();
                    channel.endMessage();
                }
                case PgProtocol.DATA_ROW -> {
                    Row row = readDataRow();
                    if (handler != null && failure == null) {
                        // See above: the answer is read to the end even when
                        // the handler has already said no.
                        try {
                            handler.row(row);
                        } catch (SQLException e) {
                            failure = e;
                        }
                    }
                    channel.endMessage();
                }
                case PgProtocol.COMMAND_COMPLETE -> {
                    lastCommandTag = channel.message().readCString();
                    channel.endMessage();
                }
                case PgProtocol.PORTAL_SUSPENDED -> {
                    // The row limit was reached: the portal stays open and the
                    // next Execute carries on where this one stopped.
                    portalSuspended = true;
                    channel.endMessage();
                }
                case PgProtocol.PARSE_COMPLETE, PgProtocol.BIND_COMPLETE,
                     PgProtocol.CLOSE_COMPLETE, PgProtocol.EMPTY_QUERY,
                     PgProtocol.PARAMETER_DESCRIPTION ->
                        channel.endMessage();
                case PgProtocol.ERROR_RESPONSE -> {
                    SQLException error = readError();
                    if (failure == null) {
                        failure = error;
                    }
                }
                case PgProtocol.READY_FOR_QUERY -> {
                    transactionStatus = (char) channel.message().getByte();
                    channel.endMessage();
                    if (failure != null) {
                        throw failure;
                    }
                    return;
                }
                default -> handleAsynchronous(tag);
            }
        }
    }

    /** Short form for statements without a result. */
    public void execute(String sql) throws SQLException {
        // Anything that really needs an answer sends the block first - that
        // is the promise of the pipeline: it saves round trips nobody waited
        // for, never a value somebody asked for.
        flushPipeline();

        simpleQuery(sql, null);
    }

    private void readRowDescription() {
        WireBuffer in = channel.message();
        int count = in.getShort() & 0xffff;
        List<Field> list = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            String name = in.readCString();
            list.add(new Field(name, in.getInt(), in.getShort(), in.getInt(),
                    in.getShort(), in.getInt(), in.getShort()));
        }
        fields = List.copyOf(list);
        channel.endMessage();
    }

    /**
     * Reads one row - into the same window every time.
     *
     * <p>A {@link Row} is only valid until the next one is read, so there is
     * no reason to build a new one: that would be the window plus its two
     * index arrays, three objects per row, for a result the caller walks once.
     */
    private Row readDataRow() {
        WireBuffer in = channel.message();
        int count = in.getShort() & 0xffff;
        if (rowOffsets.length < count) {
            rowOffsets = new int[count]; // seclume-allow: column offsets of a row, not a secret
            rowLengths = new int[count]; // seclume-allow: column lengths of a row, not a secret
        }
        for (int i = 0; i < count; i++) {
            int length = in.getInt();
            rowLengths[i] = length;
            if (length >= 0) {
                rowOffsets[i] = in.position();
                in.skip(length);
            } else {
                rowOffsets[i] = -1;
            }
        }
        if (row == null) {
            row = new Row(in, fields, rowOffsets, rowLengths);
        }
        row.reset(in, fields, rowOffsets, rowLengths, count);
        return row;
    }

    /** ParameterStatus, Notice, Notification - everything that may arrive at any time. */
    private void handleAsynchronous(byte tag) {
        WireBuffer in = channel.message();
        switch (tag) {
            case PgProtocol.PARAMETER_STATUS -> {
                String name = in.readCString();
                String value = in.readCString();
                parameters.put(name, value);
            }
            case PgProtocol.BACKEND_KEY_DATA -> {
                backendProcessId = in.getInt();
                backendSecretKey = in.getInt();
            }
            case PgProtocol.NOTICE_RESPONSE, PgProtocol.NOTIFICATION_RESPONSE -> {
                // The server's notices are of no interest here yet; they
                // belong on SQLWarning or the listener later.
            }
            default -> {
                // Unknown messages are skipped - the server may extend the
                // protocol, and an unknown tag is not an error.
            }
        }
        channel.endMessage();
    }

    /** Reads an ErrorResponse into a {@link PgException}. */
    private PgException readError() {
        WireBuffer in = channel.message();
        String message = "unknown error";
        String sqlState = "XX000";
        String severity = "ERROR";
        String detail = null;
        while (channel.messageRemaining() > 0) {
            byte type = in.getByte();
            if (type == 0) {
                break;
            }
            String value = in.readCString();
            switch (type) {
                case 'M' -> message = value;
                case 'C' -> sqlState = value;
                case 'S', 'V' -> severity = value;
                case 'D' -> detail = value;
                default -> {
                    // Position, file, line and the remaining fields are of
                    // no use to anybody here.
                }
            }
        }
        channel.endMessage();
        return new PgException(message, sqlState, severity, detail);
    }

    private SQLException protocolError(String message) {
        return new SQLException(message, "08P01");
    }

    /** The database this session is connected to. */
    public String database() {
        return database;
    }

    /** The server parameters from the login ({@code server_version} and others). */
    public Map<String, String> parameters() {
        return Map.copyOf(parameters);
    }

    public List<Field> fields() {
        return fields;
    }

    public String lastCommandTag() {
        return lastCommandTag;
    }

    /**
     * The method this session was logged in with - {@code scram-sha-256},
     * {@code md5}, {@code password} or {@code trust}. Useful in bug reports and
     * the only honest way to show in a test which path actually ran.
     */
    public String authenticationMethod() {
        return authenticationMethod;
    }

    public char transactionStatus() {
        return transactionStatus;
    }

    public int backendProcessId() {
        return backendProcessId;
    }

    public boolean isOpen() {
        return channel.isOpen();
    }

    /** The channel underneath - for tests that have to look at the transport. */
    PgChannel channel() {
        return channel;
    }

    /**
     * Whether this connection could be handed to another machine.
     *
     * <p>Two conditions. The descriptor has to be ours - {@link
     * #migrateInPlace()} explains why - and the encryption, if there is any,
     * has to be state we can write down.
     *
     * <p><b>The second condition used to be "no encryption at all", and that
     * is no longer the same thing.</b> It was true while the drivers reached
     * TLS only through an {@code SSLEngine}, which hands out neither the keys
     * nor the record sequence numbers - no method of {@code SSLSession} or
     * {@code SSLEngine} is named for any of them, by design. Such a
     * connection can be frozen and thawed <b>in this process</b>, where the
     * engine is an object that stays put, and cannot leave it.
     *
     * <p>On {@code tlsStack=seclume} the state is ours, in memory we
     * allocated, and it travels. So the honest answer now depends on which
     * stack carries the connection rather than on whether it is encrypted,
     * and the difference is asked of the layer itself - see
     * {@link space.seclume.internal.TlsLayer#movable()}.
     *
     * <p>A method rather than a sentence in a document, so that the code
     * refuses rather than the reader remembers.
     */
    public boolean canMoveBetweenNodes() {
        // the alternate transport, developed separately
                && channel.encryptionCanTravel();
    }

    /**
     * Freezes this connection and thaws it again on a new socket.
     *
      * <p>Within one process: the
     * same session, the same server backend, a different descriptor. Nothing
     * about the protocol state is serialised, because nothing about it moves -
     * the parser, the prepared plans and the buffers are objects that never
     * learn anything happened. What moves is the kernel's control block.
     *
     * <p>Both halves of the quiescent point are checked first, and they are two
     * different things: {@link PgChannel#isIdle()} says this driver has nothing
     * half-written or half-read, and {@code isQuiescent()} says the kernel has
     * nothing unacknowledged or unread. A connection can satisfy one and not
     * the other, and taking it apart then loses bytes silently.
     *
     * <p>Order, and it is the one PoC 0 paid for: thaw first, close the old
     * socket afterwards. The other way round, a retransmission from the server
     * arrives at a host with no socket for it and is answered with a RST.
     *
     * @throws SQLException if this connection is not on an FFM transport, is
     *                      not idle, or the kernel refuses - CAP_NET_ADMIN is
      * the descriptor itself
     */
    public void migrateInPlace() throws SQLException {
        // the alternate transport, developed separately
                current)) {
            throw new SQLException("moving a connection needs a descriptor of our own - "
                    + "open it with transport=ffm", "0A000");
        }
        try {
            if (!channel.isIdle()) {
                throw new SQLException("the driver is not idle on this connection", "25000");
            }
        // connection state, developed separately
            // The old socket has to go first, and this is the one place where
            // that is true. Two sockets cannot hold the same four-tuple: the
            // kernel refuses the thaw with EADDRNOTAVAIL while the old one is
            // still there. Measured, not reasoned - errno 99, every time.
            //
            // Closing first is what PoC 0 warned against, and the warning still
            // stands where it was made: across nodes, the address must stop
            // routing to the old host before it lets go, or a retransmission
            // finds no socket and is answered with a RST. Here the gap between
            // close and thaw is microseconds against a retransmission timer of
            // two hundred milliseconds, and the socket is closed in repair
            // mode, which sends nothing. A move between nodes does not get to
            // use this shortcut.
            current.close();
        // the alternate transport, developed separately
        // the alternate transport, developed separately
            channel.replaceTransport(thawed);
        } catch (IOException e) {
            throw new SQLNonTransientConnectionException(
                    "the connection could not be moved: " + e.getMessage(), "08006", e);
        }
    }

    /** Tells the server and hangs up. */
    @Override
    public void close() {
        try {
            if (channel.isOpen()) {
                channel.begin(PgProtocol.TERMINATE);
                channel.end();
                channel.flush();
            }
        } catch (IOException ignored) {
            // When hanging up an error has no consequences.
        } finally {
            channel.close();
        }
    }

    /**
     * What an authenticated stream is, once it has left its session.
     *
     * <p>Three facts beside the socket, and each is here because a decoder
     * cannot derive it: the server's {@code ParameterStatus} set - client
     * encoding, date style, whether timestamps are integers - which a
     * successor would otherwise have to guess and would guess wrong about
     * dates; the backend's process id and secret, without which nothing can
     * cancel a running query; and nothing else. The transaction status is not
     * in here on purpose: it is in the next {@code ReadyForQuery}, which the
     * stream carries anyway.
     *
     * @param stream the socket, still logged in, positioned at a message
     *               boundary
     */
    public record Detached(space.seclume.internal.Transport stream,
                           java.util.Map<String, String> parameters,
                           int backendProcessId, int backendSecretKey) {
    }

    /**
     * Hands the authenticated stream over and finishes this session object.
     *
     * <p>For handing a logged-in connection to another holder: the login
     * happens once, in the process that has the credential, and whoever
     * receives the stream never needs one. What that is used for is not this
     * class's business; what it owes is a stream that can be picked up, and
     * {@link #resume} is the other end of it.
     *
     * <p>Two refusals rather than two surprises:
     *
     * <ul>
     *   <li>not at a quiescent point - a stream with an answer half read is
     *       not something anybody else can take over, and the check is the
     *       same {@code isIdle} a freeze uses;
     *   <li>encrypted - the keys are in this process and the bytes on that
     *       socket are TLS records. Handing them on would need the keys to
     *       travel too, which is a different decision from this one. TLS to
     *       the database therefore terminates where the login happened.
     * </ul>
     *
     * <p>Afterwards this session is finished: the channel reports itself
     * closed, and the transport belongs to the caller.
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
        space.seclume.internal.Transport stream = channel.transport();
        java.util.Map<String, String> snapshot = java.util.Map.copyOf(parameters);
        channel.release();
        return new Detached(stream, snapshot, backendProcessId, backendSecretKey);
    }

    /** Cancelling a running query needs this key. */
    int backendSecretKey() {
        return backendSecretKey;
    }
}
