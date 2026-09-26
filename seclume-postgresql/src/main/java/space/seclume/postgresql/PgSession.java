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
import space.seclume.secret.NoSecretProvider;
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
                           space.seclume.tls.ClientIdentity identity,
                           boolean directTls) {

        /** Asking for TLS first, as every server before PostgreSQL 17 needs. */
        public Settings(String host, int port, String database, String user,
                        SecretProvider secret, String applicationName,
                        int connectTimeoutMillis, HostList hosts, ResultLimit resultLimit,
                        TlsMode tls, space.seclume.internal.jdbc.TlsStack tlsStack,
                        space.seclume.tls.ClientIdentity identity) {
            this(host, port, database, user, secret, applicationName, connectTimeoutMillis,
                    hosts, resultLimit, tls, tlsStack, identity, false);
        }

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
                    identity, directTls);
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
    /**
     * How this connection was made, kept for {@link #cancel()}.
     *
     * <p>Null on a session that was resumed rather than opened: whoever handed
     * the stream over knows where it came from and this object does not, so
     * cancellation on a resumed session says it cannot rather than guessing.
     */
    private Settings settings;
    private char transactionStatus = 'I';
    /** Settings that ride along with the next statement - see runLater. */
    private final List<String> pending = new ArrayList<>();
    /** Plans to be released with the next block - see writePendingCloses. */
    private final List<String> pendingCloses = new ArrayList<>();
    /**
     * Plans announced and not yet parsed, by statement name - see parseLater.
     *
     * <p>A map and not one slot. With one slot, a second prepareStatement
     * before the first one ran replaced the first one's Parse - which then
     * bound against a name the server had never seen: "prepared statement
     * seclume_3 does not exist". And whichever statement ran next sent
     * whatever Parse was waiting, its own or another's. Each statement now
     * sends its own Parse with its own first execution, and nothing else's.
     * Found by Liquibase, which prepares two statements before it runs either.
     */
    private final java.util.Map<String, String> pendingParses = new java.util.LinkedHashMap<>();
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
        return resume(stream, parameters, backendProcessId, backendSecretKey, null);
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
    public static PgSession resume(space.seclume.internal.Transport stream,
                                   java.util.Map<String, String> parameters,
                                   int backendProcessId, int backendSecretKey,
                                   space.seclume.internal.TlsLayer tls) {
        PgSession session = new PgSession(tls == null
                ? PgChannel.over(stream)
                : PgChannel.over(stream, tls));
        session.parameters.putAll(parameters);
        session.backendProcessId = backendProcessId;
        session.backendSecretKey = backendSecretKey;
        return session;
    }

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
        simpleQuery(sql, row -> {
            if (answer[0] == null && row.columnCount() > 0 && !row.isNull(0)) {
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
    private static final HostList.Roles<PgSession> ROLES = new HostList.Roles<>() {

        @Override
        public space.seclume.internal.jdbc.ServerRole of(PgSession session) throws SQLException {
            try {
                return space.seclume.internal.jdbc.ServerRole.read(session.askOneValue(
                        space.seclume.internal.jdbc.ServerRole.POSTGRESQL));
            } catch (SQLException refused) {
                return space.seclume.internal.jdbc.ServerRole.UNKNOWN;
            }
        }

        @Override
        public void giveBack(PgSession session) {
            session.close();
        }
    };

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
        // With several servers and a preference in the URL, each one is asked
        // what it is before its connection is kept - see TargetServer. With
        // one server, or none asked for, nothing is asked and this is the
        // connect it always was.
        PgSession session;
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
            PgSession any = settings.hosts().looking(space.seclume.internal.jdbc.TargetServer.ANY)
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
    private static void learn(space.seclume.internal.jdbc.AuroraTopology aurora, PgSession session) {
        try {
            aurora.learn(session.askOneValue(space.seclume.internal.jdbc.AuroraTopology.POSTGRESQL));
        } catch (SQLException notAurora) {
            aurora.refused();
        }
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
            space.seclume.internal.Transports.loggedIn(opened.transport());
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
        } catch (IOException | WireBuffer.Truncated e) {
            // Not brokenConnection: there is no channel yet to close, and a
            // server that cannot be reached is 08001 rather than 08006.
            throw new SQLNonTransientConnectionException(
                    "cannot reach " + settings.host() + ":" + settings.port(), "08001", e);
        }
        PgSession session = new PgSession(channel);
        session.setResultLimit(settings.resultLimit());
        session.settings = settings;
        // Null: nothing in the URL asks for this yet, so what decides is the
        // system property. See space.seclume.Flight for why that is where it
        // stands rather than in the settings record.
        channel.recordFlight(space.seclume.internal.FlightRecorder.from(null));
        try {
            session.negotiateTls(channel, settings);
            // The login alone, timed apart from the connect and the handshake:
            // a slow one here is the directory behind the database and nothing
            // this process did. See SeclumeEvents.Authentication.
            space.seclume.jfr.SeclumeEvents.Authentication login =
                    space.seclume.jfr.Observed.beginLogin();
            boolean loggedIn = false;
            try {
                session.startup(settings);
                loggedIn = true;
            } finally {
                space.seclume.jfr.Observed.endLogin(login, "postgresql",
                        settings.host() + ":" + settings.port(),
                        session.authenticationMethod(), loggedIn);
            }
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
            if (settings.directTls()) {
                // PostgreSQL 17's direct TLS: the handshake at once, no
                // SSLRequest before it and no round trip for its answer. The
                // server tells TLS for it from plain text by the ClientHello
                // and insists on ALPN "postgresql", so nothing else speaking
                // TLS on the port can be mistaken for it.
                channel.startTls(settings.host(), settings.port(), mode.verifies(),
                        settings.tlsStack(), settings.identity(), "postgresql");
                return;
            }
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
        } catch (IOException | WireBuffer.Truncated e) {
            throw new SQLNonTransientConnectionException(
                    "TLS to " + settings.host() + ":" + settings.port() + " failed: "
                    + e.getMessage(), "08001", e);
        }
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

    /**
     * The JVM's default zone as PostgreSQL reads it. Java's {@code GMT+1}
     * means one hour east, POSIX's one hour west, so the sign flips - the same
     * translation pgjdbc makes.
     */
    static String sessionTimeZone() {
        String id = java.util.TimeZone.getDefault().getID();
        if (id.length() > 4 && id.startsWith("GMT")) {
            char sign = id.charAt(3);
            if (sign == '+') {
                return "GMT-" + id.substring(4);
            }
            if (sign == '-') {
                return "GMT+" + id.substring(4);
            }
        }
        return id;
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
            // The JVM's zone, as pgjdbc sends it: ::date, date_trunc and
            // timestamptz text then agree with the vendor driver.
            out.putCString("TimeZone").putCString(sessionTimeZone());
            out.putByte((byte) 0);
            channel.end();
            channel.flush();

            authenticate(settings);
            waitForReady();
        } catch (IOException | WireBuffer.Truncated e) {
            // 08001: the connection was being established, not lost in the
            // middle of work. Without a SQLState this failure is invisible to
            // everything that reacts to one - a host list would not move on to
            // the next server, which is exactly what a failed startup should
            // cause it to do.
            channel.close();
            throw new SQLNonTransientConnectionException(
                    "the connection failed during startup: " + e.getMessage(), "08001", e);
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
        try {
            authenticating(settings);
        } catch (IllegalStateException refused) {
            // Every refusal SCRAM can raise - a server nonce that is not ours,
            // an implausible iteration count, a server signature that does not
            // verify - used to leave here as an IllegalStateException, out of
            // a method whose signature promises SQLException. That is the
            // wrong shape for any failure and the wrong shape twice over for
            // this one: "the server could not prove that it knows the
            // password" is not a mishap, it is the driver saying the far end
            // may not be the database. An application catches SQLException;
            // what went past it here was the one exception it most needed to
            // see. Found by the login fuzz corpus on 23.09.2026.
            throw new java.sql.SQLInvalidAuthorizationSpecException(
                    "the authentication exchange was refused: " + refused.getMessage(),
                    "28000", refused);
        }
    }

    private void authenticating(Settings settings) throws IOException, SQLException {
        space.seclume.internal.Gssapi.Context gss = null;
        try (SecretScope secret = SecretScope.fromProvider(settings.secret());
             ScramSha256 scram = new ScramSha256()) {
            boolean scramStarted = false;
            boolean scramServerProved = false;
            boolean oauthStarted = false;
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
                boolean kerberos = code == PgProtocol.AUTH_GSS || code == PgProtocol.AUTH_GSS_CONTINUE;
                if (code != PgProtocol.AUTH_OK && !kerberos
                        && NoSecretProvider.isNone(settings.secret())) {
                    throw new java.sql.SQLInvalidAuthorizationSpecException(
                            "the server asks for a password (authentication request " + code
                            + "), but this connection has provider=none - it was meant to log "
                            + "in by client certificate alone. pg_hba.conf has to say 'cert' "
                            + "for this user and address; nothing was sent", "28000");
                }
                switch (code) {
                    case PgProtocol.AUTH_OK -> {
                        channel.endMessage();
                        // An OK is only as good as the exchange before it. A
                        // server that skips SCRAM's final message never proved
                        // it knows the password (and skips channel binding with
                        // it), and one that skips Kerberos's reply never proved
                        // it is the service the ticket was for. Either would
                        // otherwise be let in (found in review, 25.09.2026).
                        if (scramStarted && !scramServerProved) {
                            throw new java.sql.SQLInvalidAuthorizationSpecException(
                                    "the server accepted the SCRAM login without its final "
                                    + "message, so it never proved it knows the password - "
                                    + "refused as a server that may not be the database",
                                    "28000");
                        }
                        if (gss != null && !gss.complete()) {
                            throw new java.sql.SQLInvalidAuthorizationSpecException(
                                    "the server accepted the Kerberos login before mutual "
                                    + "authentication was complete - refused as a server that "
                                    + "may not be the service the ticket was for", "28000");
                        }
                        if (settings.identity() != null
                                && NoSecretProvider.isNone(settings.secret())) {
                            // Nothing was asked and no password exists: the
                            // certificate is what let this session in. (With
                            // a password configured, an unasked login is
                            // trust, whatever certificate went along.)
                            authenticationMethod = "cert";
                        }
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
                        String mechanism = chooseMechanism(in, scram, settings);
                        authenticationMethod = mechanism.toLowerCase(java.util.Locale.ROOT);
                        channel.endMessage();
                        if (OAUTHBEARER.equals(mechanism)) {
                            sendBearerToken(secret);
                            oauthStarted = true;
                        } else {
                            startScram(scram, mechanism);
                            scramStarted = true;
                        }
                    }
                    case PgProtocol.AUTH_SASL_CONTINUE -> {
                        if (oauthStarted) {
                            // The token was refused; the server says why in
                            // JSON (RFC 7628) and waits for the one-byte
                            // acknowledgement before it sends the error.
                            channel.endMessage();
                            WireBuffer out = channel.begin(PgProtocol.PASSWORD);
                            out.putByte((byte) 0x01);
                            channel.end();
                            channel.flush();
                            continue;
                        }
                        if (!scramStarted) {
                            throw protocolError("the server continued a SASL exchange "
                                    + "that never started");
                        }
                        continueScram(scram, secret.secret());
                    }
                    case PgProtocol.AUTH_SASL_FINAL -> {
                        if (!scramStarted) {
                            throw protocolError("the server finished a SASL exchange that "
                                    + "was not SCRAM");
                        }
                        int length = channel.messageRemaining();
                        scram.verifyServerFinal(in.segment(), in.position(), length);
                        scramServerProved = true;
                        channel.endMessage();
                    }
                    case PgProtocol.AUTH_GSS -> {
                        // Kerberos: the ticket is the operating system's, in its
                        // credential cache - nothing secret passes through here.
                        channel.endMessage();
                        if (!space.seclume.internal.Gssapi.available()) {
                            throw new SQLException("this server asks for Kerberos (GSSAPI), "
                                    + "which seclume speaks through the system's GSSAPI library "
                                    + "on Linux (libgssapi_krb5) - it is not there on this "
                                    + "platform; Windows' SSPI is not supported yet", "28000");
                        }
                        authenticationMethod = "gss";
                        gss = kerberos(space.seclume.internal.Gssapi.initiate("postgres",
                                settings.host()), null, 0, 0);
                    }
                    case PgProtocol.AUTH_GSS_CONTINUE -> {
                        if (gss == null) {
                            throw protocolError("the server continued a GSSAPI exchange "
                                    + "that never started");
                        }
                        kerberos(gss, in.segment(), in.position(), channel.messageRemaining());
                        channel.endMessage();
                    }
                    case PgProtocol.AUTH_SSPI, PgProtocol.AUTH_KERBEROS_V5 ->
                            throw new SQLException(
                                    "this server asks for " + (code == PgProtocol.AUTH_SSPI
                                    ? "SSPI" : "Kerberos V5 (the pre-GSSAPI kind)")
                                    + " authentication, which seclume does not speak - "
                                    + "GSSAPI ('gss' in pg_hba.conf) it does", "28000");
                    default -> throw new SQLException(
                            "unknown authentication request " + code, "28000");
                }
            }
        } catch (IllegalStateException kerberosRefused) {
            if (gss == null) {
                throw kerberosRefused;
            }
            throw new java.sql.SQLInvalidAuthorizationSpecException("the Kerberos login did "
                    + "not succeed: " + kerberosRefused.getMessage(), "28000", kerberosRefused);
        } finally {
            if (gss != null) {
                gss.close();
            }
        }
    }

    /** One GSSAPI step: the server's token in, ours out - when there is one to send. */
    private space.seclume.internal.Gssapi.Context kerberos(
            space.seclume.internal.Gssapi.Context gss, MemorySegment token, long at, int length)
            throws IOException {
        byte[] next = gss.step(token, at, length);
        if (next.length > 0) {
            WireBuffer out = channel.begin(PgProtocol.PASSWORD);
            out.putBytes(MemorySegment.ofArray(next), 0, next.length);
            channel.end();
            channel.flush();
        }
        return gss;
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
    private String chooseMechanism(WireBuffer in, ScramSha256 scram, Settings settings)
            throws SQLException {
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
            if (mechanisms.contains(OAUTHBEARER)) {
                // A bearer token works for whoever holds it, and unlike SCRAM
                // nothing in it is bound to this connection - so it goes only
                // to a server that has proved who it is: verify-full, or the
                // pinned key. tls=require encrypts but would hand the token to
                // anybody in the middle (found in review, 25.09.2026).
                boolean authenticated = channel.tlsDescription() != null
                        && (settings.tls() == TlsMode.VERIFY_FULL
                            || space.seclume.internal.TrustChoice.pinned());
                if (!authenticated) {
                    throw new java.sql.SQLInvalidAuthorizationSpecException(
                            "the server asks for an OAuth token (OAUTHBEARER), which may only "
                            + "go to a server whose certificate was checked - this connection "
                            + (channel.tlsDescription() == null ? "is not encrypted"
                               : "does not check it (tls=" + settings.tls().name()
                                 .toLowerCase(java.util.Locale.ROOT).replace('_', '-') + ")")
                            + ". Use tls=verify-full or tlsPin; nothing was sent", "28000");
                }
                return OAUTHBEARER;
            }
            throw new SQLException(
                    "the server offers " + mechanisms + ", but seclume speaks SCRAM-SHA-256, "
                    + "SCRAM-SHA-256-PLUS and OAUTHBEARER", "28000");
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

    /** PostgreSQL 18's OAuth login (SASL, RFC 7628). */
    private static final String OAUTHBEARER = "OAUTHBEARER";
    private static final String BEARER_PREFIX = "n,,auth=Bearer ";

    /**
     * The OAUTHBEARER client response: {@code n,,^Aauth=Bearer <token>^A^A}.
     * The token is the provider's secret - an Azure managed identity's, the
     * GCP metadata server's, a file's - and goes from its scope straight into
     * the send buffer, as a password does.
     */
    private void sendBearerToken(SecretScope token) throws IOException {
        WireBuffer out = channel.begin(PgProtocol.PASSWORD);
        out.putCString(OAUTHBEARER);
        out.putInt(BEARER_PREFIX.length() + token.length() + 2);
        for (int i = 0; i < BEARER_PREFIX.length(); i++) {
            out.putByte((byte) BEARER_PREFIX.charAt(i));
        }
        out.putBytes(token.secret(), 0, token.length());
        out.putByte((byte) 0x01);
        out.putByte((byte) 0x01);
        channel.end();
        channel.flush();
    }

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
            // The columns are this statement's to describe, and a statement
            // without rows sends no RowDescription to overwrite the last
            // one. Left standing, the "select 1" a pool validates with made
            // the next plain "delete" look like a query that returned rows -
            // and executeUpdate refused it. Found by the Spring JDBC suite.
            fields = List.of();

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
                        settleParses();
                        if (failure != null) {
                            throw failure;
                        }
                        return;
                    }
                    default -> handleAsynchronous(tag);
                }
            }
        } catch (IOException | WireBuffer.Truncated e) {
            throw brokenConnection("the connection broke while running a statement", e);
        }
    }

    // ---- COPY -----------------------------------------------------------

    /** How much of the caller's stream goes into one CopyData message. */
    private static final int COPY_CHUNK = 64 * 1024;

    /**
     * {@code COPY ... FROM STDIN}: the rows come from {@code data}, as the
     * statement's format says (text, csv or binary), streamed in chunks - the
     * whole input is never held.
     *
     * <p>A failure reading {@code data} is sent to the server as CopyFail, so
     * the statement is rolled back there and the session stays in step; the
     * reading failure is what the caller gets.
     *
     * @return the rows the server says it copied
     */
    public long copyIn(String sql, java.io.InputStream data) throws SQLException {
        flushPipeline();
        java.io.IOException reading = null;
        try {
            int carried = writePending();
            WireBuffer out = channel.begin(PgProtocol.QUERY);
            out.putCString(sql);
            channel.end();
            channel.flush();
            for (int i = 0; i < carried; i++) {
                runUntilReady(null);
            }
            fields = List.of();
            SQLException failure = null;
            while (true) {
                byte tag = channel.nextMessage();
                switch (tag) {
                    case PgProtocol.COPY_IN_RESPONSE -> {
                        channel.endMessage();
                        reading = streamIn(data);
                    }
                    case PgProtocol.COPY_OUT_RESPONSE, PgProtocol.COPY_BOTH_RESPONSE -> {
                        channel.endMessage();
                        throw new SQLException("copyIn was given a COPY ... TO statement - "
                                + "use copyOut", "42601");
                    }
                    case PgProtocol.COMMAND_COMPLETE -> {
                        lastCommandTag = channel.message().readCString();
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
                        settleParses();
                        if (reading != null) {
                            throw new SQLException("reading the data for COPY failed - "
                                    + "nothing was copied: " + reading.getMessage(), "58030",
                                    reading);
                        }
                        if (failure != null) {
                            throw failure;
                        }
                        return copiedRows();
                    }
                    default -> handleAsynchronous(tag);
                }
            }
        } catch (IOException | WireBuffer.Truncated e) {
            throw brokenConnection("the connection broke during COPY", e);
        }
    }

    /**
     * Sends the caller's stream as CopyData, then CopyDone - or CopyFail when
     * the stream could not be read, which is then returned.
     */
    private java.io.IOException streamIn(java.io.InputStream data) throws IOException {
        byte[] chunk = new byte[COPY_CHUNK]; // seclume-allow: the caller's bulk data, not a secret
        java.lang.foreign.MemorySegment view = java.lang.foreign.MemorySegment.ofArray(chunk);
        while (true) {
            int read;
            try {
                read = data.read(chunk);
            } catch (java.io.IOException failed) {
                WireBuffer out = channel.begin(PgProtocol.COPY_FAIL);
                out.putCString("the client could not read its data: " + failed.getClass().getSimpleName());
                channel.end();
                channel.flush();
                return failed;
            }
            if (read < 0) {
                break;
            }
            if (read > 0) {
                WireBuffer out = channel.begin(PgProtocol.COPY_DATA);
                out.putBytes(view, 0, read);
                channel.end();
                channel.flush();
            }
        }
        channel.begin(PgProtocol.COPY_DONE);
        channel.end();
        channel.flush();
        return null;
    }

    /**
     * {@code COPY ... TO STDOUT}: the rows go to {@code sink} as the server
     * sends them. A failure writing to the sink does not stop the reading -
     * the rest of the answer is still on the wire and the session has to get
     * past it - and is what the caller gets at the end.
     *
     * @return the rows the server says it copied
     */
    public long copyOut(String sql, java.io.OutputStream sink) throws SQLException {
        flushPipeline();
        java.io.IOException writing = null;
        try {
            int carried = writePending();
            WireBuffer out = channel.begin(PgProtocol.QUERY);
            out.putCString(sql);
            channel.end();
            channel.flush();
            for (int i = 0; i < carried; i++) {
                runUntilReady(null);
            }
            fields = List.of();
            SQLException failure = null;
            byte[] chunk = new byte[0]; // seclume-allow: the caller's bulk data, not a secret
            while (true) {
                byte tag = channel.nextMessage();
                switch (tag) {
                    case PgProtocol.COPY_OUT_RESPONSE, PgProtocol.COPY_DONE ->
                            channel.endMessage();
                    case PgProtocol.COPY_DATA -> {
                        int length = channel.messageRemaining();
                        if (writing == null) {
                            if (chunk.length < length) {
                                chunk = new byte[Math.max(length, 8192)]; // seclume-allow: the caller's bulk data, not a secret
                            }
                            WireBuffer in = channel.message();
                            java.lang.foreign.MemorySegment.copy(in.segment(), in.position(),
                                    java.lang.foreign.MemorySegment.ofArray(chunk), 0, length);
                            try {
                                sink.write(chunk, 0, length);
                            } catch (java.io.IOException failed) {
                                writing = failed;
                            }
                        }
                        channel.endMessage();
                    }
                    case PgProtocol.COPY_IN_RESPONSE -> {
                        channel.endMessage();
                        WireBuffer fail = channel.begin(PgProtocol.COPY_FAIL);
                        fail.putCString("copyOut was given a COPY ... FROM statement");
                        channel.end();
                        channel.flush();
                        if (failure == null) {
                            failure = new SQLException("copyOut was given a COPY ... FROM "
                                    + "statement - use copyIn", "42601");
                        }
                    }
                    case PgProtocol.COMMAND_COMPLETE -> {
                        lastCommandTag = channel.message().readCString();
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
                        settleParses();
                        if (failure != null) {
                            throw failure;
                        }
                        if (writing != null) {
                            throw new SQLException("writing the COPY output failed: "
                                    + writing.getMessage(), "58030", writing);
                        }
                        return copiedRows();
                    }
                    default -> handleAsynchronous(tag);
                }
            }
        } catch (IOException | WireBuffer.Truncated e) {
            throw brokenConnection("the connection broke during COPY", e);
        }
    }

    /** The count in the last command tag, {@code COPY 42}. */
    private long copiedRows() {
        String tag = lastCommandTag;
        if (tag != null && tag.startsWith("COPY ")) {
            try {
                return Long.parseLong(tag.substring(5).trim());
            } catch (NumberFormatException ignored) {
                // a server that does not count - none known
            }
        }
        return -1;
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
        pendingParses.put(name, sql);
    }

    /**
     * Parses sent and not yet confirmed by ParseComplete, oldest first.
     *
     * <p>Sending a Parse is not having a plan. When it fails - a table that
     * does not exist yet is enough - the server has no statement of that
     * name, and every later Bind against it fails with "prepared statement
     * does not exist", on and on, because the driver thought the Parse done.
     * Liquibase met it: it asks for its lock table before creating it, and
     * the statement stayed broken after the table was there.
     */
    private final java.util.ArrayDeque<InFlightParse> unconfirmedParses =
            new java.util.ArrayDeque<>();

    /**
     * A Parse on the wire, and the ReadyForQuery that closes its block.
     *
     * <p>Not simply the next one: settings queued with runLater ride in
     * front of it as simple queries, each with a ReadyForQuery of its own,
     * and those arrive before the Parse has been answered at all.
     */
    private record InFlightParse(String name, String sql, long settledAtReady) {
    }

    /** ReadyForQuery messages read on this session so far. */
    private long readyCount;

    /** At ReadyForQuery: a Parse whose block is over and was not confirmed is owed again. */
    private void settleParses() {
        readyCount++;
        while (!unconfirmedParses.isEmpty()
                && unconfirmedParses.peek().settledAtReady() <= readyCount) {
            InFlightParse unconfirmed = unconfirmedParses.poll();
            pendingParses.putIfAbsent(unconfirmed.name(), unconfirmed.sql());
        }
    }

    /** Whether this statement's plan is announced but not yet parsed. */
    public boolean hasPendingParse(String name) {
        return pendingParses.containsKey(name);
    }

    /** The Parse of the statement about to run - if it is still owed - and no other. */
    private int writePendingParse(String statement, int carriedBefore) {
        String pendingSql = pendingParses.remove(statement);
        if (pendingSql == null) {
            return 0;
        }
        unconfirmedParses.add(new InFlightParse(statement, pendingSql,
                readyCount + carriedBefore + 1));
        WireBuffer out = channel.begin(PgProtocol.PARSE);
        out.putCString(statement);
        out.putCString(pendingSql);
        out.putShort((short) 0);              // Typen ueberlaesst der Treiber dem Server
        channel.end();

        out = channel.begin(PgProtocol.DESCRIBE);
        out.putByte((byte) 'S');
        out.putCString(statement);
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
        pendingParses.remove(name);           // parsed now; nothing is owed any more
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
        } catch (IOException | WireBuffer.Truncated e) {
            throw brokenConnection("the connection broke while preparing a statement", e);
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
            int carried = writePending();
            carried += writePendingParse(statement, carried);
            WireBuffer out = channel.begin(PgProtocol.BIND);
            out.putCString("");                       // the unnamed portal
            out.putCString(statement);
            parameters.write(out);
            List<Field> asked = writeResultFormats(out, known);
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
                //
                // The formats are the ones just asked for, not the ones the
                // first description carried. The type of a column is the
                // server's to decide and cannot change underneath; the format
                // is chosen per Bind and is ours. Handing the reader the old
                // description meant it decoded binary bytes as digits - no
                // exception, just "column 1 is not an integer: *", which is
                // what this cost before it was written down.
                fields = asked;
            }
            runUntilReady(handler);
        } catch (IOException | WireBuffer.Truncated e) {
            throw brokenConnection("the connection broke while running a prepared statement", e);
        }
    }

    /**
     * Which columns to ask for in binary, one code per column.
     *
     * <p>Binary is not a mode this driver can turn on wholesale: whoever asks
     * for it has to be able to decode every type that comes back, and a type
     * asked for in binary and decoded as text is not an error anywhere - it is
     * a wrong value. So the codes are written per column and only for the
     * types {@code PgOids.readsBinary} names, which are the fixed-width ones
     * where the saving is real and the layout is not open to interpretation.
     * Everything else stays text, including {@code numeric} and the temporal
     * types, whose binary forms are their own small specifications.
     *
     * <p><b>The first execution is always text</b>, because the column types
     * are not known until the server has described them. That is not a
     * limitation worth working around: a statement that runs once pays for one
     * parse anyway, and the shape this exists for - a framework preparing once
     * and executing many times - is binary from the second run on. The result
     * shape cannot change underneath, which is what makes it safe to decide
     * once; PostgreSQL refuses the execution with "cached plan must not change
     * result type" rather than answering in a different shape.
     */
    private List<Field> writeResultFormats(WireBuffer out, List<Field> known) {
        if (known == null || known.isEmpty() || !binaryResults) {
            out.putShort((short) 0);              // all text
            return known;
        }
        out.putShort((short) known.size());
        List<Field> asked = new java.util.ArrayList<>(known.size());
        for (Field field : known) {
            boolean binary = space.seclume.postgresql.jdbc.PgOids.readsBinary(field.typeOid());
            out.putShort(binary ? (short) 1 : (short) 0);
            asked.add(binary == (field.format() == 1) ? field
                    : new Field(field.name(), field.tableOid(), field.columnNumber(),
                            field.typeOid(), field.typeLength(), field.typeModifier(),
                            binary ? (short) 1 : (short) 0));
        }
        return List.copyOf(asked);
    }

    /**
     * Whether this session asks for binary at all - on by default, and off for
     * whoever needs the wire to be readable.
     *
     * <p>A switch rather than a constant because the two formats are the one
     * place where "it works" and "it is correct" can come apart silently: a
     * value decoded in the wrong format is a wrong number, not an exception.
     * Turning it off is then the first thing to try, and the answer either
     * changes or it does not.
     */
    private boolean binaryResults = true;

    public void setBinaryResults(boolean wanted) {
        this.binaryResults = wanted;
    }

    public boolean binaryResults() {
        return binaryResults;
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

    /**
     * Drops a session context not yet sent - before a reset, so that the
     * context of one borrower does not reach the next.
     */
    public void dropPendingContext() {
        pending.removeIf(sql -> sql.startsWith("select set_config("));
    }

    /** What opens a transaction - {@code BEGIN}, or one that carries its own characteristics. */
    private volatile String beginStatement = "BEGIN";

    /**
     * The statement a transaction opens with, from the next one on. Behind a
     * transaction pooler the isolation level and read-only have to travel in
     * it - {@code BEGIN ISOLATION LEVEL SERIALIZABLE READ ONLY} - because a
     * session characteristic would stay on a server connection that the next
     * transaction may belong to another client.
     */
    public void setBeginStatement(String beginStatement) {
        this.beginStatement = beginStatement;
    }

    /** Opens a transaction with the next statement. */
    public void beginLater() throws SQLException {
        if (!defer) {
            execute(beginStatement);
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
        } catch (IOException | WireBuffer.Truncated e) {
            throw brokenConnection("the connection broke while setting the session up", e);
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
            // "BEGIN" is the marker the list is searched for; what goes out is
            // the transaction's own opening - see setBeginStatement.
            out.putCString(sql.equals("BEGIN") ? beginStatement : sql);
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
            pipelineCarried = writePending();
            pipelineCarried += writePendingParse(statement, pipelineCarried);
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
        } catch (IOException | WireBuffer.Truncated e) {
            throw brokenConnection("the connection broke while sending the pipeline", e);
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
                    settleParses();
                    if (failure != null) {
                        throw pipelineFailure(failure, groupStart + failedAt,
                                expected - failedAt - 1);
                    }
                    return;
                }
                case PgProtocol.PARSE_COMPLETE -> {
                    unconfirmedParses.poll();
                    channel.endMessage();
                }
                case PgProtocol.BIND_COMPLETE,
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
        } catch (IOException | WireBuffer.Truncated e) {
            throw brokenConnection("the connection broke while reading the next block of rows", e);
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
        } catch (IOException | WireBuffer.Truncated e) {
            throw brokenConnection("the connection broke while closing a portal", e);
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
                    carried = writePending();
                    carried += writePendingParse(statement, carried);
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
        } catch (IOException | WireBuffer.Truncated e) {
            throw brokenConnection("the connection broke while running a batch", e);
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
                    settleParses();
                    if (failure != null) {
                        throw failure;
                    }
                    return;
                }
                case PgProtocol.PARSE_COMPLETE -> {
                    unconfirmedParses.poll();
                    channel.endMessage();
                }
                case PgProtocol.BIND_COMPLETE,
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
        // Not the announced Parses: a prepared statement is not part of a
        // transaction, and its plan is owed whether or not this one is rolled
        // back. Discarding it here left the statement believing it was
        // prepared - and its next execution bound against nothing.
    }

    /**
     * Releases a prepared plan - with the next statement, not now.
     *
     * <p>Closing a statement returns nothing, so nobody has to wait for the
     * confirmation. It still arrives and is still checked, in the same round
     * trip as the next statement.
     */
    public void closeStatementLater(String name) throws SQLException {
        if (pendingParses.remove(name) != null) {
            return;                           // never parsed, so nothing to close
        }
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
        } catch (IOException | WireBuffer.Truncated e) {
            throw brokenConnection("the connection broke while closing a statement", e);
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
                case PgProtocol.PARSE_COMPLETE -> {
                    unconfirmedParses.poll();
                    channel.endMessage();
                }
                case PgProtocol.BIND_COMPLETE,
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
                    settleParses();
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
            case PgProtocol.NOTIFICATION_RESPONSE -> {
                int from = in.getInt();
                String name = in.readCString();
                String payload = in.readCString();
                if (notifications.size() >= NOTIFICATIONS_KEPT) {
                    notifications.pollFirst();           // the oldest goes, and is counted
                    notificationsDropped++;
                }
                notifications.addLast(new PgNotification(from, name, payload));
            }
            case PgProtocol.NOTICE_RESPONSE -> {
                // The server's notices are of no interest here yet; they
                // belong on SQLWarning later.
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
     * {@code md5}, {@code password}, {@code cert} or {@code trust}. Useful in bug reports and
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

    /**
     * Asks the server to stop whatever this connection is doing.
     *
     * <p>Out of band, on a connection of its own, because the one running the
     * statement is blocked on its answer. A second socket is opened to the
     * same server, the sixteen bytes of a {@code CancelRequest} go down it,
     * and it is closed again - see
     * {@link PgChannel#sendCancelRequest}. The server sends nothing back and
     * this call does not wait for anything: <b>a cancellation that was ignored
     * and one that worked look exactly the same from here.</b> What the caller
     * sees is the statement it interrupted failing, or finishing, on its own
     * thread.
     *
     * <p>The race is in the protocol and not in this method. A cancel sent
     * while nothing is running is discarded by the server; a cancel sent in
     * the gap between two statements can stop the second one. Nothing on the
     * client can close that gap - libpq has it too - so this does not pretend
     * to, and a caller that needs certainty has to check what the statement
     * did rather than assume the cancel landed.
     *
     * <p>Safe from another thread, and that is the only way it is ever called:
     * it touches nothing this session owns except two numbers that were
     * written once during the login.
     *
     * @throws SQLException if this session cannot be cancelled - a resumed
     *                      stream, or a server that sent no key
     */
    public void cancel() throws SQLException {
        Settings where = settings;
        if (where == null) {
            throw new SQLException("this session was resumed rather than opened, so it does "
                    + "not know which server to send a cancellation to", "0A000");
        }
        if (backendProcessId == 0) {
            throw new SQLException("the server sent no BackendKeyData, so there is no key "
                    + "to cancel with", "0A000");
        }
        if (!channel.isAwaitingAnswer()) {
            // Nothing is running, so there is nothing to cancel - and sending
            // it anyway would stop the next statement instead, which is the
            // whole trap in PostgreSQL's cancellation. See
            // PgChannel#isAwaitingAnswer.
            return;
        }
        PgChannel aside;
        try {
            aside = PgChannel.connect(where.host(), where.port(),
                    where.connectTimeoutMillis());
        } catch (IOException | WireBuffer.Truncated e) {
            throw new SQLNonTransientConnectionException("cannot reach "
                    + where.host() + ":" + where.port() + " to cancel", "08001", e);
        }
        try {
            negotiateTls(aside, where);
            aside.sendCancelRequest(backendProcessId, backendSecretKey);
        } catch (IOException | WireBuffer.Truncated e) {
            throw new SQLNonTransientConnectionException(
                    "the cancellation could not be sent: " + e.getMessage(), "08006", e);
        } finally {
            aside.close();
        }
    }

    /**
     * The connection is gone, and the session with it.
     *
     * <p><b>Closing here is the point.</b> After an IO failure the protocol
     * state is unknown - a half-read message, a statement whose answer never
     * came - so every further call would fail the same way. Saying so through
     * {@code isClosed()} is what lets a pool throw the connection away instead
     * of handing it out again; without it a database that goes away for two
     * seconds takes the pool with it for as long as requests keep arriving
     * faster than the pool's validation window. Found by the chaos benchmark,
     * where it happened on every request.
     *
     * <p><b>Two causes, and they are the same fact seen from two places.</b>
     * An {@link IOException} is the socket saying so. A
     * {@link WireBuffer.Truncated} is this driver saying so: a message
     * announced more bytes than it brought, so what follows it is not where
     * the protocol says it is, and every byte after that would be read at the
     * wrong offset.
     *
     * <p><b>And what it last saw, when it was recording.</b> The flight
     * recorder's tail is attached here and not offered separately, because
     * this is the one place somebody is certain to look: a stream that went
     * out of step shows it in the order of the last few messages and in
     * nothing else, and by the time anybody thinks to ask, the connection is
     * closed. See {@link space.seclume.Flight}.
     *
     * <p><b>The second used to escape as an unchecked exception.</b>
     * {@code Truncated} is an {@code IllegalStateException}, nothing in this
     * driver caught it, and so a malformed answer came out of
     * {@code Statement.executeQuery} - a method whose signature promises
     * {@link SQLException} and nothing else. An application catches
     * {@code SQLException}; that is what a framework's retry and its
     * connection-health check are written against. An unchecked exception from
     * inside a decoder goes past all of it, is logged as a bug in the
     * application, and leaves a connection in a pool that nobody marked
     * broken. Found by the fuzz corpus on 23.09.2026.
     */
    private SQLException brokenConnection(String what, Exception cause) {
        String flight = channel.flightTail();
        channel.close();
        return new SQLNonTransientConnectionException(
                flight == null ? what : what + " - " + flight, "08006", cause);
    }

    /** What this connection last sent and received - see space.seclume.Flight. */
    public java.util.List<space.seclume.Flight.Message> recentMessages() {
        return channel.recentMessages();
    }

    /** How many messages have crossed this connection. */
    public long recordedMessages() {
        return channel.recordedMessages();
    }

    public boolean isOpen() {
        return channel.isOpen();
    }

    /** The channel underneath - for tests that have to look at the transport. */
    PgChannel channel() {
        return channel;
    }

    /**
     * The transport carrying this session, for whoever may take it apart.
     *
     * <p>One of the three methods a connection has to offer before anything
     * else can move it: what it is on, whether it is at rest, and a way to put
     * something else underneath. They are here and the moving is not, because
     * a driver that also knows how to move a socket has taken a decision that
     * belongs to whoever deploys it.
     */
    public space.seclume.internal.Transport transport() {
        return channel.transport();
    }

    /**
     * Whether the <b>driver</b> has nothing in flight.
     *
     * <p>Half of the quiescent point, and only half: this says nothing
     * half-written and nothing half-read on this side. What the kernel still
     * holds - unacknowledged bytes, unread bytes - is the other half, and only
     * the transport knows it. A connection can satisfy one and not the other,
     * and taking it apart then loses bytes silently.
     */
    public boolean isIdle() {
        return channel.isIdle();
    }

    /** Whether this session is carried by TLS at all. */
    public boolean isEncrypted() {
        return channel.isEncrypted();
    }

    /**
     * Whether the encryption on this session, if any, is state we can write
     * down.
     *
     * <p>The fourth question a mover has to ask, and the one whose answer
     * changed. While the drivers reached TLS only through an
     * {@code SSLEngine} it was always no: that class hands out neither the
     * keys nor the record sequence numbers, by design, so such a connection
     * can be frozen and thawed <b>in this process</b> - where the engine is an
     * object that stays put - and cannot leave it. On this project's own TLS
     * stack the state is ours, in memory we allocated, and it travels.
     *
     * <p>An unencrypted connection answers yes, because there is nothing to
     * carry.
     */
    public boolean encryptionCanTravel() {
        return channel.encryptionCanTravel();
    }

    /**
     * Puts another transport under this session.
     *
     * <p>The protocol state does not move and does not need to: the parser,
     * the prepared plans and the buffers are objects that never learn anything
     * happened. What changes is where the bytes come from.
     *
     * <p><b>The old transport is not closed here.</b> Closing it while the
     * server may still retransmit is what answers that retransmission with an
     * RST, and the order in which the two happen is the caller's to get right
     * - it differs between a move inside one machine and a move between two.
     *
     * @throws SQLException if the driver is not idle, which it checks; whether
     *                      the kernel is, it cannot
     */
    public void replaceTransport(space.seclume.internal.Transport replacement)
            throws SQLException {
        try {
            channel.replaceTransport(replacement);
        } catch (IOException | WireBuffer.Truncated e) {
            throw brokenConnection("the transport could not be replaced: " + e.getMessage(), e);
        }
    }

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
     * cancel a running query; and, when the stream was encrypted, the TLS
     * layer that is still live on it. The transaction status is not
     * in here on purpose: it is in the next {@code ReadyForQuery}, which the
     * stream carries anyway.
     *
     * @param stream the socket, still logged in, positioned at a message
     *               boundary
     */
    public record Detached(space.seclume.internal.Transport stream,
                           java.util.Map<String, String> parameters,
                           int backendProcessId, int backendSecretKey,
                           space.seclume.internal.TlsLayer tls) {

        /** A stream that was in the clear, and therefore carries no encryption. */
        public Detached(space.seclume.internal.Transport stream,
                        java.util.Map<String, String> parameters,
                        int backendProcessId, int backendSecretKey) {
            this(stream, parameters, backendProcessId, backendSecretKey, null);
        }
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
     *   <li>encrypted on the JDK's TLS - an {@code SSLEngine} does not hand
     *       out its traffic secrets or its record sequence numbers, by
     *       design, so there is nothing that could go with the stream and the
     *       refusal stays.
     * </ul>
     *
     * <p>On seclume's own stack it does not refuse. The TLS layer is handed
     * out with the socket, and {@link #resume(space.seclume.internal.Transport,
     * java.util.Map, int, int, space.seclume.internal.TlsLayer) resume} takes
     * it up - the same connection, a different session object, and a server
     * that is told nothing.
     *
     * <p>Afterwards this session is finished: the channel reports itself
     * closed, and the transport belongs to the caller.
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
        space.seclume.internal.Transport stream = channel.transport();
        java.util.Map<String, String> snapshot = java.util.Map.copyOf(parameters);
        space.seclume.internal.TlsLayer tls = channel.tlsLayer();
        channel.release(tls != null);
        return new Detached(stream, snapshot, backendProcessId, backendSecretKey, tls);
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
        return new Detached(channel.transport(), java.util.Map.copyOf(parameters),
                backendProcessId, backendSecretKey, channel.tlsLayer());
    }

    /**
     * Notifications the server sent and nobody has taken yet - they arrive
     * with any answer, and wait here for {@link #takeNotifications}.
     */
    private final java.util.ArrayDeque<PgNotification> notifications = new java.util.ArrayDeque<>();

    /** How many wait here at most; beyond it the oldest go. */
    private static final int NOTIFICATIONS_KEPT = 10_000;

    /** How many went that way - a listener that never takes them should find out. */
    private long notificationsDropped;

    /**
     * The notifications that arrived, oldest first, and taken.
     *
     * @param ask when nothing waits here yet, ask the server with a bare
     *            {@code Sync}: one round trip that brings whatever it has
     *            queued for this connection - and does nothing else, not
     *            even begin the transaction a pending {@code BEGIN} would
     */
    public java.util.List<PgNotification> takeNotifications(boolean ask) throws SQLException {
        if (ask && notifications.isEmpty() && channel.isIdle()) {
            try {
                channel.begin(PgProtocol.SYNC);
                channel.end();
                channel.flush();
                runUntilReady(null);
            } catch (IOException | WireBuffer.Truncated e) {
                throw brokenConnection("the connection broke while asking for notifications", e);
            }
        }
        java.util.List<PgNotification> taken = new java.util.ArrayList<>(notifications);
        notifications.clear();
        return taken;
    }

    /** How many notifications were dropped because nobody took them in time. */
    public long notificationsDropped() {
        return notificationsDropped;
    }

    /** Cancelling a running query needs this key. */
    int backendSecretKey() {
        return backendSecretKey;
    }
}
