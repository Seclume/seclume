package space.seclume.sqlserver.tds;

import java.io.IOException;
import java.sql.SQLException;
import java.sql.SQLNonTransientConnectionException;

import space.seclume.internal.WireBuffer;
import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.secret.SecretProvider;

/**
 * A session with a SQL Server.
 *
 * <p>The layer below JDBC: connect, log in, run statements, read results. It
 * knows the protocol but no {@code Connection}.
 *
 * <p>The connect sequence is four steps and each depends on the one before:
 *
 * <ol>
 *   <li>{@code PRELOGIN} - versions, and whether to encrypt.</li>
 *   <li>The TLS handshake, whose records travel <b>inside</b> TDS packets for
 *       the duration of the handshake and only afterwards the other way
 *       round. {@link TdsTls} handles that reversal.</li>
 *   <li>{@code LOGIN7} with the obfuscated password.</li>
 *   <li>The answer as a token stream, read by {@link LoginResponse}.</li>
 * </ol>
 *
 * <p>The password only lives for the length of step three and is zeroed
 * afterwards. The session does not hold on to it - not even for a reconnect;
 * for that the {@link SecretProvider} is asked again.
 */
public final class TdsSession implements AutoCloseable {

    /**
     * The header block in front of every SQL_BATCH and RPC: total length,
     * then one header of type 2 with the transaction descriptor.
     *
     * <pre>
     *   4  TotalLength, including these four bytes
     *   4  HeaderLength = 18
     *   2  HeaderType = 2, transaction descriptor
     *   8  TransactionDescriptor
     *   4  OutstandingRequestCount
     * </pre>
     *
     * <p>Leaving it out is not a protocol variant but a hard error: the server
     * reads the first four bytes of the statement text as a length and closes
     * the connection. Every request from 7.2 onwards carries it.
     */
    private static final int ALL_HEADERS_SIZE = 22;
    private static final int TRANSACTION_HEADER_SIZE = 18;
    private static final int HEADER_TYPE_TRANSACTION = 2;

    /** The procedure number of {@code sp_executesql}. */
    private static final int PROC_SP_EXECUTESQL = 10;
    /** The stored procedures of a server-side cursor, addressed by number. */
    private static final int PROC_SP_CURSOROPEN = 2;
    private static final int PROC_SP_CURSORFETCH = 7;
    private static final int PROC_SP_CURSORCLOSE = 9;
    /**
     * Prepared handles: compile once, execute by number.
     *
     * <p>Numbers from MS-TDS 2.2.6.6 („RPC Request"), read there rather than
     * copied from somewhere. That matters: this file used to declare
     * {@code PROC_SP_CURSORPREPEXEC = 13}, which is <b>Sp_PrepExec</b> -
     * Sp_CursorPrepExec is 5. The constant was never used, but the wrong
     * number is a plausible reason why an earlier attempt at a cursor with
     * bind values „refused the parameter list": it was calling a different
     * procedure than it thought.
     */
    private static final int PROC_SP_PREPARE = 11;
    private static final int PROC_SP_EXECUTE = 12;
    private static final int PROC_SP_PREPEXEC = 13;
    private static final int PROC_SP_UNPREPARE = 15;
    private static final int PROC_SP_CURSORPREPEXEC = 5;
    private static final int CURSOR_FORWARD_ONLY = 0x0004;
    /**
     * Says the statement carries parameters.
     *
     * <p>Without it {@code sp_cursorprepexec} answers "the value of the
     * parameter scrollopt is invalid" - measured, because the documentation
     * lists the flag without saying it is required.
     */
    private static final int CURSOR_PARAMETERIZED = 0x1000;
    private static final int CURSOR_READ_ONLY = 0x0001;
    private static final int FETCH_NEXT = 0x0002;
    /** Separates two RPCs in one message - 0xFF since TDS 7.2. */
    private static final int RPC_SEPARATOR = 0xff;
    /**
     * How many calls go into one message before its answer is read.
     *
     * <p>The full packets of a message leave while it is still being written
     * (TdsChannel.sendFull), so the server runs the first rows while the last
     * are encoded, and the send buffer holds a packet rather than the batch.
     * What stays unbounded is the answer: a DONE per call that the server
     * writes and nobody reads until the message is complete. Should both
     * socket buffers fill with it, the two ends would wait on each other, so
     * the calls per message are capped - at a number whose answers, some
     * 30 bytes a call, sit well inside what the buffers hold; 200 000 rows in
     * one message were tried against a real server and did not stall either.
     * Measured against mssql-jdbc, which sends a batch as one message: 5 000
     * rows 66.6 ms against 66.8, 200 000 rows 2.72 s against 2.93 s. With the
     * old cap of 1 024 rows and 60 KB it was 74 ms and 3.2 s.
     */
    private static final int BATCH_ROWS = 16_384;
    /** A bound on the part of a message still in the buffer - one huge row at most. */
    private static final int BATCH_BYTES = 60 * 1024;
    /** Connection settings. Not the password, only its source. */
    public record Settings(String host, int port, String database, String user,
                           SecretProvider secret, String applicationName,
                           int connectTimeoutMillis, boolean trustServerCertificate,
                           HostList hosts, ResultLimit resultLimit,
                           TdsVersion tdsVersion,
                           space.seclume.internal.jdbc.TlsStack tlsStack,
                           space.seclume.tls.ClientIdentity identity) {

        /**
         * With everything but the TDS version, which almost nobody sets.
         *
         * <p>7.4 and the JDK's TLS: what every SQL Server in service speaks,
         * and what this driver did before 8.0 existed here.
         */
        public Settings(String host, int port, String database, String user,
                        SecretProvider secret, String applicationName,
                        int connectTimeoutMillis, boolean trustServerCertificate,
                        HostList hosts, ResultLimit resultLimit) {
            this(host, port, database, user, secret, applicationName, connectTimeoutMillis,
                    trustServerCertificate, hosts, resultLimit, TdsVersion.TDS_7_4,
                    space.seclume.internal.jdbc.TlsStack.JSSE, null);
        }

        /** Without a result limit - what a URL without the option means. */
        public Settings(String host, int port, String database, String user,
                        SecretProvider secret, String applicationName,
                        int connectTimeoutMillis, boolean trustServerCertificate,
                        HostList hosts) {
            this(host, port, database, user, secret, applicationName, connectTimeoutMillis,
                    trustServerCertificate, hosts, ResultLimit.NONE);
        }

        public Settings(String host, int port, String database, String user,
                        SecretProvider secret) {
            this(host, port, database, user, secret, "seclume", 10_000, false);
        }

        /** One server - the ordinary case, and what a URL without a comma means. */
        public Settings(String host, int port, String database, String user,
                        SecretProvider secret, String applicationName,
                        int connectTimeoutMillis, boolean trustServerCertificate) {
            this(host, port, database, user, secret, applicationName, connectTimeoutMillis,
                    trustServerCertificate, HostList.of(host, port));
        }

        /**
         * The same settings pointed at another server of the list.
         *
         * <p>Every component has to be carried across, including the ones
         * added later - a single-host list goes through here too, so
         * anything dropped here is dropped on every connection rather than
         * only on failover.
         */
        Settings at(HostList.Host server) {
            return new Settings(server.host(), server.port(), database, user, secret,
                    applicationName, connectTimeoutMillis, trustServerCertificate, hosts,
                    resultLimit, tdsVersion, tlsStack, identity);
        }
    }

    private ResultLimit resultLimit = ResultLimit.NONE;

    // ---- the pipeline block ----------------------------------------------
    //
    // The same machinery as the batch above, pointed at a different caller:
    // the batch bundles one statement with many values, this bundles many
    // statements. TDS allows both the same way - several RPCs in one message,
    // separated by 0xff - so nothing new had to be invented for it.

    private boolean pipelining;
    /** How many RPCs are waiting in the send buffer. */
    private int pipelineGroup;
    /** Whether a message has been started that the next RPC continues. */
    private boolean pipelineOpen;
    private long[] pipelineCounts = new long[0]; // seclume-allow: update counts, not a secret
    private int pipelineCount;
    /** The statements in the group, so a failure can say which one it was. */
    private final java.util.List<String> pipelineSql = new java.util.ArrayList<>();

    private final TdsChannel channel;
    private final String serverName;
    private final int serverVersion;
    private String database;

    /**
     * The transaction descriptor the server hands out with {@code BEGIN
     * TRANSACTION} and which every following request has to quote. Zero means:
     * no explicit transaction, every statement commits on its own.
     */
    private long transactionDescriptor;
    /** A session setting waiting for a statement to ride along with. */
    private String pending;
    /** A session context waiting for the next statement - see contextLater. */
    private String pendingContext;
    /** The columns of the open cursor - only the open reports them. */
    private java.util.List<TdsColumn> cursorColumns = java.util.List.of();
    private long updateCount = -1;

    /**
     * What an authenticated TDS stream is, once it has left its session.
     *
     * <p>Beside the socket, what the login settled and a decoder cannot
     * derive: the packet size the two sides agreed on - write a larger one and
     * the server closes the connection - the database the session is in, and
     * the server's name and version, which decide how some types are read.
     *
     * @param stream the socket, still logged in, at a packet boundary
     */
    public record Detached(space.seclume.internal.Transport stream, int packetSize,
                           String database, String serverName, int serverVersion,
                           space.seclume.internal.TlsLayer tls) {

        /** A stream that was in the clear, and therefore carries no encryption. */
        public Detached(space.seclume.internal.Transport stream, int packetSize,
                        String database, String serverName, int serverVersion) {
            this(stream, packetSize, database, serverName, serverVersion, null);
        }
    }

    /**
     * Hands the authenticated stream over and finishes this session object.
     *
     * <p>The third of the four, and the same two refusals: not at a quiescent
     * point, and not while encrypted on the JDK's TLS. That second one used to
     * put this driver out of reach entirely - TDS always encrypts the login,
     * so there is no unencrypted state to hand over - which is why strict
     * encryption on seclume's own stack is the route that makes it possible at
     * all.
     *
     * <p>TDS adds one condition the others do not have. An explicit
     * transaction is not a state of the connection here but a <b>descriptor
     * the server hands out</b>, which every following request has to quote -
     * so a stream handed over in the middle of one would be useless to
     * whoever receives it: they would have to quote a number they were never
     * told. Handing it over is therefore refused, rather than discovered
     * later by a server complaining about a transaction that does not exist.
     */
    public Detached detach() throws SQLException {
        drainPending();                      // a paused answer is read in first
        if (!channel.isIdle()) {
            throw new SQLException("this session has work in flight - a stream can only be "
                    + "handed over at a quiescent point (" + channel.inFlight() + ")", "25000");
        }
        if (channel.isEncrypted() && !channel.encryptionCanTravel()) {
            throw new SQLException("this session is encrypted on the JDK's TLS, whose keys "
                    + "cannot leave the SSLEngine that holds them - so the stream cannot be "
                    + "handed to another session. Open it on seclume's own TLS stack, or "
                    + "terminate TLS where the login happens", "0A000");
        }
        if (!cursorColumns.isEmpty()) {
            throw new SQLException("a cursor is open on this session - whoever receives the "
                    + "stream would be reading rows it never asked for", "25000");
        }
        if (transactionDescriptor != 0) {
            throw new SQLException("this session is inside an explicit transaction, and its "
                    + "descriptor cannot be handed over - commit or roll back first", "25000");
        }
        // A setting waiting to ride along with the next statement goes now,
        // as on the other three drivers. This used to refuse the hand-over
        // instead - safe, but it made setTransactionIsolation() just before a
        // hand-over an error on this driver alone.
        flushPending();
        space.seclume.internal.TlsLayer tls = channel.tlsLayer();
        Detached detached = new Detached(channel.transport(), channel.packetSize(),
                database, serverName, serverVersion, tls);
        channel.release(tls != null);
        return detached;
    }

    /** The session is reset before the next request - see {@link TdsChannel#resetBeforeNextRequest}. */
    public void resetBeforeNextRequest() {
        channel.resetBeforeNextRequest();
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
        drainPending();
        if (!channel.isIdle()) {
            throw new SQLException("this session has work in flight - it can only be "
                    + "described at a quiescent point (" + channel.inFlight() + ")", "25000");
        }
        if (channel.isEncrypted() && !channel.encryptionCanTravel()) {
            throw new SQLException("this session is encrypted on the JDK's TLS, whose keys "
                    + "cannot leave the SSLEngine that holds them", "0A000");
        }
        if (!cursorColumns.isEmpty()) {
            throw new SQLException("a cursor is open on this session", "25000");
        }
        if (transactionDescriptor != 0) {
            throw new SQLException("this session is inside an explicit transaction, whose "
                    + "descriptor another process could not quote", "25000");
        }
        flushPending();
        return new Detached(channel.transport(), channel.packetSize(), database, serverName,
                serverVersion, channel.tlsLayer());
    }

    /**
     * Continues a session somebody else authenticated.
     *
     * <p>No LOGIN7 to send - the server is long past it - so what it answered
     * with is handed in instead. The packet size is the one that matters
     * immediately: it is negotiated, and a client writing a larger packet than
     * was agreed has its connection closed without an error message.
     */
    public static TdsSession resume(space.seclume.internal.Transport stream, int packetSize,
                                    String database, String serverName, int serverVersion) {
        return resume(stream, packetSize, database, serverName, serverVersion, null);
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
    public static TdsSession resume(space.seclume.internal.Transport stream, int packetSize,
                                    String database, String serverName, int serverVersion,
                                    space.seclume.internal.TlsLayer tls) {
        TdsSession session = new TdsSession(tls == null
                ? TdsChannel.over(stream)
                : TdsChannel.over(stream, tls), database, serverName, serverVersion);
        session.channel.packetSize(packetSize);
        return session;
    }

    /** The transport carrying this session, for whoever may take it apart. */
    public space.seclume.internal.Transport transport() {
        return channel.transport();
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
        sqlBatch(sql, row -> {
            if (answer[0] == null && row.columnCount() > 0 && !row.isNull(0)) {
                answer[0] = row.text(0);
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
    private static final HostList.Roles<TdsSession> ROLES = new HostList.Roles<>() {

        @Override
        public space.seclume.internal.jdbc.ServerRole of(TdsSession session) throws SQLException {
            try {
                return space.seclume.internal.jdbc.ServerRole.read(session.askOneValue(
                        space.seclume.internal.jdbc.ServerRole.SQLSERVER));
            } catch (SQLException refused) {
                return space.seclume.internal.jdbc.ServerRole.UNKNOWN;
            }
        }

        @Override
        public void giveBack(TdsSession session) {
            session.close();
        }
    };

    /** Whether the <b>driver</b> has nothing in flight - half the quiescent point. */
    public boolean isIdle() {
        return channel.isIdle();
    }

    private TdsSession(TdsChannel channel, String database, String serverName,
                       int serverVersion) {
        this.channel = channel;
        this.database = database;
        this.serverName = serverName;
        this.serverVersion = serverVersion;
    }

    private TdsSession(TdsChannel channel, LoginResponse login) {
        this.channel = channel;
        this.serverName = login.serverName();
        this.serverVersion = login.serverVersion();
        this.database = login.database();
    }

    // ---- connecting and logging in ---------------------------------------

    public static TdsSession open(Settings settings) throws SQLException {
        // One server: a plain connect. Several: the next one when a server
        // cannot be reached - and only then, see HostList.
        // With several servers and a preference in the URL, each one is asked
        // what it is before its connection is kept - see TargetServer. With
        // one server, or none asked for, nothing is asked and this is the
        // connect it always was.
        return settings.hosts().open(server -> openOne(settings.at(server)), ROLES);
    }

    private static TdsSession openOne(Settings settings) throws SQLException {
        // The expensive one: a physical connect, the TLS handshake and the
        // login. Recorded around the whole of it, because that is the number
        // a pool's warm-up time is made of. See space.seclume.jfr.
        space.seclume.jfr.SeclumeEvents.ConnectionOpen event =
                space.seclume.jfr.Observed.beginConnect();
        TdsSession opened = null;
        try {
            opened = connectAndLogIn(settings);
            return opened;
        } finally {
            space.seclume.jfr.Observed.endConnect(event, "sqlserver",
                    settings.host() + ":" + settings.port(), settings.database(),
                    opened == null ? null : opened.tlsDescription(), opened != null);
        }
    }

    private static TdsSession connectAndLogIn(Settings settings) throws SQLException {
        TdsChannel channel;
        try {
            channel = TdsChannel.connect(settings.host(), settings.port(),
                    settings.connectTimeoutMillis());
            // Before the login, because a login that fails is exactly when
            // somebody wants to know what the server said. See
            // space.seclume.Flight.
            channel.recordFlight(space.seclume.internal.FlightRecorder.from(null));
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw new SQLNonTransientConnectionException(
                    "cannot reach " + settings.host() + ":" + settings.port(), "08001", e);
        }
        try {
            TdsSession session = login(channel, settings);
            space.seclume.internal.Transports.loggedIn(session.transport());
            return session;
        } catch (space.seclume.internal.WireBuffer.Truncated e) {
            // Before the RuntimeException clause below, and that order is the
            // whole fix. Truncated is an IllegalStateException, so it used to
            // leave here as itself - anything that can answer on port 1433
            // reaches this parser before a credential is exchanged, and a
            // greeting that runs out mid-field came out as an unchecked
            // exception rather than as a login that failed.
            channel.close();
            throw new SQLNonTransientConnectionException(
                    "the server's answer is not TDS: " + e.getMessage(), "08001", e);
        } catch (SQLException | RuntimeException e) {
            channel.close();
            throw e;
        } catch (IOException e) {
            channel.close();
            throw new SQLNonTransientConnectionException(
                    "the login to " + settings.host() + " failed", "08001", e);
        }
    }

    private static TdsSession login(TdsChannel channel, Settings settings)
            throws IOException, SQLException {
        PreLogin preLogin;
        if (settings.tdsVersion().wrapsTheConnection()) {
            startStrictEncryption(channel, settings);
            // The pre-login still happens - the server wants the version and
            // the instance name - but it happens inside TLS, and its
            // encryption byte is no longer a negotiation: that was settled
            // before the first byte.
            preLogin = new PreLogin();
            preLogin.exchange(channel, Tds.ENCRYPT_ON, AccessToken.is(settings.secret()));
        } else {
            preLogin = negotiateEncryption(channel, settings);
        }

        // From here on it is the login alone: the pre-login is done and TLS is
        // up either way round. Timed apart from both, because a slow login is
        // the directory behind the server and a slow handshake is not - see
        // SeclumeEvents.Authentication.
        space.seclume.jfr.SeclumeEvents.Authentication event =
                space.seclume.jfr.Observed.beginLogin();
        boolean loggedIn = false;
        try {
            if (AccessToken.is(settings.secret()) && settings.trustServerCertificate()
                    && !space.seclume.internal.TrustChoice.pinned()) {
                // A bearer token works for whoever holds it: it goes only to
                // a server that proved who it is. trustServerCertificate
                // encrypts, but to anybody.
                throw new java.sql.SQLInvalidAuthorizationSpecException("an access token "
                        + "(authentication=token) may only go to a server whose certificate is "
                        + "checked, and trustServerCertificate=true checks nothing. Leave it off, "
                        + "or name the server's key with tlsPin; nothing was sent", "28000");
            }
            Login7.Settings login = new Login7.Settings(settings.host(), settings.database(),
                    settings.user(), settings.secret(), settings.applicationName(), "seclume");
            LoginResponse response;
            if (Kerberos.is(settings.secret())) {
                response = integrated(channel, login, preLogin,
                        Kerberos.servicePrincipal(settings.secret()));
            } else {
                Login7.send(channel, login, preLogin);
                response = new LoginResponse();
                response.read(channel);
            }
            if (response.failure() != null) {
                throw response.failure();
            }
            if (!response.isLoggedIn()) {
                throw new SQLNonTransientConnectionException(
                        "the server sent no LOGINACK", "08004");
            }
            if (response.packetSize() > 0) {
                channel.packetSize(response.packetSize());
            }
            TdsSession session = new TdsSession(channel, response);
            session.method = Kerberos.is(settings.secret()) ? "Kerberos (integrated, mutual)"
                    : AccessToken.is(settings.secret()) ? "access token (FEDAUTH, inside TLS)"
                    : "SQL login (LOGIN7, inside TLS)";
            session.setResultLimit(settings.resultLimit());
            loggedIn = true;
            return session;
        } finally {
            space.seclume.jfr.Observed.endLogin(event, "sqlserver",
                    settings.host() + ":" + settings.port(), "login7", loggedIn);
        }
    }

    /**
     * An integrated login: Kerberos tokens instead of a password. The first
     * goes in LOGIN7, every further one the server asks for in an SSPI
     * packet; the answer that logs in carries the server's own token, and
     * the login counts only when that completes the context - the server
     * proved it holds the service's key, so nobody in between can stand in
     * for it (MS-TDS 3.2.5.1, the same rule as for PostgreSQL's GSSAPI).
     */
    private static LoginResponse integrated(TdsChannel channel, Login7.Settings login,
                                            PreLogin preLogin, String servicePrincipal)
            throws IOException, SQLException {
        try (space.seclume.internal.Gssapi.Context gss =
                     space.seclume.internal.Gssapi.initiatePrincipal(servicePrincipal)) {
            byte[] token = gss.step(null, 0, 0);
            Login7.send(channel, login, preLogin, token);
            for (int round = 0; ; round++) {
                LoginResponse response = new LoginResponse();
                response.read(channel);
                if (response.failure() != null) {
                    return response;
                }
                byte[] answer = response.sspi();
                if (answer != null && !gss.complete()) {
                    token = step(gss, answer);
                } else {
                    token = new byte[0]; // seclume-allow: an empty token
                }
                if (response.isLoggedIn()) {
                    if (!gss.complete()) {
                        throw new java.sql.SQLInvalidAuthorizationSpecException("the server "
                                + "logged the session in without proving it holds the key of "
                                + servicePrincipal + " - refused, as it could be anybody", "28000");
                    }
                    return response;
                }
                if (round > 8 || (token.length == 0 && !gss.complete())) {
                    throw new SQLNonTransientConnectionException("the Kerberos login with "
                            + servicePrincipal + " ended without an answer from the server",
                            "08004");
                }
                if (token.length == 0) {
                    // The server's token completed the context; SQL Server sends
                    // it in a message of its own and the LOGINACK in the next.
                    continue;
                }
                WireBuffer out = channel.begin();
                out.putBytes(java.lang.foreign.MemorySegment.ofArray(token), 0, token.length);
                channel.send(Tds.TYPE_SSPI);
            }
        } catch (IllegalStateException kerberos) {
            // No ticket, an unknown SPN, a KDC out of reach: the library says which.
            throw new java.sql.SQLInvalidAuthorizationSpecException("Kerberos login with "
                    + servicePrincipal + " failed: " + kerberos.getMessage(), "28000", kerberos);
        }
    }

    /** One step with the server's token, which has to be in native memory for the library. */
    private static byte[] step(space.seclume.internal.Gssapi.Context gss, byte[] answer) {
        try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
            java.lang.foreign.MemorySegment in = arena.allocate(Math.max(1, answer.length));
            java.lang.foreign.MemorySegment.copy(answer, 0, in,
                    java.lang.foreign.ValueLayout.JAVA_BYTE, 0, answer.length);
            return gss.step(in, 0, answer.length);
        }
    }

    /**
     * TDS 7.4: negotiate in the clear, then run the handshake inside the
     * pre-login packets.
     */
    private static PreLogin negotiateEncryption(TdsChannel channel, Settings settings)
            throws IOException, SQLException {
        PreLogin preLogin = new PreLogin();
        preLogin.exchange(channel, Tds.ENCRYPT_ON, AccessToken.is(settings.secret()));
        if (!preLogin.supportsEncryption()) {
            // Without TLS the password would go over the wire in the LOGIN7
            // obfuscation, and that is a XOR, not encryption. seclume does
            // not do that - a server that refuses TLS is refused in turn.
            throw new SQLNonTransientConnectionException(
                    "the server refuses encryption - seclume does not log in unencrypted",
                    "08001");
        }
        TdsTls tls = TdsTls.create(channel.raw(), settings.host(), settings.port(),
                settings.trustServerCertificate());
        tls.handshake();
        channel.useTls(tls);
        return preLogin;
    }

    /**
     * TDS 8.0: TLS around everything, before a single TDS byte is written.
     *
     * <p>Nothing is negotiated in the clear here - not the encryption, not
     * the pre-login. What tells the server that this is a TDS 8.0 client
     * rather than something else that dialled port 1433 is the ALPN name
     * {@code tds/8.0}, and a server that does not select it is refused by
     * the handshake rather than talked to.
     *
     * <p>This is also the only route by which SQL Server reaches seclume's
     * own TLS stack, and therefore the only route to a client certificate
     * whose private key never becomes a Java object. The nesting 7.4 uses is
     * TLS 1.2 by construction and can never carry a 1.3 client.
     */
    private static void startStrictEncryption(TdsChannel channel, Settings settings)
            throws IOException {
        channel.useTls(space.seclume.internal.TlsLayers.start(settings.tlsStack(),
                channel.raw(), settings.host(), settings.port(),
                !settings.trustServerCertificate(), settings.identity(), TdsVersion.ALPN));
    }

    // ---- statements ------------------------------------------------------

    /**
     * Runs a statement as text and hands every row to the handler.
     *
     * <p>The handler sees a window onto the receive buffer, not a copy: after
     * it returns, the next row overwrites what it looked at. Whoever wants to
     * keep a value copies it out.
     *
     * @param handler may be {@code null} if the rows are of no interest
     */
    public TokenStream sqlBatch(String sql, TokenStream.RowHandler handler) throws SQLException {
        try {
            WireBuffer out = beginMessage();
            putAllHeaders(out);
            String waiting = takePending();
            if (waiting != null) {
                // One text, two statements - and one wait instead of two.
                putUtf16(out, waiting);
                putUtf16(out, "; ");
            }
            putUtf16(out, sql);
            channel.send(Tds.TYPE_SQL_BATCH);
            return readAnswer(handler);
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
    }

    /**
     * Runs a parameterised statement through {@code sp_executesql}.
     *
     * <p>This is SQL Server's prepared statement: the text with named
     * parameters in it, the declaration of those names, and the values - all
     * three as arguments of one stored procedure. The server caches the plan
     * under the text, so the second call with the same text is the fast one
     * without anything having to be prepared explicitly.
     *
     * <p>The procedure is addressed by its number, not its name: {@code 0xffff}
     * in the name length says "an id follows", and 10 is
     * {@code sp_executesql}. That saves the server the name lookup.
     */
    public TokenStream rpc(String sql, String declaration, TdsParameters parameters,
                           TokenStream.RowHandler handler) throws SQLException {
        flushPending();
        try {
            WireBuffer out = beginMessage();
            putAllHeaders(out);
            out.putShortLe((short) 0xffff);
            out.putShortLe((short) PROC_SP_EXECUTESQL);
            out.putShortLe((short) 0);                // no options
            TdsParameters.writeStatementText(out, sql);
            TdsParameters.writeStatementText(out, declaration);
            parameters.writeAll(out);
            channel.send(Tds.TYPE_RPC);
            return readAnswer(handler);
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
    }



    // ---- session state that rides along ---------------------------------

    /**
     * Runs a session setting with the <b>next</b> statement, not now.
     *
     * <p>{@code set implicit_transactions on} on its own is a full round trip
     * in which the database does nothing, and a framework sends it twice per
     * transaction - once to open one and once to put the connection back as it
     * found it. Sent together with the statement that follows, it is free.
     *
     * <p><b>Only a batch can carry it.</b> The obvious second way - the
     * setting as an {@code sp_executesql} call in front of the real one, in
     * the same message - does not work, and the way it fails is quiet: a
     * {@code SET} inside {@code sp_executesql} lives in that call's own scope
     * and is gone when it returns. Measured, not read: with the setting sent
     * that way the transaction was simply not open, and a row that should have
     * been held back was visible to another connection. So a prepared
     * statement sends what is waiting first and pays the round trip.
     *
     * <p>Only settings go through here: things whose answer nobody looks at.
     */
    public void runLater(String sql) {
        pending = pending == null ? sql : pending + "; " + sql;
    }

    /**
     * A session context to set with the next statement - kept apart from the
     * settings so that a reset can drop it: sent after a RESETCONNECTION, a
     * context meant for the previous borrower would reach the next one.
     */
    public void contextLater(String sql) {
        pendingContext = pendingContext == null ? sql : pendingContext + "; " + sql;
    }

    /** Drops a context not yet sent - see contextLater. */
    public void dropPendingContext() {
        pendingContext = null;
    }

    /** Whether a setting is waiting for a statement to ride along with. */
    public boolean hasPending() {
        return pending != null || pendingContext != null;
    }

    /** Sends what is pending right now, for whoever cannot wait. */
    public void flushPending() throws SQLException {
        String sql = takePending();
        if (sql != null) {
            execute(sql);
        }
    }

    /** Takes the pending text and clears it - the caller sends it along. */
    private String takePending() {
        String sql = pending == null ? pendingContext
                : pendingContext == null ? pending : pending + "; " + pendingContext;
        pending = null;
        pendingContext = null;
        return sql;
    }


    /**
     * Opens a <b>server-side cursor</b> over a statement.
     *
     * <p>{@code sp_cursoropen} is an RPC by number (2). The handle comes back
     * in a {@code RETURNVALUE}, and every later fetch names it. That is what a
     * fetch size is for on this server: the rows stay there and come in
     * blocks, so a large query costs the memory of one block.
     *
     * @return the cursor handle
     */
    public int cursorOpen(String sql, String declaration, TdsParameters parameters)
            throws SQLException {
        flushPending();
        boolean bound = declaration != null && !declaration.isEmpty();
        try {
            WireBuffer out = beginMessage();
            putAllHeaders(out);
            out.putShortLe((short) 0xffff);
            out.putShortLe((short) PROC_SP_CURSOROPEN);
            out.putShortLe((short) 0);
            TdsParameters.writeOutputInt(out, "", null);       // the cursor
            TdsParameters.writeStatementText(out, sql);
            TdsParameters.writeOutputInt(out, "", bound
                    ? CURSOR_FORWARD_ONLY | CURSOR_PARAMETERIZED : CURSOR_FORWARD_ONLY);
            TdsParameters.writeOutputInt(out, "", CURSOR_READ_ONLY);
            TdsParameters.writeOutputInt(out, "", 0);          // row count
            if (bound) {
                // With PARAMETERIZED in scrollopt, the parameter declaration
                // follows as one more argument and the values behind it -
                // the same two things sp_executesql takes.
                TdsParameters.writeStatementText(out, declaration);
                parameters.writeAll(out);
            }
            channel.send(Tds.TYPE_RPC);
            TokenStream answer = readAnswer(null);
            Integer handle = answer.returned(0);
            if (handle == null || handle == 0) {
                throw new SQLException("the server opened no cursor and named no handle - "
                        + "without one the rows cannot be fetched in blocks");
            }
            cursorColumns = answer.columns();
            return handle;
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
    }

    /** The columns of the cursor - the open reports them, the fetches do not. */
    public java.util.List<TdsColumn> cursorColumns() {
        return cursorColumns;
    }

    /**
     * Reads the next block from a cursor.
     *
     * @return how many rows came; fewer than asked for means it was the last
     */
    public long cursorFetch(int handle, int rows, TokenStream.RowHandler handler)
            throws SQLException {
        try {
            WireBuffer out = beginMessage();
            putAllHeaders(out);
            out.putShortLe((short) 0xffff);
            out.putShortLe((short) PROC_SP_CURSORFETCH);
            out.putShortLe((short) 0);
            TdsParameters.writeInt(out, "", handle);
            TdsParameters.writeInt(out, "", FETCH_NEXT);
            TdsParameters.writeInt(out, "", 0);                   // row number
            TdsParameters.writeInt(out, "", rows);
            channel.send(Tds.TYPE_RPC);
            return readAnswer(handler).rowCount();
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
    }

    /** Gives a cursor back - a result set the caller stopped reading from. */
    public void cursorClose(int handle) throws SQLException {
        try {
            WireBuffer out = beginMessage();
            putAllHeaders(out);
            out.putShortLe((short) 0xffff);
            out.putShortLe((short) PROC_SP_CURSORCLOSE);
            out.putShortLe((short) 0);
            TdsParameters.writeInt(out, "", handle);
            channel.send(Tds.TYPE_RPC);
            readAnswer(null);
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
    }

    /**
     * A statement the server has compiled and named.
     *
     * <p>Held by the {@code PreparedStatement}, not by the session: the handle
     * belongs to the statement's lifetime and is given back when it closes.
     */
    public static final class Prepared {

        /** Explicit, so the module does not hand out a default constructor. */
        public Prepared() {
        }

        private int handle;
        private String declaration = "";

        public int handle() {
            return handle;
        }

        public boolean isPrepared() {
            return handle != 0;
        }

        /**
         * Whether the compiled statement still fits the row about to be sent.
         *
         * <p>A handle is compiled <b>with</b> its parameter declaration -
         * {@code @P14 nvarchar(1)} - and every row sent through it afterwards
         * is converted to those types. So a batch whose first row passed a
         * null (declared {@code nvarchar(1)}) and whose second passes
         * "DORMANT" does not fail: the server silently truncates it to "D".
         * That is a data error with no error message, and it is what a check
         * constraint caught here by accident. The declaration is therefore
         * kept and compared, and the statement is compiled again when it
         * changes.
         */
        boolean fits(String wanted) {
            return handle != 0 && declaration.equals(wanted);
        }
    }

    /**
     * {@code sp_prepexec}: compile and run in one call, and learn the handle.
     *
     * <p>This is the first row of a batch. Everything after it goes through
     * {@link #PROC_SP_EXECUTE} with nothing but the handle and the values -
     * which is the whole point, because {@code sp_executesql} carries the
     * complete statement text <b>and</b> the parameter declaration on every
     * single row, both in UTF-16.
     *
     * @return the update count of that first row
     */
    public long prepExec(Prepared prepared, String sql, TdsParameters parameters)
            throws SQLException {
        flushPending();
        try {
            String declaration = parameters.declaration();
            WireBuffer out = beginMessage();
            putAllHeaders(out);
            out.putShortLe((short) 0xffff);
            out.putShortLe((short) PROC_SP_PREPEXEC);
            out.putShortLe((short) 0);                  // no options
            TdsParameters.writeOutputInt(out, "", null);        // @handle, OUTPUT
            TdsParameters.writeStatementText(out, declaration); // @params
            TdsParameters.writeStatementText(out, sql);         // @stmt
            parameters.writeAll(out);
            channel.send(Tds.TYPE_RPC);

            TokenStream answer = readAnswer(null);
            Integer handle = answer.returned(0);
            if (handle == null || handle == 0) {
                throw new SQLException("sp_prepexec compiled the statement but named no "
                        + "handle - without one the rest of the batch cannot be sent by "
                        + "number", "HY000");
            }
            prepared.handle = handle;
            prepared.declaration = declaration;
            // updateCount(), not updateCounts(): the latter is only filled
            // when a number of answers was announced in advance, which is the
            // batch case. This is a single call with a single count.
            long count = answer.updateCount();
            return Math.max(count, 0);
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
    }

    /** Gives a compiled statement back. One round trip, at statement close. */
    public void unprepare(int handle) throws SQLException {
        flushPipeline();
        if (handle == 0) {
            return;
        }
        try {
            WireBuffer out = beginMessage();
            putAllHeaders(out);
            out.putShortLe((short) 0xffff);
            out.putShortLe((short) PROC_SP_UNPREPARE);
            out.putShortLe((short) 0);
            TdsParameters.writeInt(out, "", handle);
            channel.send(Tds.TYPE_RPC);
            readAnswer(null);
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
     * Many calls of the same statement in <b>one</b> message.
     *
     * <p>TDS allows several RPCs in a single request, separated by a byte:
     * {@code 0xFF} since TDS 7.2. Each of them carries its own parameters and
     * their types, so a batch in which one row passes {@code null} and the
     * next a number is no problem at all - the old objection to bundling was
     * about a different technique.
     *
     * <p>That turns a batch of five hundred rows from five hundred round trips
     * into a handful. The group is bounded for the same reason as everywhere
     * else: if both sides keep writing, both socket buffers fill and both
     * block.
     */
    public long[] rpcBatch(Prepared prepared, String sql, TdsParameters parameters,
                           int count, BatchBinder binder) throws SQLException {
        long[] counts = new long[count]; // seclume-allow: update counts, not a secret
        int at = 0;
        binder.bind(0);
        if (!prepared.fits(parameters.declaration())) {
            // The first row compiles the statement and brings the handle back.
            // It costs a round trip of its own - once per statement, not once
            // per batch - and every row after it travels as a handle and its
            // values instead of the whole statement text.
            if (prepared.isPrepared()) {
                unprepare(prepared.handle());
                prepared.handle = 0;
            }
            counts[0] = prepExec(prepared, sql, parameters);
            at = 1;
            if (at >= count) {
                return counts;
            }
        }
        flushPending();
        try {
            while (at < count) {
                int start = at;
                int sent = 0;
                WireBuffer out = beginMessage();
                putAllHeaders(out);
                while (at < count && sent < BATCH_ROWS && out.position() < BATCH_BYTES) {
                    binder.bind(at);
                    if (!prepared.fits(parameters.declaration())) {
                        // This row needs other types than the handle was
                        // compiled with - a longer string, a value where the
                        // last row had a null. Send what is gathered, then
                        // compile again for the rest.
                        break;
                    }
                    if (sent > 0) {
                        out.putByte((byte) RPC_SEPARATOR);
                    }
                    out.putShortLe((short) 0xffff);
                    out.putShortLe((short) PROC_SP_EXECUTE);
                    out.putShortLe((short) 0);        // no options
                    TdsParameters.writeInt(out, "", prepared.handle());
                    parameters.writeAll(out);
                    channel.sendFull(Tds.TYPE_RPC);   // full packets leave now
                    at++;
                    sent++;
                }
                if (sent == 0) {
                    // The very next row already needs another shape.
                    unprepare(prepared.handle());
                    prepared.handle = 0;
                    counts[at] = prepExec(prepared, sql, parameters);
                    at++;
                    flushPending();
                    continue;
                }
                channel.send(Tds.TYPE_RPC);
                TokenStream answer = readAnswer(null, sent);
                long[] reported = answer.updateCounts();
                for (int i = 0; i < sent; i++) {
                    counts[start + i] = i < reported.length ? Math.max(reported[i], 0) : 0;
                }
            }
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
        return counts;
    }

    /**
     * A transaction manager request - packet type 0x0e.
     *
     * <p>The one that matters here is {@code TM_PROPAGATE_XACT}: it hands the
     * server a coordinator's transaction cookie and gets back the descriptor
     * that every following request has to quote. Without it a distributed
     * transaction exists on the server but this session is not in it - the
     * statements would quietly run outside and commit by themselves.
     *
     * @param requestType one of the {@code TM_} constants in {@link Tds}
     * @param payload     the request payload, written as a US_VARBYTE
     */
    public TokenStream transactionManager(int requestType, byte[] payload,
                                          TokenStream.RowHandler handler) throws SQLException {
        try {
            WireBuffer out = beginMessage();
            putAllHeaders(out);
            out.putShortLe((short) requestType);
            out.putShortLe((short) (payload == null ? 0 : payload.length));
            if (payload != null) {
                for (byte value : payload) {
                    out.putByte(value);
                }
            }
            channel.send(Tds.TYPE_TRANSACTION_MANAGER);
            return readAnswer(handler);
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
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

    /**
     * From here on, an execution nobody is waiting for is buffered.
     *
     * <p>See {@link space.seclume.Pipeline} for what an application writes.
     * Whether a transaction is open is checked one layer up, in the
     * connection, because that is where auto-commit lives.
     */
    public void beginPipeline() {
        pipelining = true;
        pipelineGroup = 0;
        pipelineOpen = false;
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
     * <p>Only a statement the server has already compiled can be buffered: a
     * first execution has to come back with a handle before anything can quote
     * it, and that round trip cannot be avoided. So the first one goes out on
     * its own - once per statement, not once per block - and every execution
     * after it travels as a handle and its values.
     *
     * @return {@link java.sql.Statement#SUCCESS_NO_INFO} when it was buffered,
     *         because the count is not known yet and inventing one would be a
     *         lie; the real count when the execution had to go out at once
     */
    public long pipelineExecute(Prepared prepared, String sql, TdsParameters parameters)
            throws SQLException {
        if (!prepared.fits(parameters.declaration())) {
            // Either never compiled, or compiled for other types than these
            // values need. Both mean: send what is gathered, then compile.
            flushPipeline();
            if (prepared.isPrepared()) {
                unprepare(prepared.handle());
                prepared.handle = 0;
            }
            long count = prepExec(prepared, sql, parameters);
            record(sql, count);
            return count;
        }
        // Nothing here reaches the socket: writing into the send buffer cannot
        // fail, and the only call that can - flushPipeline, at the bound
        // below - reports for itself.
        WireBuffer out;
        if (!pipelineOpen) {
            flushPending();
            out = channel.begin();
            putAllHeaders(out);
            pipelineOpen = true;
        } else {
            out = channel.buffer();
            out.putByte((byte) RPC_SEPARATOR);
        }
        out.putShortLe((short) 0xffff);
        out.putShortLe((short) PROC_SP_EXECUTE);
        out.putShortLe((short) 0);                // no options
        TdsParameters.writeInt(out, "", prepared.handle());
        parameters.writeAll(out);
        pipelineGroup++;
        pipelineSql.add(sql);
        // Bounded for the reason the batch is bounded: if both sides keep
        // writing and neither reads, both socket buffers fill and both block.
        // The byte bound is the one that actually guards it.
        if (pipelineGroup >= BATCH_ROWS || out.position() >= BATCH_BYTES) {
            flushPipeline();
        }
        return java.sql.Statement.SUCCESS_NO_INFO;
    }

    /**
     * Sends what is buffered and reads the answers.
     *
     * <p>Called at the end of the block - and by the driver itself before
     * anything that really needs an answer, which is what keeps the block from
     * handing out a number the server never gave.
     */
    public void flushPipeline() throws SQLException {
        if (pipelineGroup == 0) {
            pipelineOpen = false;
            return;
        }
        int group = pipelineGroup;
        int groupStart = pipelineCount;
        pipelineGroup = 0;
        pipelineOpen = false;
        try {
            channel.send(Tds.TYPE_RPC);
            TokenStream answer = readAnswer(null, group);
            long[] reported = answer.updateCounts();
            for (int i = 0; i < group; i++) {
                keep(groupStart + i, i < reported.length ? Math.max(reported[i], 0) : 0);
            }
            pipelineCount = groupStart + group;
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        } catch (SQLException failed) {
            // Which one failed matters more than that one of them did: a block
            // of five inserts reporting only that something went wrong leaves
            // the caller to find out by reading the table.
            String which = groupStart < pipelineSql.size()
                    ? pipelineSql.get(groupStart)
                    : "(unknown)";
            throw new SQLException("a statement in the pipeline block failed. The group held "
                    + group + " statement(s), the first of them: " + which
                    + ". Nothing in the group reported a count, so whether any of them ran has "
                    + "to be established from the transaction, which is still open: "
                    + failed.getMessage(), failed.getSQLState(), failed);
        }
    }

    /**
     * Ends the block and returns what the server reported, in order.
     *
     * @return one count per execution, in the order they were written
     */
    public long[] endPipeline() throws SQLException {
        flushPipeline();
        pipelining = false;
        long[] counts = java.util.Arrays.copyOf(pipelineCounts, pipelineCount);
        pipelineCount = 0;
        pipelineSql.clear();
        return counts;
    }

    /** A count that was known at once - the first execution of a statement. */
    private void record(String sql, long count) {
        pipelineSql.add(sql);
        keep(pipelineCount, count);
        pipelineCount++;
    }

    private void keep(int at, long count) {
        if (at >= pipelineCounts.length) {
            pipelineCounts = java.util.Arrays.copyOf(pipelineCounts,
                    Math.max(pipelineCounts.length * 2, at + 8));
        }
        pipelineCounts[at] = count;
    }

    /**
     * Starts a message - and sends what the pipeline block is holding first.
     *
     * <p><b>The one door, for a reason that cost an afternoon.</b>
     * {@code channel.begin()} rewinds the send buffer, so calling it while
     * buffered RPCs are sitting there does not merely lose them: the count of
     * what is outstanding stays, and the next flush waits for answers to a
     * message that was never sent. The symptom is a driver that hangs, and the
     * cause is somewhere else entirely.
     *
     * <p>It was found by a query inside a block, because {@code sqlBatch} is
     * the one method here that does not call {@code flushPending} - so a rule
     * of the form "flush next to that" missed exactly the method that was
     * built differently. A single entry point cannot be missed that way.
     */
    private WireBuffer beginMessage() throws SQLException {
        drainPending();                      // a paused answer first - see resume
        flushPipeline();
        return channel.begin();
    }

    /** How often this session has waited for the server. */
    public long roundTrips() {
        return channel.roundTrips();
    }

    /**
     * Loads rows with {@code INSERT BULK}: the statement announces the
     * columns, then one bulk-load message carries their description and every
     * row, streamed out a packet at a time as it fills.
     *
     * @param statement the {@code INSERT BULK ...} text, columns declared as
     *                  {@code columns} say
     * @param rows      each row checked by {@link TdsBulk#check} before any of it
     *                  is written
     * @return the rows the server says it loaded
     */
    public long bulkLoad(String statement, java.util.List<TdsBulk.Column> columns,
                         java.util.Iterator<Object[]> rows) throws SQLException {
        // Alone: "Insert bulk cannot be used in a multi-statement batch", and a
        // setting waiting to ride along would make it one.
        flushPending();
        sqlBatch(statement, null);
        try {
            WireBuffer out = beginMessage();
            TdsBulk.writeMetadata(out, columns);
            long number = 0;
            while (rows.hasNext()) {
                Object[] row = rows.next();
                number++;
                try {
                    TdsBulk.check(columns, row, number);
                } catch (SQLException refused) {
                    // Rows already streamed cannot be taken back mid-message;
                    // ending it here, with the rows so far, and telling the
                    // server to drop them keeps the session in step.
                    abandonBulk(out);
                    throw refused;
                }
                TdsBulk.writeRow(out, columns, row);
                channel.sendFull(Tds.TYPE_BULK_LOAD);
            }
            TdsBulk.writeDone(out);
            channel.send(Tds.TYPE_BULK_LOAD);
            TokenStream answer = readAnswer(null);
            updateCount = answer.updateCount();
            return updateCount;
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
    }

    /**
     * Ends a bulk load whose next row was refused: the message is finished,
     * and an ATTENTION makes the server drop what it received. The rows
     * already sent are not loaded - in auto-commit mode the load is one
     * statement, and it is cancelled.
     */
    private void abandonBulk(WireBuffer out) throws SQLException {
        try {
            TdsBulk.writeDone(out);
            channel.send(Tds.TYPE_BULK_LOAD);
            cancel();
            try {
                readAnswer(null);
            } catch (SQLException expected) {
                // the cancellation answers as an error - that is the point
            }
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection(e);
        }
    }

    /** Short form for a statement whose rows are of no interest. */
    public long execute(String sql) throws SQLException {
        sqlBatch(sql, null);
        return updateCount;
    }

    /** Reads the answer and raises whatever the server complained about. */
    private TokenStream readAnswer(TokenStream.RowHandler handler)
            throws IOException, SQLException {
        return readAnswer(handler, 0);
    }

    /**
     * @param expectedCounts how many update counts to keep apart, 0 for none -
     *                       only a batch needs them one by one
     */
    private TokenStream readAnswer(TokenStream.RowHandler handler, int expectedCounts)
            throws IOException, SQLException {
        TokenStream tokens = new TokenStream();
        if (expectedCounts > 0) {
            tokens.expectCounts(expectedCounts);
        }
        channel.startStreaming();
        return pump(tokens, handler, true);
    }

    /** The answer whose rows are still arriving, and who takes them; see {@link #resume}. */
    private TokenStream pendingTokens;
    private TokenStream.RowHandler pendingHandler;

    /**
     * Reads the answer while it arrives - see TdsChannel.pump - and, where
     * the handler asks for it, stops after a packet and leaves the rest on the
     * wire until {@link #resume} or {@link #drainPending}.
     *
     * <p>That pause is what lets an application work on the first rows while
     * the rest is still on its way, as mssql-jdbc does; without it every
     * value was decoded only after the last packet had arrived, and a large
     * result took the network's time plus the application's instead of the
     * larger of the two.
     */
    private TokenStream pump(TokenStream tokens, TokenStream.RowHandler handler,
            boolean mayPause) throws IOException, SQLException {
        boolean done = channel.pump((in, end) -> {
            if (channel.messageType() != Tds.TYPE_TABULAR_RESULT) {
                throw new IOException("expected a result, got type 0x"
                        + Integer.toHexString(channel.messageType()));
            }
            return tokens.readComplete(in, 0, end, handler);
        }, mayPause && handler != null ? handler::pause : null);
        if (!done) {
            pendingTokens = tokens;
            pendingHandler = handler;
            return tokens;
        }
        pendingTokens = null;
        pendingHandler = null;
        return complete(tokens);
    }

    /** Whether an answer is paused with rows still to come. */
    public boolean isPaused() {
        return pendingTokens != null;
    }

    /**
     * Reads on in the paused answer, until the handler asks for a pause
     * again or the answer ends.
     *
     * @return whether it paused again
     */
    public boolean resume() throws SQLException {
        if (pendingTokens == null) {
            return false;
        }
        try {
            pump(pendingTokens, pendingHandler, true);
            return pendingTokens != null;
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            pendingTokens = null;
            pendingHandler = null;
            throw brokenConnection(e);
        }
    }

    /**
     * Reads the rest of a paused answer, before anything else uses the
     * connection: TDS is one answer after the other, and a request sent into
     * the middle of one would read its tail as its own answer.
     */
    public void drainPending() throws SQLException {
        if (pendingTokens == null) {
            return;
        }
        try {
            pump(pendingTokens, pendingHandler, false);
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            pendingTokens = null;
            pendingHandler = null;
            throw brokenConnection(e);
        } finally {
            pendingTokens = null;
            pendingHandler = null;
        }
    }

    /** What the end of an answer settles: counts, database, transaction, errors. */
    private TokenStream complete(TokenStream tokens) throws IOException, SQLException {
        int type = channel.messageType();
        if (type != Tds.TYPE_TABULAR_RESULT) {
            throw new IOException("expected a result, got type 0x" + Integer.toHexString(type));
        }
        tokens.finish();
        updateCount = tokens.updateCount();
        if (!tokens.database().isEmpty()) {
            database = tokens.database();
        }
        if (tokens.transactionChanged()) {
            // The server opened or closed a transaction; from here on the
            // requests have to quote the new descriptor.
            transactionDescriptor = tokens.transactionDescriptor();
        }
        if (tokens.failure() != null) {
            // The stream was read to the end first - only then is the error
            // raised, so the connection stays usable.
            throw tokens.failure();
        }
        // The acknowledgement, if one is owed. Read here and not left for the
        // next statement - see TdsChannel#drainAttention. The two conditions
        // are not the same thing: the ATTENTION bit says the server stopped
        // mid-answer, the drain says an ATTENTION was written at all, and a
        // cancellation that arrived just as the statement finished shows only
        // the second. Both mean the caller asked for this to stop.
        boolean cancelled = tokens.wasCancelled();
        if (channel.drainAttention()) {
            cancelled = true;
        }
        if (cancelled) {
            // After the failure check, not before it: a statement that was
            // both wrong and cancelled should report what was wrong with it.
            // And after the whole stream was read, for the same reason as
            // above - the answer may have carried rows before the DONE that
            // says it was cut short, and leaving them unread would put the
            // next call one message behind.
            throw new SQLException("the statement was cancelled", "HY008");
        }
        return tokens;
    }

    /**
     * Tells the server to stop what this connection is doing.
     *
     * <p>Eight bytes on the same connection - see
     * {@link TdsChannel#sendAttention}. Nothing is read here: the answer,
     * including the acknowledgement, belongs to the thread that is already
     * waiting for it, and this one only writes.
     *
     * <p>Safe from another thread, and that is the only way it is called.
     *
     * @throws SQLException if the ATTENTION could not be written
     */
    public void cancel() throws SQLException {
        try {
            channel.sendAttention();
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw new SQLNonTransientConnectionException(
                    "the cancellation could not be sent: " + e.getMessage(), "08006", e);
        }
    }

    /**
     * The 22-byte header block. The transaction descriptor is zero outside an
     * explicit transaction, and inside one it is what the server handed out.

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
    private void putAllHeaders(WireBuffer out) {
        out.putIntLe(ALL_HEADERS_SIZE);
        out.putIntLe(TRANSACTION_HEADER_SIZE);
        out.putShortLe((short) HEADER_TYPE_TRANSACTION);
        out.putLongLe(transactionDescriptor);
        out.putIntLe(1);                              // outstanding requests
    }

    /** Statement text goes over the wire as UTF-16LE, without a length. */
    private static void putUtf16(WireBuffer out, String text) {
        for (int i = 0; i < text.length(); i++) {
            out.putShortLe((short) text.charAt(i));
        }
    }

    private SQLException brokenConnection(Exception cause) {
        close();
        return new SQLNonTransientConnectionException(
                "the connection to " + serverName + " broke: " + cause.getMessage(), "08006", cause);
    }

    // ---- state -----------------------------------------------------------

    /** The transaction descriptor the following requests will quote. */
    public void transactionDescriptor(long descriptor) {
        this.transactionDescriptor = descriptor;
    }

    public long transactionDescriptor() {
        return transactionDescriptor;
    }

    /** The row count of the last statement; -1 if the server reported none. */
    public long updateCount() {
        return updateCount;
    }

    public String serverName() {
        return serverName;
    }

    public int serverVersion() {
        return serverVersion;
    }

    /**
     * How this driver logs in, which on TDS is one way and only one.
     *
     * <p>A SQL login in a {@code LOGIN7} packet, with the password under the
     * obfuscation TDS calls encryption and nobody should: a nibble swap and an
     * XOR with a constant. That it is not a secret is exactly why this driver
     * refuses to log in without TLS underneath it - see
     * {@code negotiateEncryption}.
     *
     * <p>An integrated login says Kerberos, a token login says so too.
     */
    public String authenticationMethod() {
        return method;
    }

    /** How this session logged in - set once, right after the login. */
    private String method = "SQL login (LOGIN7, inside TLS)";

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

    /** The database the session is in. */
    public String database() {
        return database;
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

    @Override
    public void close() {
        channel.close();
    }
}
