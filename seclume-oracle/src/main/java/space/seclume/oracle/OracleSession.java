package space.seclume.oracle;

import java.io.IOException;
import java.sql.SQLException;
import java.sql.SQLNonTransientConnectionException;

import space.seclume.internal.WireBuffer;
import space.seclume.oracle.net.NsChannel;
import space.seclume.oracle.net.OracleColumn;
import space.seclume.oracle.net.NsPacket;
import space.seclume.oracle.net.TtcAuth;
import space.seclume.oracle.net.TtcClose;
import space.seclume.oracle.net.TtcFastAuth;
import space.seclume.oracle.net.TtcLob;
import space.seclume.oracle.net.TtcLogin;
import space.seclume.oracle.net.TtcMessage;
import space.seclume.oracle.net.TtcParameters;
import space.seclume.oracle.net.TtcFetch;
import space.seclume.oracle.net.TtcQuery;
import space.seclume.oracle.net.TtcResult;
import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.secret.SecretProvider;

/**
 * A session with an Oracle instance.
 *
 * <p>The layer below JDBC: connect, log in, run statements, read results. It
 * knows the protocol but no {@code Connection}.
 *
 * <p>The password only lives for the length of the login and only in native
 * memory. The session does not keep it - not even for a reconnect; for that the
 * {@link SecretProvider} is asked again.
 *
 * <p>One thing here has no counterpart in the other three drivers: <b>Oracle
 * counts the messages</b>. Every call carries a sequence number that goes up by
 * one, and the server checks it. After the combined opening and the login it
 * stands at three, which is why the first statement uses that.
 */
public final class OracleSession implements AutoCloseable {

    /** How many rows the server may send along with the answer. */
    private static final int PREFETCH_ROWS = 100;
    /** The most rows one fetch asks for. */
    private static final int MAX_FETCH_ROWS = 5000;
    /** About how many bytes one fetch should bring. */
    private static final long FETCH_BYTES = 1 << 20;

    /**
     * The rows the next fetch asks for: twice the last, as long as a fetch
     * stays near a megabyte by what the last rows actually weighed.
     *
     * <p>A result read to its end costs one round trip per fetch, and a fixed
     * hundred rows made ten thousand rows a hundred round trips where ojdbc
     * takes some forty - on a LAN that alone made seclume half as fast on a
     * large result. Starting at a hundred keeps a small result as cheap as
     * before; measuring the rows keeps a wide one - a JSON document, a vector
     * - from asking the server for hundreds of megabytes at once.
     */
    static int nextFetch(int last, long bytes, long rows) {
        if (rows <= 0) {
            return last;
        }
        long perRow = Math.max(1, bytes / rows);
        long next = Math.min((long) last * 2, Math.min(MAX_FETCH_ROWS, FETCH_BYTES / perRow));
        return (int) Math.max(PREFETCH_ROWS, next);
    }

    /** Connection settings. Not the password, only its source. */
    public record Settings(String host, int port, String service, String user,
                           SecretProvider secret, int connectTimeoutMillis, HostList hosts,
                           ResultLimit resultLimit, TlsMode tls,
                           space.seclume.internal.jdbc.TlsStack tlsStack,
                           space.seclume.tls.ClientIdentity identity) {

        /**
         * Without a client certificate - what almost every connection is.
         */
        public Settings(String host, int port, String service, String user,
                        SecretProvider secret, int connectTimeoutMillis, HostList hosts,
                        ResultLimit resultLimit, TlsMode tls,
                        space.seclume.internal.jdbc.TlsStack tlsStack) {
            this(host, port, service, user, secret, connectTimeoutMillis, hosts,
                    resultLimit, tls, tlsStack, null);
        }

        /**
         * With a TLS mode but the ordinary stack.
         *
         * <p>Which implementation carries TLS is a separate decision from how
         * much TLS is asked for - see
         * {@link space.seclume.internal.jdbc.TlsStack} - and almost nobody
         * makes it, so it defaults here rather than at every call site.
         */
        public Settings(String host, int port, String service, String user,
                        SecretProvider secret, int connectTimeoutMillis, HostList hosts,
                        ResultLimit resultLimit, TlsMode tls) {
            this(host, port, service, user, secret, connectTimeoutMillis, hosts,
                    resultLimit, tls, space.seclume.internal.jdbc.TlsStack.JSSE, null);
        }

        /** Without a result limit - what a URL without the option means. */
        public Settings(String host, int port, String service, String user,
                        SecretProvider secret, int connectTimeoutMillis, HostList hosts) {
            this(host, port, service, user, secret, connectTimeoutMillis, hosts,
                    ResultLimit.NONE, TlsMode.OFF);
        }

        /** With a result limit but without encryption - see the tls component. */
        public Settings(String host, int port, String service, String user,
                        SecretProvider secret, int connectTimeoutMillis, HostList hosts,
                        ResultLimit resultLimit) {
            this(host, port, service, user, secret, connectTimeoutMillis, hosts,
                    resultLimit, TlsMode.OFF);
        }

        public Settings(String host, int port, String service, String user,
                        SecretProvider secret) {
            this(host, port, service, user, secret, 10_000);
        }

        /** One listener - the ordinary case, and what a URL without a comma means. */
        public Settings(String host, int port, String service, String user,
                        SecretProvider secret, int connectTimeoutMillis) {
            this(host, port, service, user, secret, connectTimeoutMillis,
                    HostList.of(host, port));
        }

        /** The same settings pointed at another listener of the list. */
        Settings at(HostList.Host server) {
            return new Settings(server.host(), server.port(), service, user, secret,
                    connectTimeoutMillis, hosts, resultLimit, tls, tlsStack, identity);
        }

        /** The {@code (DESCRIPTION=...)} the listener wants. */
        String connectString() {
            return "(DESCRIPTION=(ADDRESS=(PROTOCOL=" + (tls.demands() ? "TCPS" : "TCP")
                    + ")(HOST=" + host + ")(PORT=" + port
                    + "))(CONNECT_DATA=(SERVICE_NAME=" + service
                    + ")(CID=(PROGRAM=seclume)(HOST=seclume)(USER=seclume))))";
        }
    }

    private ResultLimit resultLimit = ResultLimit.NONE;
    /** How many output binds the next answer carries - see query(..). */
    private int returningCount;
    /** Whether the cursor of the last query still has rows - see fetchMore. */
    private boolean moreRows;
    /** The cursor the last query left open, for the next block. */
    private int openCursor;
    private final NsChannel channel;
    private int sequence = 3;
    private long rows;
    private boolean autoCommit = true;
    /**
     * Whether something ran that is not committed yet.
     *
     * <p>Only for the manual mode: with auto-commit the server commits by
     * itself, and asking it to commit again would be a round trip for nothing.
     */
    private boolean inTransaction;

    /**
     * Whether every transaction is to be read-only.
     *
     * <p>Oracle has no session setting for it. {@code SET TRANSACTION READ
     * ONLY} holds for one transaction and has to be its first statement, so
     * it is sent in front of the first statement of each one - see
     * {@link #beginReadOnlyIfAsked}.
     */
    private boolean readOnlyTransactions;

    private OracleSession(NsChannel channel) {
        this.channel = channel;
        channel.piggyback(this::returnCursors);
    }

    /**
     * What an authenticated Oracle stream is, once it has left its session.
     *
     * <p>Two facts beside the socket, and the second one is Oracle's alone.
     * The protocol version decides whether a packet's length field takes two
     * bytes or four - read it wrongly and the first packet is misframed. And
     * <b>the sequence number</b>: every call carries one, the server checks
     * it, and a session that resumes with the wrong number is refused by the
     * server rather than by anything here. No other of the four databases
     * counts its calls.
     *
     * @param stream the socket, still logged in, between calls
     */
    public record Detached(space.seclume.internal.Transport stream, int protocolVersion,
                           int sequence, boolean inTransaction,
                           space.seclume.internal.TlsLayer tls) {

        /** A stream that was in the clear, and therefore carries no encryption. */
        public Detached(space.seclume.internal.Transport stream, int protocolVersion,
                        int sequence, boolean inTransaction) {
            this(stream, protocolVersion, sequence, inTransaction, null);
        }
    }

    /**
     * Hands the authenticated stream over and finishes this session object.
     *
     * <p>The fourth of four, and the two usual refusals - not mid-call, and
     * not encrypted on the JDK's TLS, whose keys will not leave the
     * {@code SSLEngine}; on seclume's own stack the encryption travels with
     * the stream - plus one of its own: an open cursor stays with the session
     * that opened it, and a successor that inherited the stream without being
     * told the cursor id would leave it open until the session ends. Oracle
     * counts those, and runs out at {@code open_cursors}.
     */
    public Detached detach() throws SQLException {
        if (!channel.isIdle()) {
            throw new SQLException("this session has work in flight - a stream can only be "
                    + "handed over between calls", "25000");
        }
        if (channel.isEncrypted() && !channel.encryptionCanTravel()) {
            throw new SQLException("this session is encrypted on the JDK's TLS, whose keys "
                    + "cannot leave the SSLEngine that holds them - so the stream cannot be "
                    + "handed to another session. Open it on seclume's own TLS stack, or "
                    + "terminate TLS where the login happens", "0A000");
        }
        if (openCursor != 0 || !cursors.isEmpty()) {
            throw new SQLException("cursors are open on this session - close them before "
                    + "handing the stream over, or the server keeps them until it ends",
                    "25000");
        }
        space.seclume.internal.TlsLayer tls = channel.tlsLayer();
        Detached detached = new Detached(channel.transport(), channel.protocolVersion(),
                sequence, inTransaction, tls);
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
                    + "described between calls", "25000");
        }
        if (channel.isEncrypted() && !channel.encryptionCanTravel()) {
            throw new SQLException("this session is encrypted on the JDK's TLS, whose keys "
                    + "cannot leave the SSLEngine that holds them", "0A000");
        }
        if (openCursor != 0 || !cursors.isEmpty()) {
            throw new SQLException("cursors are open on this session - close them first",
                    "25000");
        }
        return new Detached(channel.transport(), channel.protocolVersion(), sequence,
                inTransaction, channel.tlsLayer());
    }

    /**
     * Continues a session somebody else authenticated.
     *
     * <p>No CONNECT, no login, no type negotiation - the server settled all of
     * that with whoever opened it. What cannot be derived is handed in: the
     * protocol version, because it decides the framing, and the sequence
     * number, because the server is counting.
     *
     * <p>The stream has to be between calls, and only the caller can know it.
     */
    public static OracleSession resume(space.seclume.internal.Transport stream,
                                       int protocolVersion, int sequence,
                                       boolean inTransaction) {
        return resume(stream, protocolVersion, sequence, inTransaction, null);
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
    public static OracleSession resume(space.seclume.internal.Transport stream,
                                       int protocolVersion, int sequence,
                                       boolean inTransaction,
                                       space.seclume.internal.TlsLayer tls) {
        OracleSession session = new OracleSession(tls == null
                ? NsChannel.over(stream, protocolVersion)
                : NsChannel.over(stream, protocolVersion, tls));
        session.sequence = sequence;
        session.inTransaction = inTransaction;
        session.autoCommit = !inTransaction;
        return session;
    }

    /** The transport carrying this session, for whoever may take it apart. */
    public space.seclume.internal.Transport transport() {
        return channel.transport();
    }

    /** Whether the <b>driver</b> has nothing in flight - half the quiescent point. */
    public boolean isIdle() {
        return channel.isIdle();
    }

    /**
     * How this driver logs in to Oracle.
     *
     * <p>O5LOGON against the 12c verifier: the server sends a session key and
     * a salt, the client derives a key from the password with PBKDF2 and
     * AES-256, and what goes back is a wrapped session key rather than
     * anything resembling the password. The older 11g verifier is not
     * implemented, and external authentication is not either, so this is the
     * one truthful answer.
     */
    public String authenticationMethod() {
        return "O5LOGON (12c verifier, AES-256)";
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
            if (answer[0] == null) {
                answer[0] = row.text(0);
            }
        });
        return answer[0];
    }

    /**
     * Whether a described result needs a define before its rows can be read:
     * it has a JSON or VECTOR column not yet asked for inline. Not with an
     * object column in it - a define for that would need its type's id,
     * which the description is not kept with.
     */
    public static boolean needsDefine(java.util.List<OracleColumn> columns) {
        boolean wanted = false;
        for (OracleColumn column : columns) {
            if (column.type() == OracleColumn.TYPE_OBJECT || column.inline()) {
                return false;
            }
            wanted |= column.needsDefine();
        }
        return wanted;
    }

    /**
     * Gives the cursor a define that brings JSON and VECTOR values in the
     * row, and returns the columns as they read from now on. One round trip,
     * once per cursor: the server keeps the define with it.
     */
    public java.util.List<OracleColumn> define(int cursorId, java.util.List<OracleColumn> columns)
            throws SQLException {
        try {
            space.seclume.oracle.net.TtcQuery.sendDefine(channel, nextCall(), cursorId, columns);
            TtcResult result = readAnswer(null, columns);
            if (result.isFailure()) {
                throw new SQLException("the server refused the define: "
                        + result.errorText(), "HY000");
            }
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection("the connection broke while defining the columns", e);
        }
        java.util.List<OracleColumn> inline = new java.util.ArrayList<>(columns.size());
        for (OracleColumn column : columns) {
            inline.add(column.withInline());
        }
        return java.util.List.copyOf(inline);
    }

    /** Oracle's region names by number, asked once - see {@link #regionName}. */
    private java.util.Map<Integer, String> regions;
    /** The session's and the database's zone, asked once - see {@link #zones}. */
    private java.time.ZoneId[] zones;

    /**
     * The name of a time zone region, from the number a
     * {@code TIMESTAMP WITH TIME ZONE} carries.
     *
     * <p>The numbers are Oracle's own and come with its time zone file, so
     * the server is asked rather than a table kept here that would go stale
     * with the next file: every region, stamped into a value of that type,
     * and the number read back off the wire the same way a user's value is.
     * Six hundred short rows, once per connection and only for one that
     * meets a region at all.
     *
     * @return the name, or {@code null} for a number the server did not list
     */
    public String regionName(int id) throws SQLException {
        if (regions == null) {
            java.util.Map<Integer, String> names = new java.util.HashMap<>();
            query("select tzname, from_tz(timestamp '2000-01-01 00:00:00', tzname) "
                    + "from (select distinct tzname from v$timezone_names) order by 1", row -> {
                        if (!row.isNull(1)) {
                            names.putIfAbsent(space.seclume.oracle.net.OracleDate.regionId(
                                    row.source(), row.cellAt(1)), row.text(0));
                        }
                    });
            regions = names;
        }
        return regions.get(id);
    }

    /**
     * The session's zone and the database's, in that order.
     *
     * <p>A {@code TIMESTAMP WITH LOCAL TIME ZONE} travels in the database's
     * zone and is read in the session's. Asked of the server rather than
     * remembered from the login, so a session that was handed over reads
     * right; an ALTER SESSION after the first such value is not seen.
     */
    public java.time.ZoneId[] zones() throws SQLException {
        if (zones == null) {
            String[] answer = new String[2];
            query("select sessiontimezone, dbtimezone from dual", row -> {
                answer[0] = row.text(0);
                answer[1] = row.text(1);
            });
            zones = new java.time.ZoneId[] {zone(answer[0]), zone(answer[1])};
        }
        return zones;
    }

    private static java.time.ZoneId zone(String name) {
        try {
            return java.time.ZoneId.of(name.trim());
        } catch (RuntimeException unknown) {
            return java.time.ZoneOffset.UTC;
        }
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
    private static final HostList.Roles<OracleSession> ROLES = new HostList.Roles<>() {

        @Override
        public space.seclume.internal.jdbc.ServerRole of(OracleSession session) throws SQLException {
            try {
                return space.seclume.internal.jdbc.ServerRole.read(session.askOneValue(
                        space.seclume.internal.jdbc.ServerRole.ORACLE));
            } catch (SQLException refused) {
                return space.seclume.internal.jdbc.ServerRole.UNKNOWN;
            }
        }

        @Override
        public void giveBack(OracleSession session) {
            session.close();
        }
    };

    /**
     * What a listener's REFUSE says, as the error it is.
     *
     * <p>The refusal carries the listener's own error in its text -
     * {@code (DESCRIPTION=(ERR=12516)...)} - and that number is the whole
     * diagnosis: 12514 a service the listener does not know, 12516/12519/12520
     * no free server process this moment. Until 25.09.2026 it was dropped and
     * the message said only "REFUSE instead of ACCEPT"; a test that logs in
     * many times quickly found the difference to the vendor driver, which
     * names the number. The busy ones are transient: the same login a moment
     * later gets in.
     */
    static SQLException refused(String reason) {
        java.util.regex.Matcher err = java.util.regex.Pattern.compile("\\(ERR=(\\d+)\\)")
                .matcher(reason == null ? "" : reason);
        if (!err.find()) {
            return new SQLNonTransientConnectionException("the listener refused the connection"
                    + (reason == null || reason.isBlank() ? "" : ": " + reason), "08001");
        }
        int code = Integer.parseInt(err.group(1));
        String message = String.format("ORA-%05d: the listener refused the connection%s", code,
                switch (code) {
                    case 12514 -> " - it does not know this service";
                    case 12516, 12519, 12520 -> " - no free server process at the moment";
                    case 12505 -> " - it does not know this SID";
                    default -> "";
                });
        return switch (code) {
            case 12516, 12519, 12520 ->
                    new java.sql.SQLTransientConnectionException(message, "08001", code);
            default -> new SQLNonTransientConnectionException(message, "08001", code);
        };
    }

    /** Connects, opens and logs in - three steps that the server ties together. */
    public static OracleSession open(Settings settings) throws SQLException {
        // One listener: a plain connect. Several: the next one when a listener
        // cannot be reached - and only then, see HostList.
        // With several servers and a preference in the URL, each one is asked
        // what it is before its connection is kept - see TargetServer. With
        // one server, or none asked for, nothing is asked and this is the
        // connect it always was.
        return settings.hosts().open(server -> openOne(settings.at(server)), ROLES);
    }

    private static OracleSession openOne(Settings settings) throws SQLException {
        // The expensive one: a physical connect, the TLS handshake and the
        // login. Recorded around the whole of it, because that is the number
        // a pool's warm-up time is made of. See space.seclume.jfr.
        space.seclume.jfr.SeclumeEvents.ConnectionOpen event =
                space.seclume.jfr.Observed.beginConnect();
        OracleSession opened = null;
        try {
            opened = connectAndLogIn(settings);
            space.seclume.internal.Transports.loggedIn(opened.transport());
            return opened;
        } finally {
            space.seclume.jfr.Observed.endConnect(event, "oracle",
                    settings.host() + ":" + settings.port(), settings.service(),
                    opened == null ? null : opened.tlsDescription(), opened != null);
        }
    }

    /**
     * Connects, and starts over once if the listener asks.
     *
     * <p>A TCPS listener answers the first {@code CONNECT} with
     * {@code RESEND} rather than {@code ACCEPT}. That is not a fault and not
     * a retry after one - it is the ordinary course of events there, and a
     * plaintext listener never does it, which is why it stayed invisible
     * until there was a TCPS listener to test against.
     *
     * <p>What {@code RESEND} asks for is the whole connection again, not the
     * packet again. Sending the packet a second time down the same socket
     * gets a fatal {@code unexpected_message} alert, because by then the
     * server has finished with that TLS session - which is the sort of thing
     * only a real server tells you.
     *
     * <p>Once, and once only: a listener that asks twice is not negotiating,
     * it is looping.
     */
    private static OracleSession connectAndLogIn(Settings settings) throws SQLException {
        NsChannel channel;
        try {
            channel = NsChannel.connect(settings.host(), settings.port(),
                    settings.connectTimeoutMillis());
            // Before the login: a login that fails is exactly when somebody
            // wants to know what the server said. See space.seclume.Flight.
            channel.recordFlight(space.seclume.internal.FlightRecorder.from(null));
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            // Not brokenConnection: there is no channel yet to close, and a
            // listener that cannot be reached is 08001 rather than 08006.
            throw new SQLNonTransientConnectionException(
                    "cannot reach " + settings.host() + ":" + settings.port(), "08001", e);
        }
        if (settings.tls().demands()) {
            try {
                channel.startTls(settings.host(), settings.port(),
                        settings.tls().verifies(), settings.tlsStack(), settings.identity());
            } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
                channel.close();
                throw new SQLNonTransientConnectionException(
                        "TLS to " + settings.host() + ":" + settings.port() + " failed: "
                        + e.getMessage(), "08001", e);
            }
        }
        try {
            int type = channel.sendConnect(settings.connectString());
            if (type == NsPacket.TYPE_RESEND) {
                // Over TCPS this is the ordinary course of events, not a
                // fault: the listener has established the session - its own
                // log says so - and handed the socket to a server process,
                // which brings up a TLS session of its own. So the answer to
                // RESEND is a second handshake on the same socket and then
                // the same CONNECT again.
                //
                // The two wrong readings both fail in a way that says what
                // they are. Resending the packet without a new handshake
                // gets a plaintext fatal alert, because the new peer is
                // waiting for a ClientHello. Opening a new TCP connection
                // gets RESEND again, because a new connection starts at the
                // listener. A plaintext listener never does any of this,
                // which is why it stayed invisible until there was a TCPS
                // one to test against.
                channel.startTls(settings.host(), settings.port(),
                        settings.tls().verifies(), settings.tlsStack(), settings.identity());
                type = channel.sendConnect(settings.connectString());
            }
            if (type == NsPacket.TYPE_REFUSE) {
                throw refused(channel.readRefuse());
            }
            if (type != NsPacket.TYPE_ACCEPT) {
                throw new SQLNonTransientConnectionException(
                        "the listener answered with " + NsPacket.typeName(type)
                        + " instead of ACCEPT", "08001");
            }
            channel.readAccept();

            // From here on it is the login alone - the listener has accepted
            // and TLS, where there is any, is up. Timed apart from the
            // connect: Oracle's own is the longest of the four and folding
            // the two together hides which half is slow. See
            // SeclumeEvents.Authentication.
            space.seclume.jfr.SeclumeEvents.Authentication event =
                    space.seclume.jfr.Observed.beginLogin();
            boolean loggedIn = false;
            try {
                TtcAuth.Challenge challenge = TtcFastAuth.open(channel, "seclume",
                        settings.user());
                channel.nextPacketCarriesTheCredential();
                TtcLogin.phaseTwo(channel, settings.user(), settings.secret(), challenge,
                        settings.connectString());
                OracleSession session = new OracleSession(channel);
                session.setResultLimit(settings.resultLimit());
                loggedIn = true;
                return session;
            } finally {
                space.seclume.jfr.Observed.endLogin(event, "oracle",
                        settings.host() + ":" + settings.port(), "o5logon", loggedIn);
            }
        } catch (space.seclume.internal.WireBuffer.Truncated e) {
            // Before the RuntimeException clause, and that order is the fix:
            // Truncated is an IllegalStateException, so it used to leave here
            // as itself. Anything that can answer on the listener's port
            // reaches this parser before a credential is exchanged, and an
            // answer that runs out mid-field came out as an unchecked
            // exception rather than as a login that failed.
            channel.close();
            throw new SQLNonTransientConnectionException(
                    "the server's answer is not Oracle TNS: " + e.getMessage(), "08001", e);
        } catch (SQLException | RuntimeException e) {
            channel.close();
            throw e;
        } catch (IOException e) {
            channel.close();
            throw new SQLNonTransientConnectionException(
                    "the login to " + settings.host() + " failed", "08001", e);
        }
    }

    /**
     * Runs a statement and hands every row to the handler.
     *
     * <p>The handler sees a window onto the receive buffer, not a copy: after
     * it returns, the next row overwrites what it looked at.
     *
     * @param handler may be {@code null} if the rows are of no interest
     */
    public TtcResult query(String sql, TtcResult.RowHandler handler) throws SQLException {
        return query(sql, null, handler);
    }

    /**
     * The same with bind variables.
     *
     * <p>The values travel in the same message as the text - Oracle has no
     * separate prepare step on the wire, so a prepared statement costs no
     * extra round trip. The reason to use one here is safety, not speed:
     * pasting values into the text would be an SQL injection.
     *
     * @param binds may be {@code null} or empty
     */
    public TtcResult query(String sql, space.seclume.oracle.net.TtcBinds binds,
                           TtcResult.RowHandler handler) throws SQLException {
        return query(sql, binds, handler, 0, 1, null);
    }

    /**
     * The same, with a cursor the server already has and with several sets of
     * values.
     *
     * <p>Two things ride on this, and both matter more than they look:
     *
     * <ul>
     *   <li>Handing the <b>cursor number</b> back means the server does not
     *       parse the text again - and, more importantly, does not open a new
     *       cursor. Without it a connection that runs the same statement five
     *       hundred times ends in {@code ORA-01000, maximum open cursors
     *       exceeded}.</li>
     *   <li>{@code iterations} greater than one is Oracle's batch: one message
     *       carries the statement once and the values many times, and the
     *       server runs it that often. Five hundred rows cost one round trip
     *       instead of five hundred.</li>
     * </ul>
     *
     * @param cursorId   the cursor of this statement, or 0 for a fresh parse
     * @param iterations how many sets of values follow
     * @param rows       supplies the values of row {@code i}, or {@code null}
     */
    public TtcResult query(String sql, space.seclume.oracle.net.TtcBinds binds,
                           TtcResult.RowHandler handler, int cursorId, int iterations,
                           space.seclume.oracle.net.TtcQuery.Rows batch)
            throws SQLException {
        return query(sql, binds, handler, cursorId, iterations, batch, java.util.List.of());
    }

    /**
     * And with the columns already known.
     *
     * <p>A query that runs again on a cursor the server already has gets
     * <b>no column description</b> back - the server assumes the client kept
     * the one from the first run. Whoever reuses a cursor therefore has to
     * hand the columns in, or the first row arrives with nothing to read it
     * against.
     */
    public TtcResult query(String sql, space.seclume.oracle.net.TtcBinds binds,
                           TtcResult.RowHandler handler, int cursorId, int iterations,
                           space.seclume.oracle.net.TtcQuery.Rows batch,
                           java.util.List<space.seclume.oracle.net.OracleColumn> known)
            throws SQLException {
        return query(sql, binds, handler, cursorId, iterations, batch, known, false);
    }

    /**
     * @param oneBlock stop after the first block instead of reading to the end
     *                 - that is what a fetch size asks for
     */
    public TtcResult query(String sql, space.seclume.oracle.net.TtcBinds binds,
                           TtcResult.RowHandler handler, int cursorId, int iterations,
                           space.seclume.oracle.net.TtcQuery.Rows batch,
                           java.util.List<space.seclume.oracle.net.OracleColumn> known,
                           boolean oneBlock) throws SQLException {
        beginReadOnlyIfAsked(sql);
        try {
            rows = 0;
            releaseCarried();
            boolean query = returnsRows(sql);
            boolean plsql = isPlsqlBlock(sql);
            if (!autoCommit && !query) {
                inTransaction = true;
            }
            long answerStart = channel.bytesReceived();
            TtcQuery.send(channel, nextCall(), sql, query ? PREFETCH_ROWS : 0, query, binds,
                    cursorId, iterations, batch, autoCommit, plsql);
            TtcResult result = readAnswer(handler, known, returningCount);
            returningCount = 0;
            returningFromCall = false;
            returningCursors = null;
            rows = result.rowCount();
            java.util.List<space.seclume.oracle.net.OracleColumn> columns =
                    result.columns();
            int cursor = result.cursorId();

            // The server decides how much of the result it sends and says
            // whether that was all of it. Asking for more is driven by that
            // word and not by counting rows: a query over many columns comes
            // back with the description and no rows at all, and a client that
            // only fetches after a full block never asks for them - which is
            // exactly how getColumns came back empty while getTables worked.
            openCursor = cursor;
            moreRows = query && !result.isExhausted() && !result.isFailure() && cursor != 0;
            if (oneBlock || (query && needsDefine(columns))) {
                // The caller asked for one block; the rest waits in the cursor.
                // Or: the rows carry JSON or VECTOR locators, which the next
                // fetch would spoil - the caller gives the cursor a define and
                // runs it again, and the rows come with their values in them.
                return result;
            }
            int fetchRows = PREFETCH_ROWS;
            long before = answerStart;
            long rowsBefore = 0;
            while (query && !result.isExhausted() && !result.isFailure() && cursor != 0) {
                fetchRows = nextFetch(fetchRows, channel.bytesReceived() - before,
                        rows - rowsBefore);
                before = channel.bytesReceived();
                rowsBefore = rows;
                TtcFetch.send(channel, nextCall(), cursor, fetchRows);
                TtcResult more = readAnswer(handler, columns);
                rows += more.rowCount();
                if (more.cursorId() != 0) {
                    cursor = more.cursorId();
                }
                if (more.rowCount() == 0 && !more.isExhausted()) {
                    // No rows and no end - asking again would loop forever.
                    break;
                }
                result = more;
            }
            moreRows = false;
            return result;
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            // 08006, like every other broken connection here. Without a
            // SQLState this failure is invisible to everything that reacts to
            // one: a host list does not move on, a pool does not replace the
            // connection, and an application cannot tell it from a syntax
            // error. It was the only place in the driver missing it.
            throw brokenConnection("the connection to the server broke: "
                    + e.getMessage(), e);
        }
    }


    /**
     * The flag on the last packet of an answer.
     *
     * <p>Everything before it is continuation: raw bytes without even a
     * message type in front. A reader that stops after the first packet gets
     * the first 8060 characters of a LOB and calls it the value.
     */
    private static final int END_OF_ANSWER = 0x2000;

    /**
     * Prints every packet of a LOB answer.
     *
     * <p>Left in on purpose: this is the switch that showed the answer is not
     * framed the way the reference client's is, and the next person to pick
     * the question up will want it within reach rather than rewritten.
     */
    private static final boolean TRACE_LOB =
            Boolean.getBoolean("seclume.oracle.traceLob");

    /**
     * The packet the server sends when it will not send the LOB itself.
     *
     * <p>It carries how many bytes it has and then the server waits. Reaching
     * this means the connect options are wrong, not that the LOB is missing.
     */
    private static final int NS_DATA_DESCRIPTOR = 15;

    /** What the server reported behind the locator in the last LOB answer. */
    private long reportedLobValue = -1;

    /**
     * How long the LOB is, in one call.
     *
     * <p>Its own operation (0x0001), the same message as a read with offset and
     * amount at zero. Before this, {@code length()} read the whole value and
     * counted - correct, and needlessly expensive for a caller who only wanted
     * to know how much there is.
     */
    public long lobLength(WireBuffer locator, int at, int locatorLength) throws SQLException {
        int call = nextCall();
        try (WireBuffer nothing = new WireBuffer(16)) {
            exchangeLob(() -> TtcLob.sendLength(channel, call, locator, at, locatorLength),
                    true, nothing);
            return reportedLobValue;
        }
    }

    /**
     * Creates a temporary LOB on the server and returns its locator.
     *
     * <p>The caller owns the buffer and closes it - and has to free the LOB on
     * the server as well, or it stays in the temporary tablespace until the
     * session ends.
     */
    public WireBuffer createTemporaryLob(boolean character) throws SQLException {
        WireBuffer locator = new WireBuffer(64);
        int call = nextCall();
        try (WireBuffer nothing = new WireBuffer(16)) {
            exchangeLob(() -> TtcLob.sendCreateTemporary(channel, call, character,
                    space.seclume.oracle.net.TtcDataTypes.CHARSET_AL32UTF8),
                    true, nothing, locator);
        } catch (SQLException | RuntimeException e) {
            locator.close();
            throw e;
        }
        return locator;
    }

    /**
     * Frees a temporary LOB on the server.
     *
     * <p>Without this it stays in the temporary tablespace until the session
     * ends — which for a pooled connection can be a very long time.
     */
    public void freeTemporaryLob(WireBuffer locator, int at, int locatorLength)
            throws SQLException {
        try (WireBuffer nothing = new WireBuffer(16)) {
            int call = nextCall();
            exchangeLob(() -> TtcLob.sendFreeTemporary(channel, call, locator, at,
                    locatorLength), false, nothing);
        }
    }

    /**
     * Writes bytes into a LOB, at an offset counted from 1.
     *
     * <p>The payload is bytes either way: UTF-16BE for a CLOB, raw for a BLOB.
     */
    public void writeLob(WireBuffer locator, int at, int locatorLength, long offset,
                         WireBuffer data, int length) throws SQLException {
        try (WireBuffer nothing = new WireBuffer(16)) {
            int call = nextCall();
            exchangeLob(() -> TtcLob.sendWrite(channel, call, locator, at, locatorLength,
                    offset, data, length), false, nothing);
        }
    }

    /**
     * Fetches the contents of a LOB into {@code sink}.
     *
     * <p>One call, however large the value: the answer may run over fifty
     * packets, and they are put back together here rather than paid for one
     * round trip at a time. Nothing lands on the Java heap on the way - the
     * bytes go from the receive buffer into {@code sink}, both of them native.
     *
     * @param locator where the locator lies
     * @param at      its first byte
     * @param offset  counted from 1, the way Oracle counts
     * @param amount  units to read, or {@link TtcLob#ALL}
     */
    public void readLob(WireBuffer locator, int at, int locatorLength, long offset,
                        long amount, WireBuffer sink)
            throws SQLException {
        int call = nextCall();
        exchangeLob(() -> TtcLob.sendRead(channel, call, locator, at, locatorLength,
                offset, amount), true, sink);
    }

    /** Sends a LOB call and reads its answer, however many packets it takes. */
    private interface Send {
        void run() throws IOException;
    }

    private void exchangeLob(Send send, boolean amountFollows, WireBuffer sink)
            throws SQLException {
        exchangeLob(send, amountFollows, sink, null);
    }

    /**
     * @param amountFollows whether the call asked with an amount - and so
     *                   whether the answer carries one behind the locator. A
     *                   write and a free do not, and reading one there took
     *                   the status message behind it for a number
     * @param locatorOut if given, the locator the server returned is copied
     *                   into it - that is how a create gets its locator, and it
     *                   is why nothing here assumes 112 bytes: a temporary one
     *                   is 38.
     */
    private void exchangeLob(Send send, boolean amountFollows, WireBuffer sink,
                             WireBuffer locatorOut)
            throws SQLException {
        try {
            reportedLobValue = -1;
            send.run();
            try (WireBuffer answer = new WireBuffer(16 * 1024)) {
                while (true) {
                    int type = drainMarkers(channel.nextPacket());
                    if (TRACE_LOB) {
                        WireBuffer dbg = channel.packet();
                        StringBuilder head = new StringBuilder();
                        int from = Math.max(0, dbg.position() - 10);
                        for (int i = from; i < dbg.limit(); i++) {
                            head.append(i == dbg.position() ? "| " : "");
                            head.append(String.format("%02x ", dbg.getByte(i)));
                        }
                        System.err.println("[lob] type=" + type + " flags=0x"
                                + Integer.toHexString(channel.dataFlags())
                                + " len=" + (dbg.limit() - dbg.position()) + " : " + head);
                    }
                    if (type == NS_DATA_DESCRIPTOR) {
                        // Should not happen any more - see SERVICE_OPTIONS in
                        // NsChannel. Named rather than swallowed, because the
                        // symptom otherwise is a connection that simply stops.
                        throw new SQLException("the server announced the LOB in a descriptor "
                                + "packet instead of sending it; the connect service options "
                                + "are wrong for this server", "08006");
                    }
                    if (type != NsPacket.TYPE_DATA) {
                        throw new SQLException("expected a DATA packet, got "
                                + NsPacket.typeName(type));
                    }
                    WireBuffer in = channel.packet();
                    int from = in.position();
                    int length = in.limit() - from;
                    answer.ensureCapacity(answer.position() + length);
                    answer.putBytes(in.segment(), from, length);
                    if ((channel.dataFlags() & END_OF_ANSWER) != 0) {
                        break;
                    }
                }
                TtcLob.Answer result = TtcLob.read(answer, 0, answer.position(), sink,
                        amountFollows);
                if (result.tail().isFailure()
                        && result.tail().errorNumber() != TtcResult.ORA_NO_DATA_FOUND) {
                    throw new SQLException("the LOB call failed (ORA-"
                            + String.format("%05d", result.tail().errorNumber()) + "): "
                            + result.tail().errorText(), "22000");
                }
                reportedLobValue = result.reported();
                if (locatorOut != null) {
                    if (result.locatorAt() < 0) {
                        throw new SQLException("the server returned no LOB locator", "22000");
                    }
                    locatorOut.clear();
                    locatorOut.ensureCapacity(result.locatorLength());
                    locatorOut.putBytes(answer.segment(), result.locatorAt(),
                            result.locatorLength());
                }
            }
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            close();
            throw new SQLNonTransientConnectionException(
                    "the connection to the server broke: " + e.getMessage(), "08006", e);
        }
    }

    /** Says that the next statement has that many {@code into} binds. */
    public void expectReturning(int count) {
        expectReturning(count, false);
    }

    /** The same, saying that they come from a PL/SQL call - a different shape. */
    public void expectReturning(int count, boolean fromCall) {
        expectReturning(count, fromCall, null);
    }

    /**
     * The same, saying which of the outputs is a cursor.
     *
     * <p>A cursor slot in the answer is read as a description and a cursor
     * number rather than as bytes - see {@code TtcResult}. Which slot that is
     * cannot be seen from the answer, only from what was bound.
     */
    public void expectReturning(int count, boolean fromCall, boolean[] cursors) {
        this.returningCount = count;
        this.returningFromCall = fromCall;
        this.returningCursors = cursors;
    }

    private boolean returningFromCall;
    private boolean[] returningCursors;

    /**
     * Whether the cursor of the last query still has rows in it.
     *
     * <p>Oracle reads in blocks anyway - the driver simply used to fetch until
     * the end and keep everything. With a fetch size it stops after the first
     * block and comes back here.
     */
    public boolean hasMoreRows() {
        return moreRows;
    }

    /** The cursor the last query left open, or 0. */
    public int openCursor() {
        return openCursor;
    }

    /**
     * Reads the next block from a cursor that still has rows.
     *
     * <p>Unlike PostgreSQL this needs no transaction: an Oracle cursor belongs
     * to the session, not to a transaction.
     */
    public TtcResult fetchMore(int cursorId, int rows, TtcResult.RowHandler handler,
                               java.util.List<space.seclume.oracle.net.OracleColumn> columns)
            throws SQLException {
        try {
            if (carriedCursor != cursorId) {
                // Another statement has been through here since; what was
                // carried over belongs to its cursor, not to this one.
                releaseCarried();
            }
            TtcFetch.send(channel, nextCall(), cursorId, rows);
            TtcResult more = readAnswer(handler, columns);
            moreRows = !more.isExhausted() && !more.isFailure() && more.rowCount() > 0;
            return more;
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            close();
            throw new SQLNonTransientConnectionException(
                    "the connection to the server broke: " + e.getMessage(), "08006", e);
        }
    }

    /**
     * Reads one answer.
     *
     * <p>One packet: the server puts the description, the rows and the
     * closing status into a single answer and marks it with the
     * end-of-response flag. A wide query looked like a packet problem for a
     * while, but it was two parsing faults - the column description and the
     * bit vector - and both are fixed.
     */
    private TtcResult readAnswer(TtcResult.RowHandler handler,
                                 java.util.List<space.seclume.oracle.net.OracleColumn> columns)
            throws IOException, SQLException {
        return readAnswer(handler, columns, 0);
    }

    /**
     * @param returning how many output binds the answer carries in front of
     *                  everything else - a DML with a {@code returning into}
     */
    private TtcResult readAnswer(TtcResult.RowHandler handler,
                                 java.util.List<space.seclume.oracle.net.OracleColumn> columns,
                                 int returning)
            throws IOException, SQLException {
        int type = drainMarkers(channel.nextPacket());
        if (type != NsPacket.TYPE_DATA) {
            throw new SQLException("expected a DATA packet, got " + NsPacket.typeName(type));
        }
        TtcResult result = new TtcResult(columns, carried);
        result.expectReturned(returning, returningFromCall, returningCursors);

        if ((channel.dataFlags() & END_OF_ANSWER) != 0) {
            // The common case: the whole answer is in this packet, and it is
            // parsed where it lies - no copy on the hot path.
            WireBuffer in = channel.packet();
            result.read(in, in.position(), in.limit(), handler);
            keep(result);
        } else {
            try (WireBuffer whole = collectAnswer()) {
                result.read(whole, 0, whole.position(), handler);
                keep(result);
            }
        }
        if (channel.takeLateBreak()) {
            // Cancelled, and the server acts on it only now - its markers and
            // the ORA-01013 behind them are this call's outcome, not the next
            // statement's. See NsChannel.lateBreak.
            return readAnswer(handler, columns, 0);
        }
        return result;
    }

    /**
     * Holds on to the last row of an answer for the next one.
     *
     * <p>Oracle does not send a value again when it is the same as in the row
     * before, and it counts the row before across the boundary of a fetch.
     * The block that row was in is written over by then, so its values are
     * moved to safety here - one row per answer, no matter how many rows it
     * carried. Without this the first row of the second block came back with
     * an empty value wherever the server had left one out, and a schema with
     * more than a hundred columns in it is enough to see it: Hibernate said
     * "missing column [holder] in table [zl_ticket]" for a column that was
     * plainly there.
     */
    private void keep(TtcResult result) {
        space.seclume.oracle.net.TtcRow row = result.row();
        if (row != null) {
            row.carryOver();
        }
        if (row != carried) {
            releaseCarried();
            carried = row;
        }
        if (result.cursorId() != 0) {
            carriedCursor = result.cursorId();
        }
    }

    private void releaseCarried() {
        if (carried != null) {
            carried.release();
            carried = null;
        }
        carriedCursor = 0;
    }

    /** The row window that the last answer left behind - see {@link #keep}. */
    private space.seclume.oracle.net.TtcRow carried;
    /** Which cursor it belongs to; another one must not read it. */
    private int carriedCursor;

    /**
     * Puts an answer back together that did not fit in one packet.
     *
     * <p>The server splits a large answer and marks only the last packet.
     * Everything before it is raw continuation and carries no message type at
     * all, so the pieces belong together before anything reads them.
     *
     * <p>Not doing this is worse than it sounds, and it is how this was found:
     * the driver parsed the first packet, concluded the result was not
     * finished, asked for the next block - and read the <b>leftover</b> packet
     * as the answer to that request. From there the connection is one answer
     * out of step, and it ends with the driver waiting for a packet that
     * nobody owes it. A metadata query over a schema with a few dozen tables
     * is enough; that is why Spring Data on Oracle hung and nothing in the
     * stack trace pointed at the cause.
     *
     * <p>The first packet is already in the channel buffer when this starts.
     */
    private WireBuffer collectAnswer() throws IOException, SQLException {
        WireBuffer whole = new WireBuffer(32 * 1024);
        while (true) {
            WireBuffer in = channel.packet();
            int from = in.position();
            int length = in.limit() - from;
            whole.ensureCapacity(whole.position() + length);
            whole.putBytes(in.segment(), from, length);
            if ((channel.dataFlags() & END_OF_ANSWER) != 0) {
                return whole;
            }
            int type = drainMarkers(channel.nextPacket());
            if (type != NsPacket.TYPE_DATA) {
                whole.close();
                throw new SQLException("the answer broke off after "
                        + whole.position() + " bytes: " + NsPacket.typeName(type));
            }
        }
    }

    /**
     * Ends the transaction - as a call of its own, not as a statement.
     *
     * <p>Four bytes go over the wire: message type, function number, sequence,
     * and an empty token. Sending the word {@code commit} as SQL works too and
     * is what this driver did - but every statement Oracle parses opens a
     * <b>cursor</b>, so a connection that committed a few hundred times died
     * with {@code ORA-01000}. That is how this was found: as
     * {@code ORA-00604} in a benchmark, which is the wrapper Oracle puts
     * around it.
     */
    public void commit() throws SQLException {
        if (!inTransaction) {
            // Nothing ran since the last one, so there is nothing to commit -
            // and a commit is a round trip like any other.
            return;
        }
        endTransaction(TtcMessage.FUNCTION_COMMIT, "commit");
    }

    /** Whether anything has run that a commit would have to cover. */
    public boolean inTransaction() {
        return inTransaction;
    }

    /** The same for a rollback. */
    public void rollback() throws SQLException {
        if (!inTransaction) {
            return;
        }
        endTransaction(TtcMessage.FUNCTION_ROLLBACK, "rollback");
    }

    private void endTransaction(int function, String what) throws SQLException {
        inTransaction = false;
        try {
            WireBuffer out = channel.beginData();
            out.putByte((byte) TtcMessage.TYPE_FUNCTION);
            out.putByte((byte) function);
            out.putByte((byte) sequence++);
            TtcParameters.putNumber(out, 0);                  // token number
            channel.sendData();
            TtcResult result = readAnswer(null, java.util.List.of());
            if (result.isFailure()) {
                throw new SQLException("the server rejected the " + what + " (ORA-"
                        + String.format("%05d", result.errorNumber()) + ")", "25000",
                        result.errorNumber());
            }
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            close();
            throw new SQLNonTransientConnectionException(
                    "the connection broke during the " + what, "08006", e);
        }
    }

    /**
     * Whether the server commits every statement by itself.
     *
     * <p>JDBC starts with auto-commit on, and Oracle takes it as a bit in the
     * execute call - so it costs nothing. Switching it off is what a
     * transaction is: from then on the statements pile up until somebody says
     * {@code commit}.
     */
    public void setAutoCommit(boolean autoCommit) {
        this.autoCommit = autoCommit;
    }

    /**
     * Makes every following transaction read-only, or stops doing so.
     *
     * <p>This used to send {@code SET TRANSACTION READ ONLY} at once. Spring
     * calls {@code setReadOnly(true)} before {@code setAutoCommit(false)}, so
     * that statement ran in auto-commit mode, was committed with itself, and
     * the transaction that followed was an ordinary one - writes went
     * through while {@code isReadOnly()} said true. And even where it landed
     * inside a transaction, the one after the next commit was read-write
     * again. Found by the Spring JDBC suite.
     */
    public void setReadOnlyTransactions(boolean readOnly) {
        this.readOnlyTransactions = readOnly;
    }

    /**
     * {@code SET TRANSACTION READ ONLY}, in front of the first statement of a
     * transaction that is to be read-only.
     *
     * <p>Only with auto-commit off: in auto-commit mode every statement is its
     * own transaction and a read-only one around a single statement is
     * nothing a caller could have meant. The statement counts as the start of
     * the transaction, so a following {@code commit} ends it and the next
     * transaction is primed again.
     */
    private void beginReadOnlyIfAsked(String sql) throws SQLException {
        if (!readOnlyTransactions || autoCommit || inTransaction) {
            return;
        }
        inTransaction = true;
        query("set transaction read only", null);
    }

    public boolean isAutoCommit() {
        return autoCommit;
    }

    /**
     * What the server has open for a statement text.
     *
     * <p>A cursor belongs to the <b>connection</b>, not to the
     * {@code PreparedStatement} object in front of it - and that is not a
     * detail. Frameworks build a fresh statement object for every call, so a
     * cursor tied to the object means a new cursor per call: the server parses
     * again, and after {@code open_cursors} of them - three hundred by default
     * - the connection dies with {@code ORA-01000}.
     *
     * <p>Kept in access order and bounded, because a cache that grows without
     * bound is a leak with a friendly name.
     */
    private record OpenCursor(int id, java.util.List<OracleColumn> columns) {
    }

    private final java.util.LinkedHashMap<String, OpenCursor> cursors =
            new java.util.LinkedHashMap<>(16, 0.75f, true);

    /** How many statements one connection keeps parsed. */
    private static final int CURSOR_CACHE_SIZE = 64;

    /** The cursor the server has for this text, or 0. */
    public int cursorFor(String sql) {
        OpenCursor open = cursors.get(sql);
        // Recorded by fingerprint, like everything else: a cache report that
        // listed the statements by their text would carry every value in
        // them, which is precisely the report nobody could then share.
        space.seclume.jfr.Observed.statementCache(sql,
                space.seclume.QueryFingerprint.Dialect.ORACLE, open != null);
        return open == null ? 0 : open.id();
    }

    /** What that cursor describes - the server sends it only the first time. */
    public java.util.List<OracleColumn> columnsFor(String sql) {
        OpenCursor open = cursors.get(sql);
        return open == null ? java.util.List.of() : open.columns();
    }

    /**
     * Whether this text is DDL - what Oracle executes at parse time.
     *
     * <p>By the first word, after leading space and comments. PL/SQL blocks
     * are not DDL here even when they run some: a block is executed on every
     * execution, so its cursor can be kept like a query's.
     */
    public static boolean isDefinition(String sql) {
        int at = 0;
        int length = sql.length();
        while (at < length) {
            char c = sql.charAt(at);
            if (Character.isWhitespace(c)) {
                at++;
            } else if (c == '-' && at + 1 < length && sql.charAt(at + 1) == '-') {
                int end = sql.indexOf('\n', at);
                at = end < 0 ? length : end + 1;
            } else if (c == '/' && at + 1 < length && sql.charAt(at + 1) == '*') {
                int end = sql.indexOf("*/", at + 2);
                at = end < 0 ? length : end + 2;
            } else {
                break;
            }
        }
        int end = at;
        while (end < length && Character.isLetter(sql.charAt(end))) {
            end++;
        }
        return switch (sql.substring(at, end).toLowerCase(java.util.Locale.ROOT)) {
            case "create", "drop", "alter", "truncate", "rename", "grant", "revoke",
                 "comment", "analyze", "audit", "noaudit", "purge", "flashback",
                 "associate", "disassociate" -> true;
            default -> false;
        };
    }

    /**
     * A statement failed: its text gets no cursor from the cache any more,
     * and the cursor it ran on goes back to the server.
     *
     * <p>Found with Liquibase, which asks for its lock table before creating
     * it. The failed query's cursor was cached like a good one, and once the
     * table existed the same text was run on it again - "no statement
     * parsed", on every later attempt.
     */
    public void forgetCursor(String sql, int id) {
        OpenCursor cached = cursors.remove(sql);
        if (cached != null && cached.id() != id) {
            giveCursorBack(cached.id());
        }
        giveCursorBack(id);
    }

    /** Remembers what the server opened for this text. */
    public void rememberCursor(String sql, int id, java.util.List<OracleColumn> columns) {
        if (id == 0) {
            return;
        }
        if (isDefinition(sql)) {
            // Oracle runs DDL when it parses it. A cursor kept for the text
            // and executed again is not parsed again - so the second
            // "create table" of the same text on a connection did nothing,
            // said nothing, and the table stayed dropped. A test that drops
            // and recreates its table per case met it on a pooled
            // connection; a "truncate table" repeated would have left the
            // rows where they were. Never kept: closed at once.
            giveCursorBack(id);
            return;
        }
        OpenCursor replaced = cursors.put(sql, new OpenCursor(id, columns));
        if (replaced != null && replaced.id() != id) {
            // The same text on a different cursor: the server parsed afresh
            // and the old number is now ours to give back.
            giveCursorBack(replaced.id());
        }
        if (cursors.size() > CURSOR_CACHE_SIZE) {
            java.util.Iterator<java.util.Map.Entry<String, OpenCursor>> oldest =
                    cursors.entrySet().iterator();
            // Dropping the entry is not closing the cursor. The server has no
            // way of finding out that nobody will ask for this number again,
            // counts it against open_cursors, and a connection that sees more
            // distinct statements than this cache holds would die with
            // ORA-01000 - which is what STATUS.md records having met once.
            giveCursorBack(oldest.next().getValue().id());
            oldest.remove();
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
     * The number for the next call - and the guard in front of every one.
     *
     * <p><b>Why the number.</b> Oracle numbers each call, so every send has to
     * ask for one; a guard here therefore cannot be forgotten by a method
     * written later. And it has to be somewhere, because the failure it
     * prevents is the quiet kind: a call sent while earlier answers are still
     * outstanding gets the <b>first outstanding answer</b> handed to it, not
     * its own. No error, no hang - just a result belonging to another
     * statement, which is the worst shape a defect can take in a driver.
     *
     * <p>The TDS side of this learnt the same lesson through a hang, which was
     * the kinder version.
     */
    private int nextCall() throws SQLException {
        flushPipeline();
        return newCallNumber();
    }

    /**
     * One call number - and the one in front of it, if something is waiting to
     * ride along.
     *
     * <p>The order is the point. A piggyback travels <b>ahead of</b> the call
     * it rides with and therefore carries the lower number; everywhere the
     * number is taken before the packet is opened, the one for the piggyback
     * has to be reserved here or the two would go out in the wrong order and
     * the server would refuse the pair.
     */
    private int newCallNumber() {
        if (closingCount > 0) {
            reservedForCursors = sequence++;
        }
        return sequence++;
    }

    // ---- giving cursors back ---------------------------------------------

    /** Cursor numbers the cache has dropped and the server has not been told about. */
    private int[] closing = new int[8];   // seclume-allow: cursor numbers, not a secret
    private int closingCount;

    /**
     * The call number reserved for the next piggyback, or {@code -1}.
     *
     * <p>See {@link #newCallNumber()}. Where the packet is opened before a
     * number is taken - {@code endTransaction} is the one - none is reserved
     * and the piggyback takes the next one itself, which is then still the
     * lower of the two.
     */
    private int reservedForCursors = -1;

    /**
     * Writes the pending cursor returns at the head of a packet that is being
     * built.
     *
     * <p>Hung off the channel rather than called at each send site, because
     * this driver has six of those and a seventh written later would forget.
     */
    private void returnCursors(WireBuffer out) {
        if (closingCount == 0) {
            return;
        }
        int call = reservedForCursors >= 0 ? reservedForCursors : sequence++;
        reservedForCursors = -1;
        TtcClose.putPiggyback(out, call, closing, closingCount);
        closingCount = 0;
    }

    /** Queues a cursor number the server should have back. */
    private void giveCursorBack(int id) {
        if (id == 0) {
            return;
        }
        if (closingCount == closing.length) {
            closing = java.util.Arrays.copyOf(closing, closing.length * 2);
        }
        closing[closingCount++] = id;
    }

    /** How many cursors are waiting to be given back - for the tests. */
    public int cursorsWaitingToClose() {
        return closingCount;
    }

    /**
     * Gives every cursor this session holds back to the server, and waits
     * until it has.
     *
     * <p>{@link #detach()} refuses while cursors are open - a successor that
     * inherited the stream was never told their numbers, so the server would
     * keep them until the session ends and a long-lived connection would
     * walk into {@code ORA-01000}. Until now that refusal named an action
     * nothing here offered: there was no way to close them, only to let the
     * cache evict them one at a time.
     *
     * <p>Returning a cursor is a piggyback - function 105, riding in front of
     * a real call, answering nothing of its own - so it needs a call to ride
     * on. <b>A ping is the one</b>: a statement would parse and open a cursor,
     * leaving one behind, and a rollback - what this rode on first - ends the
     * transaction the session is in, which is exactly the state a hand-over
     * exists to keep. A ping changes nothing on the server.
     *
     * <p>Costs one round trip, and only when there is something to return.
     */
    public void releaseCursors() throws SQLException {
        java.util.Set<Integer> given = new java.util.LinkedHashSet<>();
        for (OpenCursor open : cursors.values()) {
            given.add(open.id());
        }
        // And the one the last statement left standing, which is not always
        // in the cache and is half of what detach() looks at.
        given.add(openCursor);
        cursors.clear();
        openCursor = 0;
        moreRows = false;
        for (int id : given) {
            giveCursorBack(id);
        }
        if (closingCount == 0) {
            return;
        }
        // Carried on a ping, not on a rollback. It rode on a rollback before,
        // "because the point of it here is the freight and not the cargo" -
        // and the cargo was the open transaction: every session detached
        // inside one lost it without a word. Found by moving a session with
        // an uncommitted row from Linux to Windows; the moves before had all
        // been made between transactions.
        call(TtcMessage.FUNCTION_PING, "ping");
    }

    /**
     * A bare call with no effect of its own - what a piggyback rides on when
     * nothing else is due.
     */
    private void call(int function, String what) throws SQLException {
        try {
            WireBuffer out = channel.beginData();
            out.putByte((byte) TtcMessage.TYPE_FUNCTION);
            out.putByte((byte) function);
            out.putByte((byte) sequence++);
            TtcParameters.putNumber(out, 0);                  // token number
            channel.sendData();
            TtcResult result = readAnswer(null, java.util.List.of());
            if (result.isFailure()) {
                throw new SQLException("the server rejected the " + what + " (ORA-"
                        + String.format("%05d", result.errorNumber()) + ")", "HY000",
                        result.errorNumber());
            }
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            close();
            throw new SQLNonTransientConnectionException(
                    "the connection broke during the " + what, "08006", e);
        }
    }

    // ---- the pipeline block ----------------------------------------------
    //
    // Whether this works at all is a question about the server rather than
    // about this code: Oracle numbers every call and this driver has always
    // sent one and waited. Two calls in flight at once is therefore an
    // experiment, and the answer is written down where the experiment is -
    // see OraConnection.

    private boolean pipelining;
    /** How many calls have been sent whose answers nobody has read. */
    private int pipelineGroup;
    private long[] pipelineCounts = new long[0]; // seclume-allow: update counts, not a secret
    private int pipelineCount;
    private final java.util.List<String> pipelineSql = new java.util.ArrayList<>();

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
     * Sends one call without waiting for its answer.
     *
     * @return {@link java.sql.Statement#SUCCESS_NO_INFO} - the count is not
     *         known yet, and inventing one would be a lie
     */
    public long pipelineExecute(String sql, space.seclume.oracle.net.TtcBinds binds)
            throws SQLException {
        beginReadOnlyIfAsked(sql);
        try {
            releaseCarried();
            if (!autoCommit) {
                inTransaction = true;
            }
            TtcQuery.send(channel, newCallNumber(), sql, 0, false, binds, 0, 1, null,
                    autoCommit, isPlsqlBlock(sql));
            pipelineGroup++;
            pipelineSql.add(sql);
            if (pipelineGroup >= PIPELINE_CALLS) {
                flushPipeline();
            }
            return java.sql.Statement.SUCCESS_NO_INFO;
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection("the connection to the server broke: " + e.getMessage(), e);
        }
    }

    /**
     * How many calls may be in flight at once.
     *
     * <p>Bounded for the reason every such buffer is: if both sides keep
     * writing and neither reads, both socket buffers fill and both block.
     */
    private static final int PIPELINE_CALLS = 64;

    /** Reads the answers to everything that was sent. */
    public void flushPipeline() throws SQLException {
        if (pipelineGroup == 0) {
            return;
        }
        int group = pipelineGroup;
        pipelineGroup = 0;
        try {
            for (int i = 0; i < group; i++) {
                TtcResult result = readAnswer(null, java.util.List.of());
                keep(pipelineCount + i, Math.max(result.rowCount(), 0));
            }
            pipelineCount += group;
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw brokenConnection("the connection to the server broke: " + e.getMessage(), e);
        }
    }

    public long[] endPipeline() throws SQLException {
        flushPipeline();
        pipelining = false;
        long[] counts = java.util.Arrays.copyOf(pipelineCounts, pipelineCount);
        pipelineCount = 0;
        pipelineSql.clear();
        return counts;
    }

    private void keep(int at, long count) {
        if (at >= pipelineCounts.length) {
            pipelineCounts = java.util.Arrays.copyOf(pipelineCounts,
                    Math.max(pipelineCounts.length * 2, at + 8));
        }
        pipelineCounts[at] = count;
    }

    /** How often this session has waited for the server. */
    public long roundTrips() {
        return channel.roundTrips();
    }

    /**
     * Whether this is an anonymous PL/SQL block rather than a statement.
     *
     * <p>It decides the options mask, and the wrong one is not a nuance: a
     * block sent with {@code OPTION_NOT_PLSQL} - which every other statement
     * carries - is answered with {@code ORA-03146, invalid buffer length for
     * TTC field}. Recognised from the text, the same way a query is.
     */
    private static boolean isPlsqlBlock(String sql) {
        String text = sql.stripLeading();
        return text.regionMatches(true, 0, "begin", 0, 5)
                || text.regionMatches(true, 0, "declare", 0, 7);
    }

    /**
     * Whether a statement returns rows.
     *
     * <p>Decided by the first word, the way every driver decides it. The
     * server has to be told: asking to fetch from a statement that produced no
     * cursor answers {@code ORA-01003}, and a create table produces none.
     */
    private static boolean returnsRows(String sql) {
        String text = sql.stripLeading();
        return text.regionMatches(true, 0, "select", 0, 6)
                || text.regionMatches(true, 0, "with", 0, 4);
    }

    /**
     * Answers the server's markers and reads on.
     *
     * <p>When a statement fails, Oracle does not simply send the error: it
     * first sends a marker - in fact two, a break and a reset - and waits for
     * the client to answer with a reset of its own. Only then does the error
     * come. A client that does not know this waits forever, and the symptom
     * looks like a hung network rather than a failed statement.
     */
    private int drainMarkers(int type) throws IOException {
        return channel.answerMarkers(type);
    }

    /**
     * Tells the server to abandon the call this connection is waiting on.
     *
     * <p>A {@code !} as TCP urgent data and a break marker behind it, down the
     * same socket - see
     * {@link space.seclume.oracle.net.NsChannel#sendBreak}. Nothing is read
     * here: the markers the server answers with, and the {@code ORA-01013}
     * behind them, belong to the thread that is already waiting, and this one
     * only writes.
     *
     * <p>Does nothing when no call is in flight, which is deliberate and is
     * explained where the decision is made rather than here.
     *
     * <p>Safe from another thread, and that is the only way it is called.
     *
     * @throws SQLException if the break could not be written
     */
    public void cancel() throws SQLException {
        try {
            channel.sendBreak();
        } catch (IOException | space.seclume.internal.WireBuffer.Truncated e) {
            throw new SQLNonTransientConnectionException(
                    "the cancellation could not be sent: " + e.getMessage(), "08006", e);
        }
    }

    /** What this connection last sent and received - see space.seclume.Flight. */
    public java.util.List<space.seclume.Flight.Message> recentMessages() {
        return channel.recentMessages();
    }

    /** How many packets have crossed this connection. */
    public long recordedMessages() {
        return channel.recordedMessages();
    }

    /** How many rows the last statement produced, across all blocks. */
    public long rowCount() {
        return rows;
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
    private SQLException brokenConnection(String what, Exception cause) {
        channel.close();
        return new SQLNonTransientConnectionException(what, "08006", cause);
    }

    public boolean isOpen() {
        return channel.isOpen();
    }

    @Override
    public void close() {
        releaseCarried();
        channel.close();
    }
}
