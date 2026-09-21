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
     * How many calls go into one message before it is sent.
     *
     * <p>The number that actually guards anything is {@link #BATCH_BYTES}: a
     * client that keeps writing while the server keeps answering can fill both
     * socket buffers and deadlock, and a bounded message is what prevents it.
     * The row cap is a second, cruder bound - it used to be 256, which with
     * handles became the binding one for no reason: five hundred rows of
     * {@code sp_execute} are some 15 KB, well inside the byte bound, yet they
     * were split into two messages and two round trips. Raising it to 1024
     * left the byte bound in charge and closed the rest of the gap to
     * mssql-jdbc (11.2 ms against 11.1 ms for five hundred rows, measured).
     */
    private static final int BATCH_ROWS = 1024;
    /** And how many bytes, whichever comes first - this is the real guard. */
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
    /** The columns of the open cursor - only the open reports them. */
    private java.util.List<TdsColumn> cursorColumns = java.util.List.of();
    private long updateCount = -1;

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
        return settings.hosts().open(server -> openOne(settings.at(server)));
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
        } catch (IOException e) {
            throw new SQLNonTransientConnectionException(
                    "cannot reach " + settings.host() + ":" + settings.port(), "08001", e);
        }
        try {
            return login(channel, settings);
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
        if (settings.tdsVersion().wrapsTheConnection()) {
            startStrictEncryption(channel, settings);
            // The pre-login still happens - the server wants the version and
            // the instance name - but it happens inside TLS, and its
            // encryption byte is no longer a negotiation: that was settled
            // before the first byte.
            new PreLogin().exchange(channel, Tds.ENCRYPT_ON);
        } else {
            negotiateEncryption(channel, settings);
        }

        Login7.send(channel, new Login7.Settings(settings.host(), settings.database(),
                settings.user(), settings.secret(), settings.applicationName(), "seclume"));

        LoginResponse response = new LoginResponse();
        response.read(channel);
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
        session.setResultLimit(settings.resultLimit());
        return session;
    }

    /**
     * TDS 7.4: negotiate in the clear, then run the handshake inside the
     * pre-login packets.
     */
    private static void negotiateEncryption(TdsChannel channel, Settings settings)
            throws IOException, SQLException {
        PreLogin preLogin = new PreLogin();
        preLogin.exchange(channel, Tds.ENCRYPT_ON);
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
            WireBuffer out = channel.begin();
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
        } catch (IOException e) {
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
            WireBuffer out = channel.begin();
            putAllHeaders(out);
            out.putShortLe((short) 0xffff);
            out.putShortLe((short) PROC_SP_EXECUTESQL);
            out.putShortLe((short) 0);                // no options
            TdsParameters.writeStatementText(out, sql);
            TdsParameters.writeStatementText(out, declaration);
            parameters.writeAll(out);
            channel.send(Tds.TYPE_RPC);
            return readAnswer(handler);
        } catch (IOException e) {
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

    /** Whether a setting is waiting for a statement to ride along with. */
    public boolean hasPending() {
        return pending != null;
    }

    /** Sends what is pending right now, for whoever cannot wait. */
    public void flushPending() throws SQLException {
        if (pending != null) {
            String sql = pending;
            pending = null;
            execute(sql);
        }
    }

    /** Takes the pending text and clears it - the caller sends it along. */
    private String takePending() {
        String sql = pending;
        pending = null;
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
        if (declaration != null && !declaration.isEmpty()) {
            throw new SQLException("a fetch size on a statement with bind values is not "
                    + "supported on SQL Server yet - sp_cursorprepexec refuses the "
                    + "parameter list this driver sends, and half of a cursor is worse "
                    + "than none. Without bind values the block cursor works.");
        }
        try {
            WireBuffer out = channel.begin();
            putAllHeaders(out);
            out.putShortLe((short) 0xffff);
            out.putShortLe((short) PROC_SP_CURSOROPEN);
            out.putShortLe((short) 0);
            TdsParameters.writeOutputInt(out, "", null);       // the cursor
            TdsParameters.writeStatementText(out, sql);
            TdsParameters.writeOutputInt(out, "", CURSOR_FORWARD_ONLY);
            TdsParameters.writeOutputInt(out, "", CURSOR_READ_ONLY);
            TdsParameters.writeOutputInt(out, "", 0);          // row count
            channel.send(Tds.TYPE_RPC);
            TokenStream answer = readAnswer(null);
            Integer handle = answer.returned(0);
            if (handle == null || handle == 0) {
                throw new SQLException("the server opened no cursor and named no handle - "
                        + "without one the rows cannot be fetched in blocks");
            }
            cursorColumns = answer.columns();
            return handle;
        } catch (IOException e) {
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
            WireBuffer out = channel.begin();
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
        } catch (IOException e) {
            throw brokenConnection(e);
        }
    }

    /** Gives a cursor back - a result set the caller stopped reading from. */
    public void cursorClose(int handle) throws SQLException {
        try {
            WireBuffer out = channel.begin();
            putAllHeaders(out);
            out.putShortLe((short) 0xffff);
            out.putShortLe((short) PROC_SP_CURSORCLOSE);
            out.putShortLe((short) 0);
            TdsParameters.writeInt(out, "", handle);
            channel.send(Tds.TYPE_RPC);
            readAnswer(null);
        } catch (IOException e) {
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
            WireBuffer out = channel.begin();
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
        } catch (IOException e) {
            throw brokenConnection(e);
        }
    }

    /** Gives a compiled statement back. One round trip, at statement close. */
    public void unprepare(int handle) throws SQLException {
        if (handle == 0) {
            return;
        }
        try {
            WireBuffer out = channel.begin();
            putAllHeaders(out);
            out.putShortLe((short) 0xffff);
            out.putShortLe((short) PROC_SP_UNPREPARE);
            out.putShortLe((short) 0);
            TdsParameters.writeInt(out, "", handle);
            channel.send(Tds.TYPE_RPC);
            readAnswer(null);
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
                WireBuffer out = channel.begin();
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
        } catch (IOException e) {
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
            WireBuffer out = channel.begin();
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
        } catch (IOException e) {
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

    /** How often this session has waited for the server. */
    public long roundTrips() {
        return channel.roundTrips();
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
        int type = channel.receive();
        if (type != Tds.TYPE_TABULAR_RESULT) {
            throw new IOException("expected a result, got type 0x" + Integer.toHexString(type));
        }
        TokenStream tokens = new TokenStream();
        if (expectedCounts > 0) {
            tokens.expectCounts(expectedCounts);
        }
        tokens.read(channel.message(), 0, channel.messageLength(), handler);
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
        return tokens;
    }

    /**
     * The 22-byte header block. The transaction descriptor is zero outside an
     * explicit transaction, and inside one it is what the server handed out.
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

    private SQLException brokenConnection(IOException cause) {
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

    /** What TLS this connection uses, or {@code null} without it. */
    public String tlsDescription() {
        return channel.tlsDescription();
    }

    /** The database the session is in. */
    public String database() {
        return database;
    }

    public boolean isOpen() {
        return channel.isOpen();
    }

    @Override
    public void close() {
        channel.close();
    }
}
