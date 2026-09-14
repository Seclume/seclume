package space.seclume.oracle;

import java.io.IOException;
import java.sql.SQLException;
import java.sql.SQLNonTransientConnectionException;

import space.seclume.internal.WireBuffer;
import space.seclume.oracle.net.NsChannel;
import space.seclume.oracle.net.OracleColumn;
import space.seclume.oracle.net.NsPacket;
import space.seclume.oracle.net.TtcAuth;
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

    /** Connection settings. Not the password, only its source. */
    public record Settings(String host, int port, String service, String user,
                           SecretProvider secret, int connectTimeoutMillis, HostList hosts,
                           ResultLimit resultLimit) {

        /** Without a result limit - what a URL without the option means. */
        public Settings(String host, int port, String service, String user,
                        SecretProvider secret, int connectTimeoutMillis, HostList hosts) {
            this(host, port, service, user, secret, connectTimeoutMillis, hosts,
                    ResultLimit.NONE);
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
                    connectTimeoutMillis, hosts, resultLimit);
        }

        /** The {@code (DESCRIPTION=...)} the listener wants. */
        String connectString() {
            return "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=" + host + ")(PORT=" + port
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

    private OracleSession(NsChannel channel) {
        this.channel = channel;
    }

    /** Connects, opens and logs in - three steps that the server ties together. */
    public static OracleSession open(Settings settings) throws SQLException {
        // One listener: a plain connect. Several: the next one when a listener
        // cannot be reached - and only then, see HostList.
        return settings.hosts().open(server -> openOne(settings.at(server)));
    }

    private static OracleSession openOne(Settings settings) throws SQLException {
        NsChannel channel;
        try {
            channel = NsChannel.connect(settings.host(), settings.port(),
                    settings.connectTimeoutMillis());
        } catch (IOException e) {
            throw new SQLNonTransientConnectionException(
                    "cannot reach " + settings.host() + ":" + settings.port(), "08001", e);
        }
        try {
            int type = channel.sendConnect(settings.connectString());
            if (type != NsPacket.TYPE_ACCEPT) {
                throw new SQLNonTransientConnectionException(
                        "the listener answered with " + NsPacket.typeName(type)
                        + " instead of ACCEPT", "08001");
            }
            channel.readAccept();

            TtcAuth.Challenge challenge = TtcFastAuth.open(channel, "seclume",
                    settings.user());
            TtcLogin.phaseTwo(channel, settings.user(), settings.secret(), challenge,
                    settings.connectString());
            OracleSession session = new OracleSession(channel);
            session.setResultLimit(settings.resultLimit());
            return session;
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
        try {
            rows = 0;
            boolean query = returnsRows(sql);
            if (!autoCommit && !query) {
                inTransaction = true;
            }
            TtcQuery.send(channel, sequence++, sql, query ? PREFETCH_ROWS : 0, query, binds,
                    cursorId, iterations, batch, autoCommit);
            TtcResult result = readAnswer(handler, known, returningCount);
            returningCount = 0;
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
            if (oneBlock) {
                // The caller asked for one block; the rest waits in the cursor.
                return result;
            }
            while (query && !result.isExhausted() && !result.isFailure() && cursor != 0) {
                TtcFetch.send(channel, sequence++, cursor, PREFETCH_ROWS);
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
        } catch (IOException e) {
            close();
            throw new SQLNonTransientConnectionException(
                    "the connection to the server broke: " + e.getMessage(), "08006", e);
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
        try (WireBuffer nothing = new WireBuffer(16)) {
            exchangeLob(() -> TtcLob.sendLength(channel, sequence++, locator, at, locatorLength),
                    nothing);
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
        try (WireBuffer nothing = new WireBuffer(16)) {
            exchangeLob(() -> TtcLob.sendCreateTemporary(channel, sequence++, character,
                    space.seclume.oracle.net.TtcDataTypes.CHARSET_AL32UTF8),
                    nothing, locator);
        } catch (SQLException | RuntimeException e) {
            locator.close();
            throw e;
        }
        return locator;
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
        exchangeLob(() -> TtcLob.sendRead(channel, sequence++, locator, at, locatorLength,
                offset, amount), sink);
    }

    /** Sends a LOB call and reads its answer, however many packets it takes. */
    private interface Send {
        void run() throws IOException;
    }

    private void exchangeLob(Send send, WireBuffer sink) throws SQLException {
        exchangeLob(send, sink, null);
    }

    /**
     * @param locatorOut if given, the locator the server returned is copied
     *                   into it - that is how a create gets its locator, and it
     *                   is why nothing here assumes 112 bytes: a temporary one
     *                   is 38.
     */
    private void exchangeLob(Send send, WireBuffer sink, WireBuffer locatorOut)
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
                TtcLob.Answer result = TtcLob.read(answer, 0, answer.position(), sink);
                if (result.tail().isFailure()
                        && result.tail().errorNumber() != TtcResult.ORA_NO_DATA_FOUND) {
                    throw new SQLException("reading the LOB failed (ORA-"
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
        } catch (IOException e) {
            close();
            throw new SQLNonTransientConnectionException(
                    "the connection to the server broke: " + e.getMessage(), "08006", e);
        }
    }

    /** Says that the next statement has that many {@code into} binds. */
    public void expectReturning(int count) {
        this.returningCount = count;
    }

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
            TtcFetch.send(channel, sequence++, cursorId, rows);
            TtcResult more = readAnswer(handler, columns);
            moreRows = !more.isExhausted() && !more.isFailure() && more.rowCount() > 0;
            return more;
        } catch (IOException e) {
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
        TtcResult result = new TtcResult(columns);
        result.expectReturned(returning);

        if ((channel.dataFlags() & END_OF_ANSWER) != 0) {
            // The common case: the whole answer is in this packet, and it is
            // parsed where it lies - no copy on the hot path.
            WireBuffer in = channel.packet();
            result.read(in, in.position(), in.limit(), handler);
            return result;
        }
        try (WireBuffer whole = collectAnswer()) {
            result.read(whole, 0, whole.position(), handler);
        }
        return result;
    }

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
        } catch (IOException e) {
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
        return open == null ? 0 : open.id();
    }

    /** What that cursor describes - the server sends it only the first time. */
    public java.util.List<OracleColumn> columnsFor(String sql) {
        OpenCursor open = cursors.get(sql);
        return open == null ? java.util.List.of() : open.columns();
    }

    /** Remembers what the server opened for this text. */
    public void rememberCursor(String sql, int id, java.util.List<OracleColumn> columns) {
        if (id == 0) {
            return;
        }
        cursors.put(sql, new OpenCursor(id, columns));
        if (cursors.size() > CURSOR_CACHE_SIZE) {
            java.util.Iterator<String> oldest = cursors.keySet().iterator();
            oldest.next();
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

    /** How often this session has waited for the server. */
    public long roundTrips() {
        return channel.roundTrips();
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
        boolean sawReset = false;
        int current = type;
        while (current == NsPacket.TYPE_MARKER) {
            sawReset |= channel.markerType() == NsPacket.MARKER_RESET;
            if (sawReset) {
                channel.sendMarker(NsPacket.MARKER_RESET);
                sawReset = false;
            }
            current = channel.nextPacket();
        }
        return current;
    }

    /** How many rows the last statement produced, across all blocks. */
    public long rowCount() {
        return rows;
    }

    public boolean isOpen() {
        return channel.isOpen();
    }

    @Override
    public void close() {
        channel.close();
    }
}
