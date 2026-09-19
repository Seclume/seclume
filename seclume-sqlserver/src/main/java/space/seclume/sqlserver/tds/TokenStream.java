package space.seclume.sqlserver.tds;

import java.io.IOException;
import java.sql.SQLException;
import java.util.List;

import space.seclume.internal.WireBuffer;

/**
 * Walks the token stream that a server answer consists of.
 *
 * <p>TDS has no result structure - the answer is a flat run of tokens, and
 * their order carries the meaning: a {@code COLMETADATA} opens a result, the
 * rows that follow belong to it, a {@code DONE} closes it, and the next
 * {@code COLMETADATA} opens the one after. A batch of three statements
 * produces that sequence three times in a single message.
 *
 * <p>Two things follow from that, and they shape this class:
 *
 * <ul>
 *   <li>Every token has to be walked over, even the uninteresting ones - there
 *       is no skipping ahead to the next one that matters, because a length
 *       sits where its own token says it does and nowhere else.</li>
 *   <li>An error does not end the stream. The server sends {@code ERROR} and
 *       carries on to the {@code DONE}; the failure is kept and raised by the
 *       caller once the stream is through, because otherwise the connection
 *       would be left with unread bytes on it.</li>
 * </ul>
 *
 * <p>The class deliberately reads from a {@link WireBuffer} rather than from a
 * channel: that way it can be tested against a synthetic stream, byte for
 * byte, without a server behind it.
 */
public final class TokenStream {

    /** DONE status: another result follows. */
    public static final int DONE_MORE = 0x0001;
    /** DONE status: the statement failed. */
    public static final int DONE_ERROR = 0x0002;
    /** DONE status: the row count is meaningful. */
    public static final int DONE_COUNT = 0x0010;

    /** The length of every DONE token: status, current command, row count. */
    private static final int DONE_SIZE = 12;

    /** Receives the rows - a window onto the buffer, valid until the next row. */
    @FunctionalInterface
    public interface RowHandler {
        void row(TdsRow row) throws SQLException;
    }

    private List<TdsColumn> columns = List.of();
    private TdsRow row;
    private long updateCount = -1;
    /**
     * The count the <b>first</b> statement of a batch reported.
     *
     * <p>Needed by exactly one caller and worth the field: a prepared insert
     * that asks for its generated key is sent as the insert plus a
     * {@code select scope_identity()}, and the select's own count would
     * otherwise be what {@code executeUpdate} reports. For a one-row insert
     * both happen to be 1, which is exactly the kind of coincidence that
     * holds until somebody inserts two rows.
     */
    private long firstUpdateCount = -1;
    /** What a procedure wrote back, in order - see readReturnValue. */
    private final java.util.List<Integer> returned = new java.util.ArrayList<>(2);
    /** One count per call of a batch, in order; null when nobody asked. */
    private long[] counts;
    private int countIndex;
    private long totalRows;
    private int returnStatus;
    private String database = "";
    private long transactionDescriptor;
    private boolean transactionChanged;
    private SQLException failure;

    /** The stream is built empty and then walked once. */
    public TokenStream() {
    }

    /**
     * Reads the tokens from {@code at} up to {@code end}.
     *
     * @param handler receives every row; may be {@code null} for a statement
     *                whose rows are of no interest
     */
    public void read(WireBuffer in, int at, int end, RowHandler handler)
            throws IOException, SQLException {
        int p = at;
        SQLException refused = null;
        while (p < end) {
            int token = in.getByte(p) & 0xff;
            p++;
            switch (token) {
                case Tds.TOKEN_COLMETADATA -> {
                    ColumnMetadata.Parsed parsed = ColumnMetadata.read(in, p);
                    columns = parsed.columns();
                    row = columns.isEmpty() ? null : new TdsRow(in, columns);
                    p = parsed.end();
                }
                case Tds.TOKEN_ROW, Tds.TOKEN_NBCROW -> {
                    if (row == null) {
                        throw new IOException("a row arrived before its description");
                    }
                    p = row.read(p, token == Tds.TOKEN_NBCROW);
                    totalRows++;
                    if (handler != null && refused == null) {
                        // A handler that refuses a row - a result limit, say -
                        // must not stop the walk: the rest of the answer still
                        // has to be read, or the next call would start in the
                        // middle of this one.
                        try {
                            handler.row(row);
                        } catch (SQLException e) {
                            refused = e;
                        }
                    }
                }
                case Tds.TOKEN_DONE, Tds.TOKEN_DONE_PROC, Tds.TOKEN_DONE_IN_PROC -> {
                    int status = ushort(in, p);
                    long count = readLong(in, p + 4);
                    if (counts != null) {
                        // Measured against a real server: the count arrives in
                        // a DONE_IN_PROC (0xff) and the call is closed by a
                        // DONE_PROC (0xfe). So the count belongs to the call
                        // that has not been closed yet.
                        if ((status & DONE_COUNT) != 0 && countIndex < counts.length) {
                            counts[countIndex] = count;
                        }
                        if (token == Tds.TOKEN_DONE_PROC) {
                            countIndex++;
                        }
                    }
                    if ((status & DONE_COUNT) != 0) {
                        // Several statements in one batch each report their own
                        // count; the last one that reports anything wins, which
                        // is what JDBC expects from executeUpdate.
                        updateCount = count;
                        if (firstUpdateCount < 0) {
                            firstUpdateCount = count;
                        }
                    }
                    p += DONE_SIZE;
                }
                case Tds.TOKEN_RETURN_VALUE -> p = readReturnValue(in, p);
                case Tds.TOKEN_ERROR -> p = readMessage(in, p, true);
                case Tds.TOKEN_INFO -> p = readMessage(in, p, false);
                case Tds.TOKEN_ENVCHANGE -> p = readEnvChange(in, p);
                // A cursor result names the table its columns came from and
                // says which of them make up the key. Neither is of any use
                // here, and both are length-prefixed, so they are stepped over.
                case Tds.TOKEN_ORDER, Tds.TOKEN_LOGIN_ACK, Tds.TOKEN_TABNAME,
                     Tds.TOKEN_COLINFO -> p += 2 + ushort(in, p);
                case Tds.TOKEN_RETURN_STATUS -> {
                    returnStatus = in.getIntLe(p);
                    p += 4;
                }
                case Tds.TOKEN_FEATURE_EXT_ACK -> p = skipFeatureExtAck(in, p);
                default -> throw new IOException(
                        "unexpected token " + Tds.tokenName(token) + " at offset " + (p - 1));
            }
        }
        if (refused != null) {
            throw refused;
        }
    }

    /** An error or a message from the server. */
    private int readMessage(WireBuffer in, int at, boolean isError) {
        int end = at + 2 + ushort(in, at);
        int p = at + 2;
        int number = in.getIntLe(p);
        p += 4;
        p++;                                          // state
        int severity = in.getByte(p) & 0xff;
        p++;
        int messageChars = ushort(in, p);
        p += 2;
        String message = utf16(in, p, messageChars);
        if (isError) {
            SQLException next = new SQLException(
                    message + " (error " + number + ", severity " + severity + ")",
                    sqlState(number), number);
            if (failure == null) {
                failure = next;
            } else {
                // Several errors in one batch: the first one stays the cause,
                // the rest hang behind it so that nothing is lost.
                failure.setNextException(next);
            }
        }
        return end;
    }

    /**
     * SQL Server sends no SQLState, only its own error number. These are the
     * ones a caller actually branches on; everything else stays generic.
     */
    private static String sqlState(int number) {
        return switch (number) {
            case 2601, 2627, 547 -> "23000";          // duplicate key, foreign key
            case 1205 -> "40001";                     // deadlock victim
            case 8152 -> "22001";                     // string would be truncated
            case 18456 -> "28000";                    // login failed
            default -> "S0001";
        };
    }

    /**
     * A change to the session state. Two of them matter:
     *
     * <ul>
     *   <li>Kind 1, the database - for {@code getCatalog}.</li>
     *   <li>Kinds 8 to 11, the transaction. The server hands out a descriptor
     *       when a transaction begins, and <b>every</b> following request has
     *       to quote it in its header. Miss this and the next statement runs
     *       outside the transaction that was just opened - which no error
     *       reports, because from the server's point of view nothing is
     *       wrong.</li>
     * </ul>
     *
     * <p>Everything else is skipped by its length.
     */
    private int readEnvChange(WireBuffer in, int at) {
        int end = at + 2 + ushort(in, at);
        int p = at + 2;
        int kind = in.getByte(p) & 0xff;
        p++;
        switch (kind) {
            case 1 -> database = utf16(in, p + 1, in.getByte(p) & 0xff);
            case 8, 11 -> {                           // begin, enlist
                transactionDescriptor = varByteLong(in, p);
                transactionChanged = true;
            }
            case 9, 10 -> {                           // commit, rollback
                transactionDescriptor = 0;
                transactionChanged = true;
            }
            default -> {
                // Language, collation, packet size - of no concern here.
            }
        }
        return end;
    }

    /** A one-byte length, then that many bytes, least significant first. */
    private static long varByteLong(WireBuffer in, int at) {
        int length = in.getByte(at) & 0xff;
        long value = 0;
        for (int i = length - 1; i >= 0; i--) {
            value = (value << 8) | (in.getByte(at + 1 + i) & 0xffL);
        }
        return value;
    }

    private int skipFeatureExtAck(WireBuffer in, int at) {
        int p = at;
        while (true) {
            int feature = in.getByte(p) & 0xff;
            p++;
            if (feature == 0xff) {
                return p;
            }
            p += 4 + in.getIntLe(p);
        }
    }

    private static int ushort(WireBuffer in, int at) {
        return (in.getByte(at) & 0xff) | ((in.getByte(at + 1) & 0xff) << 8);
    }

    private static long readLong(WireBuffer in, int at) {
        long value = 0;
        for (int i = 7; i >= 0; i--) {
            value = (value << 8) | (in.getByte(at + i) & 0xffL);
        }
        return value;
    }

    /** UTF-16LE; {@code chars} counts characters, not bytes. */
    private static String utf16(WireBuffer in, int at, int chars) {
        char[] text = new char[chars]; // seclume-allow: server messages, protocol text and never a secret
        for (int i = 0; i < chars; i++) {
            text[i] = (char) ((in.getByte(at + i * 2) & 0xff)
                    | ((in.getByte(at + i * 2 + 1) & 0xff) << 8));
        }
        return new String(text); // seclume-allow: protocol text, never a secret
    }

    // ---- what the stream left behind -------------------------------------


    /**
     * A value the server wrote back - {@code RETURNVALUE}, token 0xac.
     *
     * <p>Only integers are read, and that is not laziness: the one place this
     * driver asks for an OUTPUT parameter is the handle of a server-side
     * cursor, and that is an {@code int}. Anything else would be a promise
     * that nothing keeps, so it says so instead.
     *
     * <p>Layout: ordinal, name, status, user type, flags, then the type and
     * the value - the same TYPE_INFO shape a column has.
     */
    private int readReturnValue(WireBuffer in, int at) throws IOException {
        int p = at + 2;                               // parameter ordinal
        p += 1 + 2 * (in.getByte(p) & 0xff);          // name, UTF-16
        p += 1;                                       // status
        p += 4;                                       // user type
        p += 2;                                       // flags
        int type = in.getByte(p) & 0xff;
        p++;
        if (type == Tds.TYPE_INTN) {
            p++;                                      // maximum width
            int length = in.getByte(p) & 0xff;
            p++;
            long value = 0;
            for (int i = length - 1; i >= 0; i--) {
                value = (value << 8) | (in.getByte(p + i) & 0xff);
            }
            returned.add(length == 0 ? null : (int) value);
            return p + length;
        }
        throw new IOException("this driver only reads an int back from a procedure, "
                + "and the server sent type 0x" + Integer.toHexString(type)
                + " - nothing here asks for anything else");
    }

    /**
     * The values the server wrote back, in the order of the parameters.
     *
     * <p>Order matters: {@code sp_cursorprepexec} answers with the handle of
     * the prepared statement <b>and</b> the handle of the cursor, and taking
     * the wrong one gives a number that looks fine and works for nothing.
     */
    public Integer returned(int index) {
        return index < returned.size() ? returned.get(index) : null;
    }

    /** The columns of the last result; empty for a statement without one. */
    public List<TdsColumn> columns() {
        return columns;
    }

    /** Keep the counts of a batch apart - one per call, in order. */
    void expectCounts(int expected) {
        this.counts = new long[expected]; // seclume-allow: update counts, not a secret
        this.countIndex = 0;
    }

    /** The counts of a batch; empty when nobody asked for them. */
    public long[] updateCounts() {
        return counts == null ? new long[0] : counts;
    }

    /** The last row count the server reported; -1 if it reported none. */
    public long updateCount() {
        return updateCount;
    }

    /** The count of the first statement in the batch; -1 if none reported one. */
    public long firstUpdateCount() {
        return firstUpdateCount;
    }

    /** How many rows went through the handler. */
    public long rowCount() {
        return totalRows;
    }

    /** The return value of a procedure. */
    public int returnStatus() {
        return returnStatus;
    }

    /** The database the session ended up in, if the server said so. */
    public String database() {
        return database;
    }

    /** Whether the server reported a transaction change in this answer. */
    public boolean transactionChanged() {
        return transactionChanged;
    }

    /** The descriptor the following requests have to quote; 0 outside one. */
    public long transactionDescriptor() {
        return transactionDescriptor;
    }

    /** The first error, with the rest chained behind it; {@code null} if none. */
    public SQLException failure() {
        return failure;
    }
}
