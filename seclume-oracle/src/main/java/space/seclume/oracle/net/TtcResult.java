package space.seclume.oracle.net;

import java.sql.SQLException;
import java.util.List;

import space.seclume.internal.WireBuffer;

/**
 * Walks the answer to a statement.
 *
 * <p>Oracle answers with a run of messages, each starting with a type byte:
 * the column description, then a header per row block, then the rows, and at
 * the end status information. One round trip carries all of it, as long as the
 * rows fit into the answer.
 *
 * <p><b>{@code ORA-01403: no data found} is not an error here</b> - it is how
 * the server says the result is exhausted. A driver that passes it on reports
 * a failure for every successful query.
 *
 * <p>What is deliberately <b>not</b> parsed yet: everything after the rows.
 * The status message carries the row count and the cursor number, and both
 * will be needed - for now the walk stops at the first message it does not
 * know, which is honest and keeps the rows correct.
 */
public final class TtcResult {

    /** The end of the result, not a failure. */
    public static final int ORA_NO_DATA_FOUND = 1403;

    /** Receives the rows - a window onto the buffer, valid until the next row. */
    @FunctionalInterface
    public interface RowHandler {
        void row(TtcRow row) throws SQLException;
    }

    private List<OracleColumn> columns;
    private int cursorId;
    private long rowCount;
    private boolean exhausted;
    private int stoppedAt;
    private int errorNumber;
    private String errorText;
    /** How many output binds the answer carries, and what came back in them. */
    private int expectedReturned;
    private final java.util.List<byte[]> returned = new java.util.ArrayList<>(2);
    private long affectedRows;

    /** A fresh answer - the description is expected to come with it. */
    public TtcResult() {
        this(List.of());
    }

    /**
     * An answer to a fetch call.
     *
     * <p>A fetch answer carries no column description: the server assumes the
     * client still has the one from the statement. Whoever fetches has to pass
     * it in, or the rows cannot be read.
     */
    public TtcResult(List<OracleColumn> columns) {
        this.columns = columns;
    }

    /**
     * The same, continuing a result that has already delivered rows.
     *
     * <p>The row object is handed on from the previous answer because the
     * server refers back to it: a value that has not changed is not sent
     * again, and the first row of a fetch may point at the last row of the
     * block before it. See {@link TtcRow#carryOver()}.
     */
    public TtcResult(List<OracleColumn> columns, TtcRow previous) {
        this.columns = columns;
        this.previous = previous;
    }

    private TtcRow previous;

    /** The row window this answer used, so the next one can continue it. */
    public TtcRow row() {
        return previous;
    }

    /** Reads the answer from {@code at} up to {@code end}. */
    public void read(WireBuffer in, int at, int end, RowHandler handler) throws SQLException {
        int p = at;
        TtcRow row = previous;
        if (row != null) {
            row.rebind(in);
        } else if (!columns.isEmpty()) {
            row = new TtcRow(in, columns);
        }
        previous = row;
        byte[] unchanged = null;
        // A handler that refuses a row - a result limit, say - must not stop
        // the walk: the rest of the answer still has to be read, or the next
        // call would start in the middle of this one.
        SQLException refused = null;
        while (p < end) {
            int type = in.getByte(p) & 0xff;
            p++;
            switch (type) {
                case TtcMessage.TYPE_DESCRIBE_INFO -> {
                    TtcDescribe.Parsed parsed = TtcDescribe.read(in, p);
                    columns = parsed.columns();
                    // A description means a new result: whatever the previous
                    // one carried over says nothing about this one.
                    if (row != null) {
                        row.release();
                    }
                    row = columns.isEmpty() ? null : new TtcRow(in, columns);
                    previous = row;
                    p = parsed.end();
                }
                case TtcMessage.TYPE_ROW_HEADER -> {
                    Header header = readHeader(in, p);
                    unchanged = header.unchanged();
                    p = header.end();
                }
                case TtcMessage.TYPE_BIT_VECTOR -> {
                    // A number - the row this applies to - and then the
                    // vector itself, which carries no length: it is one bit
                    // per column, rounded up to whole bytes. Reading a length
                    // in front of it eats the first byte of the next row, and
                    // the walk then ends on a byte that is no message type.
                    p = skipNumber(in, p);             // row index
                    int width = (columns.size() + 7) / 8;
                    unchanged = new byte[width]; // seclume-allow: a bit vector of the protocol, not a secret
                    for (int i = 0; i < width; i++) {
                        unchanged[i] = in.getByte(p + i);
                    }
                    p += width;
                }
                case TtcMessage.TYPE_ROW_DATA -> {
                    if (expectedReturned > 0 && returned.isEmpty()) {
                        // A DML returning answers with its output binds first,
                        // and without a description - the shape comes from the
                        // binds that were sent.
                        p = readReturned(in, p);
                        continue;
                    }
                    if (row == null) {
                        throw new SQLException("a row arrived before its description");
                    }
                    p = row.read(p, unchanged);
                    rowCount++;
                    if (handler != null && refused == null) {
                        try {
                            handler.row(row);
                        } catch (SQLException e) {
                            refused = e;
                        }
                    }
                }
                case TtcMessage.TYPE_IO_VECTOR -> p = skipIoVector(in, p);
                case TtcMessage.TYPE_PARAMETER -> p = skipReturnParameters(in, p);
                case TtcMessage.TYPE_ERROR -> {
                    readError(in, p);
                    if (refused != null) {
                        throw refused;
                    }
                    return;
                }
                default -> {
                    // Status, warnings, end of response: not parsed yet. The
                    // type is kept so that a caller can say what stopped the
                    // walk instead of silently returning too few rows.
                    stoppedAt = type;
                    if (refused != null) {
                        throw refused;
                    }
                    return;
                }
            }
        }
        if (refused != null) {
            throw refused;
        }
    }

    /**
     * Steps over the in/out vector a PL/SQL call is answered with.
     *
     * <p>It says which binds the server wrote into, and the values follow it.
     * Before this was handled the walk stopped here - not with an error, which
     * would have been easy to find, but by returning what it had, so the
     * outputs came back empty and the call looked as if the procedure had
     * done nothing.
     *
     * <p>The shape was measured rather than read: a byte, the number of
     * binds, five numbers that were zero, one and zeros in every recording,
     * and then <b>one flag byte per bind</b> - {@code 0x20} where the client
     * sent a value and {@code 0x10} where the server writes one. Two calls of
     * two binds could not have shown that last part, so a third with three
     * binds was recorded: {@code 20 10} became {@code 20 10 10}. See
     * {@code docs/protocol/oracle.md}.
     */
    private int skipIoVector(WireBuffer in, int at) {
        int p = at + 1;                                // a byte nobody has decoded
        long binds = number(in, p);
        p = skipNumber(in, p);
        for (int i = 0; i < 5; i++) {
            p = skipNumber(in, p);                     // constant in every recording
        }
        return p + (int) binds;                        // one flag byte per bind
    }

    /** The row header, with the bit vector of columns that stayed the same. */
    private record Header(byte[] unchanged, int end) {
    }

    private static Header readHeader(WireBuffer in, int at) {
        int p = at;
        p++;                                           // flags
        p = skipNumber(in, p);                         // number of requests
        p = skipNumber(in, p);                         // iteration number
        p = skipNumber(in, p);                         // number of iterations
        p = skipNumber(in, p);                         // buffer length
        int length = in.getByte(p) & 0xff;
        long bytes = 0;
        for (int i = 0; i < length; i++) {
            bytes = (bytes << 8) | (in.getByte(p + 1 + i) & 0xff);
        }
        p += 1 + length;
        byte[] unchanged = null;
        if (bytes > 0) {
            p++;                                       // the length once more
            unchanged = new byte[(int) bytes]; // seclume-allow: a bit vector of the protocol, not a secret
            for (int i = 0; i < bytes; i++) {
                unchanged[i] = in.getByte(p + i);
            }
            p += (int) bytes;
        }
        int keyLength = in.getByte(p) & 0xff;          // rxhrid
        p += 1 + (keyLength == 0 ? 0 : keyLength);
        if (keyLength > 0) {
            // What rxhrid announces is the row's rowid, and it follows as a
            // block of its own - see TtcDescribe, where the same pair stands
            // after the description of the first row. Only a "for update"
            // answer carries it.
            p = skipBlock(in, p);
        }
        return new Header(unchanged, p);
    }

    /**
     * The return parameters of a call - nothing here is needed, but the
     * message has to be walked over: behind it sits the error message, and
     * with it the cursor number that a fetch call needs. Stopping here is what
     * made large results end silently after the first block.
     */
    private static int skipReturnParameters(WireBuffer in, int at) {
        int p = at;
        long count = number(in, p);
        p = skipNumber(in, p);
        for (int i = 0; i < count; i++) {
            p = skipNumber(in, p);
        }
        long bytes = number(in, p);
        p = skipNumber(in, p);
        p += (int) bytes;
        long pairs = number(in, p);
        p = skipNumber(in, p);
        for (int i = 0; i < pairs; i++) {
            p = skipBlock(in, p);                      // key
            p = skipBlock(in, p);                      // value
            p = skipNumber(in, p);                     // flags
        }
        long registration = number(in, p);
        p = skipNumber(in, p);
        return p + (int) registration;
    }

    /**
     * The error message - which is also how the server says "no more rows".
     *
     * <p>{@code ORA-01403} is the end of the result and not a failure. Every
     * other number is one, and it is raised by the caller.
     *
     * <p>The layout is long and mostly of no interest, but none of it can be
     * skipped by arithmetic: a rowid sits in the middle, then three lists for
     * batch errors, and only after them the error number. That is why this
     * walks every field.
     */
    private void readError(WireBuffer in, int at) {
        int p = at;
        p = skipNumber(in, p);                         // call status
        p = skipNumber(in, p);                         // end-to-end sequence
        p = skipNumber(in, p);                         // current row number
        p = skipNumber(in, p);                         // error number, old and short
        p = skipNumber(in, p);                         // array element error
        p = skipNumber(in, p);                         // array element error
        cursorId = (int) number(in, p);
        p = skipNumber(in, p);                         // cursor number
        p = skipNumber(in, p);                         // error position
        // Six single bytes, not five and a number. The sixth is the flag byte,
        // and a zero byte reads the same either way - which is why a statement
        // that failed with a flag of zero went through and an insert, whose
        // flag is not zero, ran off the message.
        p += 6;                                        // sql type, fatal, flags,
                                                       // cursor options, UPI, flags
        // The rowid: two numbers, a single byte, two more numbers. The byte in
        // the middle is the same trap once more.
        p = skipNumber(in, p);                         // relative block address
        p = skipNumber(in, p);                         // partition
        p += 1;
        p = skipNumber(in, p);                         // block number
        p = skipNumber(in, p);                         // slot number
        p = skipNumber(in, p);                         // operating system error
        p += 2;                                        // statement and call number
        p = skipNumber(in, p);                         // padding
        p = skipNumber(in, p);                         // successful iterations
        // The logical rowid: a length, and only if it is not zero does a
        // block follow. A select leaves it empty, an insert does not - which
        // is why the walk was right for years' worth of queries and ran off
        // the message on the first insert.
        long rowidLength = number(in, p);
        p = skipNumber(in, p);
        if (rowidLength > 0) {
            p = skipBlock(in, p);
        }

        p = skipList(in, p);                           // batch error codes
        p = skipList(in, p);                           // batch error offsets
        p = skipList(in, p);                           // batch error messages

        errorNumber = (int) number(in, p);
        p = skipNumber(in, p);
        // And right behind the number the count of rows the statement touched -
        // the one thing an update has to report back.
        affectedRows = number(in, p);
        exhausted = errorNumber == ORA_NO_DATA_FOUND;
        errorText = readErrorText(in, p);
    }

    /**
     * The server's own wording, behind the number.
     *
     * <p>Worth the walk: {@code ORA-00942} alone leaves a developer guessing,
     * while "table or view does not exist" ends the question - and a PL/SQL
     * block reports what it raised only here, in the text.
     *
     * <p>Three fields sit between the row count and the text, and the text
     * itself is a length and its bytes. Anything unexpected gives up quietly
     * and leaves the number to speak: an error must never turn into a second
     * error while it is being read.
     */
    private static String readErrorText(WireBuffer in, int at) {
        try {
            int p = skipNumber(in, at);                // row count
            p = skipNumber(in, p);                     // error position in the text
            p = skipNumber(in, p);                     // reserved, always zero here
            int length = in.getByte(p) & 0xff;
            if (length == 0 || length > 0xfd || p + 1 + length > in.limit()) {
                return null;
            }
            int keep = in.position();
            in.position(p + 1);
            String text = in.readString(length);
            in.position(keep);
            return text.strip();
        } catch (RuntimeException e) {
            return null;                               // the number still stands
        }
    }

    /**
     * One of the three batch lists: a count, and only if it is not zero does
     * anything follow. For a single statement all three are empty, which is
     * the case this driver has seen.
     */
    private static int skipList(WireBuffer in, int at) {
        long count = number(in, at);
        int p = skipNumber(in, at);
        if (count == 0) {
            return p;
        }
        throw new IllegalStateException("batch errors are not read yet");
    }

    private static int skipBlock(WireBuffer in, int at) {
        int length = in.getByte(at) & 0xff;
        return at + 1 + (length == 0 ? 0 : length);
    }

    private static long number(WireBuffer in, int at) {
        int length = in.getByte(at) & 0xff;
        long value = 0;
        for (int i = 0; i < length; i++) {
            value = (value << 8) | (in.getByte(at + 1 + i) & 0xff);
        }
        return value;
    }

    private static int skipNumber(WireBuffer in, int at) {
        return at + 1 + (in.getByte(at) & 0xff);
    }


    /**
     * The values the server wrote back into the {@code into} binds.
     *
     * <p>A DML returning answers with a {@code ROW_DATA} message in front of
     * everything else, and it carries one entry per output bind: how many rows
     * it stands for, the value itself, and a return code. There is no column
     * description - the client knows the shape from the binds it sent, which
     * is why this has to be asked for rather than discovered.
     */
    public java.util.List<byte[]> returned() {
        return returned;
    }

    /** Says how many output binds the answer will carry. */
    public void expectReturned(int count) {
        expectReturned(count, false);
    }

    /**
     * The same, saying whether they come from a PL/SQL call.
     *
     * <p>The two shapes differ by one field and the difference is invisible
     * until the values come out empty. A DML {@code returning} writes, per
     * bind, <b>how many rows it stands for</b>, then the value, then a
     * return code - it has to, because one statement can return many rows. A
     * PL/SQL bind has exactly one value and no count: the recorded answer to
     * {@code begin p(:1, :2); end;} is {@code 07 02 C1 2B 00}, which is the
     * row-data marker, the number 42 and a return code of zero. Read with the
     * count expected, the value itself is eaten as the count and what is left
     * is an empty value - not an error, just nothing. Measured with
     * {@code docs/protocol/oracle.md}.
     */
    public void expectReturned(int count, boolean fromCall) {
        this.expectedReturned = count;
        this.returnedFromCall = fromCall;
    }

    private boolean returnedFromCall;

    private int readReturned(WireBuffer in, int at) {
        int p = at;
        for (int i = 0; i < expectedReturned; i++) {
            long rows = 1;
            if (!returnedFromCall) {
                rows = number(in, p);                  // rows this bind stands for
                p = skipNumber(in, p);
            }
            int length = in.getByte(p) & 0xff;
            byte[] value = new byte[length]; // seclume-allow: a returned key, payload
            for (int b = 0; b < length; b++) {
                value[b] = in.getByte(p + 1 + b);
            }
            p += 1 + length;
            p = skipNumber(in, p);                     // return code
            if (rows > 0) {
                // An empty value is a NULL output and belongs in the list -
                // leaving it out would shift every output after it.
                returned.add(value);
            }
        }
        return p;
    }

    /** The columns of the result. */
    public List<OracleColumn> columns() {
        return columns;
    }

    /** How many rows went through the handler. */
    public long rowCount() {
        return rowCount;
    }

    /** Whether the server said the result is finished - {@code ORA-01403}. */
    public boolean isExhausted() {
        return exhausted;
    }

    /** The cursor the server opened - a fetch call has to name it. */
    public int cursorId() {
        return cursorId;
    }

    /** The message type the walk stopped at, 0 if it read to the end. */
    public int stoppedAt() {
        return stoppedAt;
    }

    /**
     * How many rows the statement changed.
     *
     * <p>The server sends it right behind the error number, and only there -
     * an update that reports nothing back is an update whose result nobody can
     * check.
     */
    public long affectedRows() {
        return affectedRows;
    }

    /** What the server wrote about the error, or {@code null}. */
    public String errorText() {
        return errorText;
    }

    /** The number the server reported; 1403 means "no more rows". */
    public int errorNumber() {
        return errorNumber;
    }

    /**
     * Whether the statement really failed.
     *
     * <p>{@code ORA-01403} is not a failure: it is how the server ends a
     * result. Everything else with a number is one. Getting this distinction
     * wrong in either direction is expensive - a driver that reports 1403
     * fails every successful query, and one that swallows all numbers turns a
     * broken statement into an empty result.
     */
    public boolean isFailure() {
        return errorNumber != 0 && errorNumber != ORA_NO_DATA_FOUND;
    }
}
