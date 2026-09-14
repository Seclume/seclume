package space.seclume.oracle.net;

import java.io.IOException;

import space.seclume.internal.WireBuffer;

/**
 * A statement, as TTC function 94.
 *
 * <p>One round trip does everything: the client sends the text, and the answer
 * already carries the column description, the rows and the end of the result.
 * Oracle has no separate parse and no separate fetch as long as the rows fit
 * into the answer - which is the shape worth building, not the three-step one.
 *
 * <p>The field list comes from {@code python-oracledb} 4.0.2, read as protocol
 * documentation and checked field by field against a recorded exchange; see
 * {@code docs/protocol/oracle.md}. Two details in it are the kind
 * nobody guesses:
 *
 * <ul>
 *   <li>From server version 23.1 on there is an <b>eight-byte token number</b>
 *       right after the sequence number. It shifts every field behind it.</li>
 *   <li>The <b>sequence number counts per connection</b>. After the combined
 *       opening and the login it stands at three.</li>
 * </ul>
 */
public final class TtcQuery {

    /** Execute and fetch in one call. */
    public static final int FUNCTION = 94;

    // The option bits, as the reference client sets them.
    private static final int OPTION_PARSE = 0x0001;
    private static final int OPTION_BIND = 0x0008;
    private static final int OPTION_EXECUTE = 0x0020;
    private static final int OPTION_FETCH = 0x0040;
    private static final int OPTION_NOT_PLSQL = 0x8000;
    /**
     * Commit as soon as the statement has run - Oracle's auto-commit.
     *
     * <p>One bit, not a second round trip: the difference between
     * {@code 0x8029} and {@code 0x8129} in a recording of the same insert once
     * with and once without {@code autocommit}.
     */
    private static final int OPTION_COMMIT = 0x0100;

    /** A query without bind variables: parse it, run it, and send rows back. */
    public static final int OPTIONS_QUERY =
            OPTION_NOT_PLSQL | OPTION_FETCH | OPTION_EXECUTE | OPTION_PARSE;

    /**
     * Anything that returns no rows - an insert, a create table.
     *
     * <p>Without the fetch bit, and that is not a detail: asking to fetch from
     * a statement that produced no cursor answers {@code ORA-01003, no
     * statement parsed}. The bit is what tells the server whether rows are
     * expected at all.
     */
    public static final int OPTIONS_UPDATE =
            OPTION_NOT_PLSQL | OPTION_EXECUTE | OPTION_PARSE;

    /** The largest {@code LONG} the client will accept. */
    private static final long MAX_LONG_LENGTH = 0x7fffffffL;
    /** The fixed length of the {@code al8i4} field. */
    private static final int AL8I4_LENGTH = 13;
    /** Zero bytes between the last pointer and the statement text - observed. */
    private static final int TAIL_ZEROES = 15;
    /** Up to this length a byte string carries a single length byte. */
    private static final int SHORT_LENGTH = 252;
    /** The length byte that says "chunks follow". */
    private static final int CHUNKED = 0xfe;
    /** How much goes into one chunk. */
    private static final int CHUNK_SIZE = 32767;

    /**
     * How many rows the server sends along when none are expected.
     *
     * <p>One, not zero - that is what the reference client sends for an insert
     * or a create table, and it is not a free choice.
     */
    private static final int NO_ROWS_EXPECTED = 1;

    /** Where the number of iterations sits in the {@code al8i4} vector. */
    private static final int AL8I4_ITERATIONS = 1;
    /** Where the flag sits that a query sets. */
    private static final int AL8I4_QUERY = 7;
    /** A fixed value in the vector, always the same. */
    private static final int AL8I4_CONSTANT = 9;
    /** And what it is. */
    private static final int AL8I4_CONSTANT_VALUE = 0x8000;

    private TtcQuery() {
    }

    /**
     * Writes the call for a statement without bind variables.
     *
     * @param sequence      the message counter of this connection
     * @param prefetchRows  how many rows the server may send along
     */
    public static void put(WireBuffer out, int sequence, String sql, int prefetchRows) {
        put(out, sequence, sql, prefetchRows, true, null);
    }

    /** Writes the call for a statement without bind variables. */
    public static void put(WireBuffer out, int sequence, String sql, int prefetchRows,
                           boolean query) {
        put(out, sequence, sql, prefetchRows, query, null);
    }

    /**
     * Writes the call.
     *
     * @param query whether rows are expected back
     */
    public static void put(WireBuffer out, int sequence, String sql, int prefetchRows,
                           boolean query, TtcBinds binds) {
        put(out, sequence, sql, prefetchRows, query, binds, 0, 1, null);
    }

    /**
     * Writes the call, with everything the caller may want to decide.
     *
     * @param cursorId   the cursor the server already opened for this text, or
     *                   0 to have it parse the text anew
     * @param iterations how many sets of values follow - one for a normal
     *                   statement, one per row for a batch
     * @param rows       supplies the values for row {@code i}, or {@code null}
     */
    public static void put(WireBuffer out, int sequence, String sql, int prefetchRows,
                           boolean query, TtcBinds binds, int cursorId, int iterations,
                           Rows rows) {
        put(out, sequence, sql, prefetchRows, query, binds, cursorId, iterations, rows, false);
    }

    /**
     * Writes the call, with everything the caller may want to decide.
     *
     * @param autoCommit whether the server should commit when it is done
     */
    public static void put(WireBuffer out, int sequence, String sql, int prefetchRows,
                           boolean query, TtcBinds binds, int cursorId, int iterations,
                           Rows rows, boolean autoCommit) {
        byte[] text = sql.getBytes(java.nio.charset.StandardCharsets.UTF_8); // seclume-allow: statement text, never a secret

        out.putByte((byte) TtcMessage.TYPE_FUNCTION);
        out.putByte((byte) FUNCTION);
        out.putByte((byte) sequence);
        TtcParameters.putNumber(out, 0);                  // token number

        int count = binds == null ? 0 : binds.count();
        int options = query ? OPTIONS_QUERY : OPTIONS_UPDATE;
        if (cursorId != 0) {
            // The server already has this statement under that number, so it
            // must not parse it again - and the text is not sent at all. That
            // is not only cheaper: a parse opens a <b>new</b> cursor every
            // time, and a connection that keeps parsing the same statement
            // runs into ORA-01000, maximum open cursors, after a few hundred
            // executions.
            options &= ~OPTION_PARSE;
        }
        if (count > 0) {
            options |= OPTION_BIND;
        }
        if (autoCommit && !query) {
            // Auto-commit is a bit in this mask, not a second statement. A
            // driver that leaves it out and sends no commit of its own writes
            // data that is rolled back when the connection closes - which is
            // what this one did.
            options |= OPTION_COMMIT;
        }
        TtcParameters.putNumber(out, options);
        TtcParameters.putNumber(out, cursorId);
        out.putByte((byte) (cursorId == 0 ? 1 : 0));      // pointer: statement text
        TtcParameters.putNumber(out, cursorId == 0 ? text.length : 0);
        out.putByte((byte) 1);                            // pointer: vector
        TtcParameters.putNumber(out, AL8I4_LENGTH);
        out.putByte((byte) 0);                            // pointer: al8o4
        out.putByte((byte) 0);                            // pointer: al8o4l
        TtcParameters.putNumber(out, 0);                  // prefetch buffer size
        TtcParameters.putNumber(out, query ? prefetchRows : NO_ROWS_EXPECTED);
        TtcParameters.putNumber(out, MAX_LONG_LENGTH);
        out.putByte((byte) (count > 0 ? 1 : 0));          // pointer: binds
        TtcParameters.putNumber(out, count);              // number of binds
        for (int i = 0; i < 5; i++) {
            out.putByte((byte) 0);                        // al8app, al8txn, al8txl, al8kv, al8kvl
        }
        out.putByte((byte) 0);                            // pointer: defines
        TtcParameters.putNumber(out, 0);                  // number of defines
        TtcParameters.putNumber(out, 0);                  // registration id, lower half
        out.putByte((byte) 0);                            // pointer: al8objlist
        out.putByte((byte) 1);                            // pointer: al8objlen
        // From here to the statement text everything is zero, and how many
        // zeroes there are depends on what the server can do: al8blv, al8dnam,
        // the upper half of the registration id, al8pidmlrc, and from 12.2 on
        // the SQL signature and the SQL id. Which of those the reference client
        // writes is decided by capability flags we do not evaluate - so the
        // count is taken from the recording rather than derived. All of them
        // are zero for a query without bind variables, so the number is the
        // only thing that matters.
        out.putZeroes(TAIL_ZEROES);

        if (cursorId == 0) {
            putBytes(out, text);
        }
        putAl8i4(out, query, cursorId, iterations, prefetchRows);
        if (count > 0) {
            try {
                long[] sizes = null;
                if (rows != null) {
                    sizes = new long[count]; // seclume-allow: buffer sizes of a batch, not a secret
                    for (int row = 0; row < iterations; row++) {
                        rows.bind(row);
                        binds.measure(sizes);
                    }
                }
                binds.putDescriptors(out, sizes);
                for (int row = 0; row < iterations; row++) {
                    if (rows != null) {
                        rows.bind(row);
                    }
                    binds.putValues(out);
                }
            } catch (java.sql.SQLException e) {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
        }
    }

    /** Supplies the values of one row of a batch. */
    @FunctionalInterface
    public interface Rows {
        void bind(int row) throws java.sql.SQLException;
    }

    /**
     * The thirteen numbers of the call.
     *
     * <p>Field 1 is the one that cost a round trip per prepared query for a
     * while. It is <b>how many rows the execute itself may bring back</b>, and
     * it was zero for every query. On the first execution that goes unnoticed:
     * the server answers with the prefetch anyway. On a <b>re-execution of an
     * existing cursor</b> it does not - it answers with no rows at all, and
     * every prepared query paid a fetch to get what should have come with the
     * execute. Measured, not read: with the field at zero a second run cost
     * two round trips, with it at the prefetch count it costs one.
     *
     * <p>It stays zero on a <b>first</b> execution, because that is what the
     * reference client sends and what the recorded byte comparisons hold the
     * driver to - there the server answers with rows regardless.
     *
     * <p>Which of the thirteen are not zero depends on what the statement is,
     * and that is not a detail: a statement that returns no rows has to say
     * <b>one iteration</b> in the same field, and one that does sets a flag
     * further along instead. With the query shape sent for a
     * {@code create table} the server answers {@code ORA-01003, no statement
     * parsed} - it parsed the text and then ran it zero times.
     */
    private static void putAl8i4(WireBuffer out, boolean query, int cursorId,
                                 int iterations, int prefetchRows) {
        for (int i = 0; i < AL8I4_LENGTH; i++) {
            long value = switch (i) {
                // One where the text is parsed, zero where an existing cursor
                // is executed again - taken from a recording of both.
                case 0 -> cursorId == 0 ? 1 : 0;
                // Zero on a first execution - that is what the reference
                // client sends, and the recorded byte comparisons hold it
                // there. On a re-execution the prefetch count goes in, which
                // is the whole point: see the javadoc above.
                case AL8I4_ITERATIONS -> query
                        ? (cursorId == 0 ? 0 : prefetchRows) : iterations;
                case AL8I4_QUERY -> query ? 1 : 0;
                case AL8I4_CONSTANT -> AL8I4_CONSTANT_VALUE;
                default -> 0;
            };
            TtcParameters.putNumber(out, value);
        }
    }

    /**
     * A byte string, in one piece or in chunks.
     *
     * <p>Up to 252 bytes a single length byte is enough. Beyond that the
     * length byte is {@code 0xfe} and the bytes follow in chunks, each with
     * its own length, closed by a zero. Metadata queries are longer than 252
     * bytes almost by definition, so this is not an exotic path.
     */
    private static void putBytes(WireBuffer out, byte[] text) {
        if (text.length <= SHORT_LENGTH) {
            out.putByte((byte) text.length);
            out.putBytes(java.lang.foreign.MemorySegment.ofArray(text), 0, text.length);
            return;
        }
        out.putByte((byte) CHUNKED);
        int at = 0;
        while (at < text.length) {
            int chunk = Math.min(CHUNK_SIZE, text.length - at);
            TtcParameters.putNumber(out, chunk);
            out.putBytes(java.lang.foreign.MemorySegment.ofArray(text), at, chunk);
            at += chunk;
        }
        TtcParameters.putNumber(out, 0);
    }

    /** Sends the call on its own packet. */
    public static void send(NsChannel channel, int sequence, String sql, int prefetchRows,
                            boolean query) throws IOException {
        send(channel, sequence, sql, prefetchRows, query, null);
    }

    /** Sends the call on its own packet. */
    public static void send(NsChannel channel, int sequence, String sql, int prefetchRows,
                            boolean query, TtcBinds binds) throws IOException {
        send(channel, sequence, sql, prefetchRows, query, binds, 0, 1, null);
    }

    /** Sends the call on its own packet, with cursor and iterations. */
    public static void send(NsChannel channel, int sequence, String sql, int prefetchRows,
                            boolean query, TtcBinds binds, int cursorId, int iterations,
                            Rows rows) throws IOException {
        send(channel, sequence, sql, prefetchRows, query, binds, cursorId, iterations, rows,
                false);
    }

    /** Sends the call on its own packet, with the commit flag. */
    public static void send(NsChannel channel, int sequence, String sql, int prefetchRows,
                            boolean query, TtcBinds binds, int cursorId, int iterations,
                            Rows rows, boolean autoCommit) throws IOException {
        WireBuffer out = channel.beginData();
        put(out, sequence, sql, prefetchRows, query, binds, cursorId, iterations, rows,
                autoCommit);
        channel.sendData();
    }
}
