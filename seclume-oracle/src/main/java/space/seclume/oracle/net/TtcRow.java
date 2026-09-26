package space.seclume.oracle.net;

import java.util.List;

import space.seclume.internal.WireBuffer;

/**
 * A result row - a window onto the message buffer, not a copy.
 *
 * <p>The same object serves every row: {@link #read} moves the window along.
 * So there is no object per row and none per cell; whoever wants to keep a row
 * copies its values before the next one is read.
 *
 * <p>Every value is a length-prefixed block, and a length of zero is SQL NULL.
 * Numbers arrive in Oracle's own format and are decoded by
 * {@link OracleNumber} - not into a {@code String} on the way, and for
 * {@code getLong} not at all.
 */
public final class TtcRow {

    private WireBuffer in;
    private final List<OracleColumn> columns;
    /** Two entries per cell: start within the buffer and length (-1 = NULL). */
    private final int[] cells;

    /**
     * Where the values of the previous answer were put so that the next one
     * can still refer to them.
     *
     * <p>The server may say "this value is the same as in the row before"
     * (see {@link #read}), and it says that across the boundary of a fetch as
     * well: the first row of the second block can point back into the last
     * row of the first. That block is gone by then - the receive buffer has
     * been written over - so the values that could still be referred to are
     * moved here before the buffer is reused. Native memory to native memory,
     * as everywhere else.
     */
    private WireBuffer carry;
    private WireBuffer spare;
    /** Which cells live in {@link #carry} rather than in the message. */
    private final boolean[] carried;

    /**
     * How long each LOB is, straight out of the row.
     *
     * <p>The server puts the length next to the locator, so {@code length()}
     * on a LOB costs nothing. Asking the server for it - which is what the
     * obvious implementation does - would buy a round trip that the value has
     * already paid for.
     */
    private final long[] lobLengths;

    /** The server did not say how long the LOB is. */
    public static final long UNKNOWN_LENGTH = -1;

    /** A length of this means the value arrives in pieces. */
    private static final int CHUNKED = 0xfe;

    private int end;

    public TtcRow(WireBuffer in, List<OracleColumn> columns) {
        this.in = in;
        this.columns = columns;
        this.cells = new int[columns.size() * 2]; // seclume-allow: offsets into the buffer, not content
        this.lobLengths = new long[columns.size()]; // seclume-allow: lengths of the protocol, not content
        this.carried = new boolean[columns.size()]; // seclume-allow: which buffer a cell is in, not content
    }

    /**
     * Points the row at the next answer, keeping what it carried over.
     *
     * <p>This is what makes a row survive a fetch: the same object reads the
     * next block, and the values {@link #carryOver} saved are still there for
     * a first row that refers back to them.
     */
    public void rebind(WireBuffer next) {
        this.in = next;
    }

    /**
     * Saves the values of the row as it stands, before the buffer under it is
     * reused.
     *
     * <p>Only called at the end of an answer, so it copies one row per fetch
     * and not one per row. Cells that already sit in the carry buffer are
     * copied along - the new one is built from scratch and the two swap, so
     * the source is never the destination.
     */
    public void carryOver() {
        if (columns.isEmpty()) {
            return;
        }
        if (spare == null) {
            spare = new WireBuffer(256);
        }
        spare.clear();
        for (int i = 0; i < columns.size(); i++) {
            int length = cells[i * 2 + 1];
            if (length <= 0) {
                cells[i * 2] = 0;
                carried[i] = true;
                continue;
            }
            spare.ensureCapacity(spare.position() + length);
            int at = spare.position();
            spare.putBytes(bufferOf(i).segment(), cells[i * 2], length);
            cells[i * 2] = at;
            carried[i] = true;
        }
        WireBuffer swap = carry;
        carry = spare;
        spare = swap;
    }

    /** The buffer a cell's bytes are in - the message, or what was carried over. */
    private WireBuffer bufferOf(int index) {
        return carried[index] ? carry : in;
    }

    /** Lets go of the carry buffer; the row is finished with. */
    public void release() {
        if (carry != null) {
            carry.close();
            carry = null;
        }
        if (spare != null) {
            spare.close();
            spare = null;
        }
    }

    /**
     * Points the window at the row that starts at {@code at}.
     *
     * @param sent the bit vector of the row header, or {@code null}. One bit
     *             per column, counted from the bottom of the byte - and the
     *             sense is the opposite of what the name "bit vector" suggests:
     *             a <b>set</b> bit means the value is in this row, a
     *             <b>clear</b> one means it is the same as in the row before
     *             and was not sent again. Getting that round the wrong way
     *             produces plausible wrong data rather than an error.
     * @return the position just after the row
     */
    public int read(int at, byte[] sent) {
        int p = at;
        for (int i = 0; i < columns.size(); i++) {
            OracleColumn column = columns.get(i);
            boolean unbounded = column.type() == OracleColumn.TYPE_LONG
                    || column.type() == OracleColumn.TYPE_LONG_RAW;
            if (column.bufferSize() == 0 && !unbounded) {
                // A buffer size of zero means the column carries no bytes at
                // all - not even a zero length. That is how the server
                // describes an untyped null in the select list, and a reader
                // that expects one value per column reads every value after it
                // one place too early. Metadata queries are full of
                // "null as SOMETHING", so this is not an exotic case.
                //
                // A LONG is the exception: it has no size limit, so the server
                // describes it with a buffer size of zero as well - and it
                // does send bytes.
                cells[i * 2] = p;
                cells[i * 2 + 1] = -1;
                carried[i] = false;
                continue;
            }
            if (isDuplicate(sent, i)) {
                continue;                              // keeps the previous value
            }
            carried[i] = false;                        // this one is in the message
            if (column.inline()) {
                p = readInline(p, i);
                continue;
            }
            if (OracleColumn.isLob(column.type())
                    || column.type() == OracleColumn.TYPE_BFILE) {
                p = readLocator(p, i);
                continue;
            }
            if (column.type() == OracleColumn.TYPE_UROWID) {
                // A length of the protocol's variable width in front of the
                // usual length-prefixed bytes; zero is NULL. Read as the bytes
                // alone, the length was taken for the value and every column
                // after it was read from the wrong place.
                long total = rawNumber(p);
                p = skipRawNumber(p);
                if (total == 0) {
                    cells[i * 2] = p;
                    cells[i * 2 + 1] = -1;
                    continue;
                }
            }
            if (column.type() == OracleColumn.TYPE_ROWID) {
                p = readRowid(p, i);
                continue;
            }
            if (column.type() == OracleColumn.TYPE_OBJECT) {
                p = readObject(p, i);
                continue;
            }
            int length = in.getByte(p) & 0xff;
            p++;
            if (length == CHUNKED) {
                p = readChunked(p, i);
            } else if (length == 0) {
                cells[i * 2] = p;
                cells[i * 2 + 1] = -1;
            } else {
                cells[i * 2] = p;
                cells[i * 2 + 1] = length;
                p += length;
            }
            // A LONG carries two fields behind its value: whether it was NULL
            // - as a signed number, so the length byte has its top bit set -
            // and a return code, which is 1405 for a null one. They look like
            // the next column when they are not read, and the row is then
            // shifted from there on.
            if (unbounded) {
                p = skipSigned(p);                     // null indicator
                p = skipSigned(p);                     // return code, 1405 if null
            }
        }
        end = p;
        return p;
    }

    /**
     * A {@code CLOB} or {@code BLOB} column: not the value, but the 112-byte
     * locator that names it on the server.
     *
     * <p>The shape is <b>not the same for every client</b>, which is the trap
     * here:
     *
     * <pre>
     *   this driver        number 114 | 114 | 0 | 112 | locator
     *   python-oracledb    number 114 | number length | number chunk size
     *                                 | 114 | 0 | 112 | locator
     * </pre>
     *
     * <p>The reference client gets the length and the chunk size for free;
     * we do not, because we do not negotiate whatever asks for them. Reading
     * them anyway shifts the rest of the row - and the server does not
     * complain about that. It answers the next call with
     * {@code ORA-01002, fetch out of sequence}, several round trips later,
     * which is as far from the cause as a message can get.
     *
     * <p>So the two fields are taken when they are there and skipped when they
     * are not, decided on the byte that follows: the leading number says how
     * long the descriptor is, and the same value as a single byte announces
     * it - 114 for a persistent locator of 112 bytes, 40 for the temporary one
     * of 38 that a {@code JSON} column carries. A length prefix is at most
     * eight, so it is never mistaken for either.
     *
     * <p>A NULL LOB has none of it: the leading number is zero and the column
     * is over.
     */
    private int readLocator(int at, int column) {
        int p = at;
        long descriptor = rawNumber(p);
        p = skipRawNumber(p);
        if (descriptor == 0) {
            cells[column * 2] = p;
            cells[column * 2 + 1] = -1;
            lobLengths[column] = UNKNOWN_LENGTH;
            return p;
        }
        lobLengths[column] = UNKNOWN_LENGTH;
        for (int guard = 0; guard < 4 && (in.getByte(p) & 0xff) != descriptor; guard++) {
            if (lobLengths[column] == UNKNOWN_LENGTH) {
                lobLengths[column] = rawNumber(p);      // the length, when it comes at all
            }
            p = skipRawNumber(p);
        }
        p++;                                           // the descriptor size, as a byte
        p++;                                           // a zero byte
        int locatorLength = in.getByte(p) & 0xff;
        p++;
        cells[column * 2] = p;
        cells[column * 2 + 1] = locatorLength;
        return p + locatorLength;
    }

    /**
     * A {@code ROWID}: a leading byte that is zero for NULL, then five numbers
     * of the protocol's variable width - object, file, a byte nothing uses,
     * block, slot. The cell is the five, still encoded; {@link OracleRowid}
     * turns them into the text Oracle prints.
     *
     * <p>Read as a length-prefixed value before, the leading byte was taken
     * for a length - fourteen, where the five take eleven - and three bytes of
     * the next column went with it: every column after a rowid was read from
     * the wrong place.
     */
    private int readRowid(int at, int column) {
        int p = at;
        int present = in.getByte(p) & 0xff;
        p++;
        if (present == 0) {
            cells[column * 2] = p;
            cells[column * 2 + 1] = -1;
            return p;
        }
        int start = p;
        for (int field = 0; field < 5; field++) {
            p = skipRawNumber(p);
        }
        cells[column * 2] = start;
        cells[column * 2 + 1] = p - start;
        return p;
    }

    /**
     * An object column - {@code XMLType} among them: the type's id, the
     * object's id and a snapshot, each a number giving a length and then that
     * many bytes when it is not zero; a version; the image's length; flags;
     * and the image itself, length-prefixed like any value and chunked when
     * long. The cell is the image.
     *
     * <p>Read as a plain value before, the first length was taken for the
     * value's length and the rest of the row from the wrong place - the result
     * looked empty.
     */
    private int readObject(int at, int column) {
        int p = at;
        for (int part = 0; part < 3; part++) {             // type id, object id, snapshot
            long length = rawNumber(p);
            p = skipRawNumber(p);
            if (length > 0) {
                p = skipValue(p);
            }
        }
        p = skipRawNumber(p);                               // version
        long imageLength = rawNumber(p);
        p = skipRawNumber(p);
        p = skipRawNumber(p);                               // flags
        if (imageLength == 0) {
            cells[column * 2] = p;
            cells[column * 2 + 1] = -1;
            return p;
        }
        int length = in.getByte(p) & 0xff;
        p++;
        if (length == CHUNKED) {
            return readChunked(p, column);
        }
        cells[column * 2] = p;
        cells[column * 2 + 1] = length == 0 ? -1 : length;
        return p + length;
    }

    /** Walks over a length-prefixed value, chunked or not. */
    private int skipValue(int at) {
        int length = in.getByte(at) & 0xff;
        int p = at + 1;
        if (length != CHUNKED) {
            return p + length;
        }
        while (true) {
            int lengthOfLength = in.getByte(p) & 0xff;
            p++;
            int chunk = 0;
            for (int i = 0; i < lengthOfLength; i++) {
                chunk = (chunk << 8) | (in.getByte(p + i) & 0xff);
            }
            p += lengthOfLength;
            if (chunk == 0) {
                return p;
            }
            p += chunk;
        }
    }

    /** Oracle's length-prefixed number: one byte of count, then the value. */
    private long rawNumber(int at) {
        int length = in.getByte(at) & 0xff;
        long value = 0;
        for (int i = 0; i < length; i++) {
            value = (value << 8) | (in.getByte(at + 1 + i) & 0xff);
        }
        return value;
    }

    private int skipRawNumber(int at) {
        return at + 1 + (in.getByte(at) & 0xff);
    }

    /**
     * How long the LOB in that column is, or {@link #UNKNOWN_LENGTH}.
     *
     * <p>Free when the server sends it. It does not send it to this driver
     * today - see {@link #readLocator} - so callers have to cope with not
     * knowing, and the value decides its own size when it arrives.
     */
    public long lobLength(int index) {
        return lobLengths[index];
    }

    /**
     * A JSON or VECTOR value the define asked for in the row: its length, the
     * LOB's size and chunk size, the value itself - one piece or chunks - and
     * the locator, which nobody needs any more. A length of zero is NULL.
     */
    private int readInline(int at, int column) {
        int p = at;
        long length = rawNumber(p);
        p = skipRawNumber(p);
        if (length == 0) {
            cells[column * 2] = p;
            cells[column * 2 + 1] = -1;
            return p;
        }
        p = skipRawNumber(p);                          // size of the LOB
        p = skipRawNumber(p);                          // chunk size
        int first = in.getByte(p) & 0xff;
        p++;
        if (first == CHUNKED) {
            p = readChunked(p, column);
        } else {
            cells[column * 2] = p;
            cells[column * 2 + 1] = first;
            p += first;
        }
        int locator = in.getByte(p) & 0xff;            // the locator, walked over
        p++;
        if (locator == CHUNKED) {
            int keep = cells[column * 2];
            int keepLength = cells[column * 2 + 1];
            p = skipChunks(p);
            cells[column * 2] = keep;
            cells[column * 2 + 1] = keepLength;
            return p;
        }
        return p + locator;
    }

    /** Walks over chunks without moving them. */
    private int skipChunks(int at) {
        int read = at;
        while (true) {
            int lengthOfLength = in.getByte(read) & 0xff;
            read++;
            int chunk = chunkLength(read, lengthOfLength);
            read += lengthOfLength + chunk;
            if (chunk == 0) {
                return read;
            }
        }
    }

    /**
     * A value that arrives in pieces.
     *
     * <p>Every piece has its own length in front of it, so the bytes are not
     * contiguous. They are made contiguous here - moved together inside the
     * receive buffer, over the lengths that separated them - because a value
     * has to be one window for whoever reads it. Nothing behind the value
     * moves; a gap is left where the lengths were.
     */
    private int readChunked(int at, int column) {
        int write = at;
        int read = at;
        int total = 0;
        while (true) {
            int lengthOfLength = in.getByte(read) & 0xff;
            read++;
            int chunk = chunkLength(read, lengthOfLength);
            read += lengthOfLength;
            if (chunk == 0) {
                break;
            }
            java.lang.foreign.MemorySegment.copy(in.segment(), read,
                    in.segment(), write + total, chunk);
            total += chunk;
            read += chunk;
        }
        cells[column * 2] = write;
        cells[column * 2 + 1] = total == 0 ? -1 : total;
        return read;
    }

    /**
     * One chunk's length, as the wire gives it - at most four bytes of it, and
     * no more than what is left of the received data. A length the server
     * cannot have meant (a negative one after four bytes, found by Jazzer on
     * 25.09.2026, reached a copy as "size is negative") is refused as a
     * malformed answer instead.
     */
    private int chunkLength(int at, int lengthOfLength) {
        if (lengthOfLength > 4) {
            throw space.seclume.internal.WireBuffer.malformed("a chunk length of "
                    + lengthOfLength + " bytes");
        }
        long chunk = 0;
        for (int i = 0; i < lengthOfLength; i++) {
            chunk = (chunk << 8) | (in.getByte(at + i) & 0xff);
        }
        if (chunk > in.segment().byteSize() - at - lengthOfLength) {
            throw space.seclume.internal.WireBuffer.malformed("a chunk of " + chunk
                    + " bytes in an answer that has fewer left");
        }
        return (int) chunk;
    }

    /**
     * Walks over a signed number: the top bit of the length byte says the
     * value is negative, it is not part of the length.
     */
    private int skipSigned(int at) {
        return at + 1 + (in.getByte(at) & 0x7f);
    }

    /** No vector at all means every value is in the row. */
    private static boolean isDuplicate(byte[] sent, int column) {
        if (sent == null) {
            return false;
        }
        int index = column / 8;
        return index < sent.length && (sent[index] & (1 << (column % 8))) == 0;
    }

    public int end() {
        return end;
    }

    public int columnCount() {
        return columns.size();
    }

    public OracleColumn column(int index) {
        return columns.get(index);
    }

    public boolean isNull(int index) {
        return cells[index * 2 + 1] < 0;
    }

    /**
     * Whether every cell of this row lies in the one message buffer.
     *
     * <p>Usually yes, and then a reader can take the whole row over in a
     * single copy. It is not always: a row that spans two messages has its
     * earlier cells moved into a buffer of their own (see the carry above), and
     * then the cells are in two places and have to be copied one at a time.
     */
    public boolean inOneBuffer() {
        for (int i = 0; i < columns.size(); i++) {
            if (carried[i]) {
                return false;
            }
        }
        return true;
    }

    /** The message buffer - only meaningful while {@link #inOneBuffer()}. */
    public java.lang.foreign.MemorySegment source() {
        return in.segment();
    }

    /** Where a cell sits in the buffer - for whoever takes the row over. */
    public int cellAt(int index) {
        return cells[index * 2];
    }

    /** How long a cell is; negative for SQL NULL. */
    public int cellLength(int index) {
        return cells[index * 2 + 1];
    }

    /**
     * Copies a cell into another buffer, at its current position.
     *
     * <p>This is how a {@code ResultSet} takes a row over: the row itself is
     * only a window and is gone with the next message, so whoever wants to
     * keep it moves the bytes - native memory to native memory, without a Java
     * object in between.
     */
    public void copyTo(int index, WireBuffer target) {
        int length = cells[index * 2 + 1];
        if (length > 0) {
            target.putBytes(bufferOf(index).segment(), cells[index * 2], length);
        }
    }

    /** The description this row belongs to. */
    public List<OracleColumn> columns() {
        return columns;
    }

    /** The value as text; {@code null} for SQL NULL. */
    public String text(int index) {
        if (isNull(index)) {
            return null;
        }
        int at = cells[index * 2];
        int length = cells[index * 2 + 1];
        WireBuffer from = bufferOf(index);
        OracleColumn column = columns.get(index);
        if (column.type() == OracleColumn.TYPE_NUMBER) {
            return OracleNumber.toText(from.segment(), at, length);
        }
        char[] letters = new char[length]; // seclume-allow: user payload requested as text, not a secret
        for (int i = 0; i < length; i++) {
            letters[i] = (char) (from.getByte(at + i) & 0xff);
        }
        return new String(letters); // seclume-allow: user payload, not a secret
    }

    /** The value as an integer; 0 for SQL NULL, as JDBC prescribes. */
    public long number(int index) {
        if (isNull(index)) {
            return 0;
        }
        return OracleNumber.toLong(bufferOf(index).segment(),
                cells[index * 2], cells[index * 2 + 1]);
    }
}
