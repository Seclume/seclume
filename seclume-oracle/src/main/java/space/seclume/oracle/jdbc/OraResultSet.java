package space.seclume.oracle.jdbc;

import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;

import space.seclume.internal.WireBuffer;
import space.seclume.internal.jdbc.ReadOnlyResultSet;
import space.seclume.oracle.net.TtcLob;
import space.seclume.oracle.net.OracleColumn;
import space.seclume.oracle.net.OracleFloat;
import space.seclume.oracle.net.OracleDate;
import space.seclume.oracle.net.OracleNumber;

/**
 * A {@code ResultSet} on top of an {@link OraResultBlock}.
 *
 * <p>Everything formal - the cursor, {@code wasNull}, the many methods that do
 * not apply to a forward-only result - lives in {@link ReadOnlyResultSet}. Only
 * the values are here, and with Oracle that means mostly one thing: numbers.
 *
 * <p>Oracle has a single numeric type, and it arrives in a format of its own -
 * base 100, with an exponent byte. {@link OracleNumber} turns it into a
 * {@code long} without a {@code String} on the way, which is the whole point:
 * {@code getLong} allocates nothing.
 */
public final class OraResultSet extends ReadOnlyResultSet {

    private final OraResultBlock block;

    /** The statement that can bring the next block, or {@code null}. */
    private final OraStatement owner;

    @Override
    protected java.sql.Clob clobAt(int column) throws SQLException {
        return OraLob.clob(lobSession(), block.data(), block.offset(column));
    }

    @Override
    protected java.sql.Blob blobAt(int column) throws SQLException {
        return OraLob.blob(lobSession(), block.data(), block.offset(column));
    }

    @Override
    protected java.io.Reader readerAt(int column) throws SQLException {
        if (block.column(column).type() != OracleColumn.TYPE_CLOB) {
            return new java.io.StringReader(stringAt(column));
        }
        return clobAt(column).getCharacterStream();
    }

    @Override
    protected java.io.InputStream binaryStreamAt(int column) throws SQLException {
        if (!OracleColumn.isLob(block.column(column).type())) {
            return new java.io.ByteArrayInputStream(bytesAt(column));
        }
        return blobAt(column).getBinaryStream();
    }

    private space.seclume.oracle.OracleSession lobSession() throws SQLException {
        if (owner == null) {
            throw new SQLException("this result has no statement to read the LOB with", "HY000");
        }
        return owner.connection.session();
    }

    /**
     * The contents of a CLOB, as text.
     *
     * <p>Oracle sends character LOBs in UTF-16, big-endian - measured, not
     * assumed. The length is not asked for: it came with the row, so the
     * whole value costs exactly one round trip however large it is.
     */
    private String clobText(int column) throws SQLException {
        try (WireBuffer value = fetchLob(column)) {
            int bytes = value.position();
            StringBuilder text = new StringBuilder(bytes / 2); // seclume-allow: user payload requested as text, not a secret
            for (int i = 0; i + 1 < bytes; i += 2) {
                text.append((char) (((value.getByte(i) & 0xff) << 8)
                        | (value.getByte(i + 1) & 0xff)));
            }
            return text.toString();
        }
    }

    /** The contents of a LOB as bytes - for a BLOB, the value itself. */
    private byte[] lobBytes(int column) throws SQLException {
        try (WireBuffer value = fetchLob(column)) {
            int bytes = value.position();
            byte[] out = new byte[bytes]; // seclume-allow: user payload requested as bytes, not a secret
            for (int i = 0; i < bytes; i++) {
                out[i] = value.getByte(i);
            }
            return out;
        }
    }

    /**
     * The one round trip a LOB costs.
     *
     * <p>The row carried a locator, not a value; this turns it into the value.
     * An empty LOB comes back as no bytes at all, which is the same answer the
     * server gives for a read past the end - and rightly so: an empty LOB and
     * the end of a LOB are the same thing seen from the offset.
     */
    private WireBuffer fetchLob(int column) throws SQLException {
        long length = block.lobLength(column);
        if (length == 0) {
            return new WireBuffer(16);                 // empty, and the server need not say so
        }
        WireBuffer value = new WireBuffer(
                length > 0 ? (int) Math.min(length * 2, 1 << 16) : 16 * 1024);
        if (owner == null) {
            value.close();
            throw new SQLException("this result has no statement to read the LOB with", "HY000");
        }
        // The locator of a column is a persistent one, so 112 bytes. A
        // temporary LOB is 38 - which is why the length is a parameter and not
        // a constant inside the call.
        owner.connection.session().readLob(block.data(), block.offset(column),
                TtcLob.LOCATOR_LENGTH, 1, TtcLob.ALL, value);
        return value;
    }

    /**
     * Asks the statement for the next block.
     *
     * <p>Only does anything when a fetch size is set and the cursor still has
     * rows; otherwise the whole result is here already and this says so.
     */
    @Override
    protected boolean fetchMore() throws SQLException {
        return owner != null && owner.fetchNextBlock();
    }

    OraResultSet(OraResultBlock block, Statement statement) {
        super(statement);
        this.block = block;
        this.owner = statement instanceof OraStatement ora ? ora : null;
    }

    @Override
    protected int rowCount() {
        return block.rowCount();
    }

    @Override
    protected int columnCount() {
        return block.columnCount();
    }

    @Override
    protected void moveTo(int row) {
        block.select(row);
    }

    @Override
    protected boolean isNullAt(int column) {
        return block.isNull(column);
    }

    @Override
    protected String stringAt(int column) throws SQLException {
        OracleColumn description = block.column(column);
        int at = block.offset(column);
        int length = block.length(column);
        if (description.type() == OracleColumn.TYPE_CLOB) {
            return clobText(column);
        }
        if (description.type() == OracleColumn.TYPE_BLOB) {
            throw new SQLException("a BLOB is not text", "22005");
        }
        if (description.type() == OracleColumn.TYPE_NUMBER) {
            return OracleNumber.toText(block.data().segment(), at, length);
        }
        if (OracleFloat.isBinaryFloat(description.type())) {
            double value = OracleFloat.toDouble(block.data().segment(), at, length);
            return description.type() == OracleColumn.TYPE_BINARY_FLOAT
                    ? Float.toString((float) value) : Double.toString(value);
        }
        if (description.type() == OracleColumn.TYPE_BOOLEAN) {
            return length > 0 && block.data().getByte(at) != 0 ? "1" : "0";
        }
        if (OracleDate.isDate(description.type())) {
            return OracleDate.toText(block.data().segment(), at, length);
        }
        return utf8(at, length);
    }

    /**
     * The bytes of a text column, decoded as UTF-8.
     *
     * <p>The driver logs in with AL32UTF8 and the server answers in it, so a
     * character outside ASCII arrives as two bytes or more. Reading them one
     * byte per character - which is what this did - turns "Grüße" into
     * "GrÃ¼ÃŸe", and only for the values that have such a character in them.
     *
     * <p>Written out rather than handed to {@code new String(bytes, UTF_8)}:
     * that would need the bytes in a heap array first, which is the one
     * thing this project does not do. A malformed sequence becomes the
     * replacement character rather than throwing - a result set is no place
     * to fail over one bad byte.
     */
    private String utf8(int at, int length) {
        StringBuilder text = new StringBuilder(length); // seclume-allow: user payload requested as text, not a secret
        int i = 0;
        while (i < length) {
            int first = block.data().getByte(at + i) & 0xff;
            i++;
            if (first < 0x80) {
                text.append((char) first);
                continue;
            }
            int following = first >= 0xf0 ? 3 : first >= 0xe0 ? 2 : first >= 0xc0 ? 1 : -1;
            if (following < 0 || i + following > length) {
                text.append('�');
                continue;
            }
            int point = first & (0x3f >> following);
            for (int k = 0; k < following; k++) {
                int next = block.data().getByte(at + i + k) & 0xff;
                if ((next & 0xc0) != 0x80) {
                    point = -1;
                    break;
                }
                point = (point << 6) | (next & 0x3f);
            }
            if (point < 0) {
                text.append('�');
                continue;
            }
            i += following;
            text.appendCodePoint(point);
        }
        return text.toString();
    }

    @Override
    protected long longAt(int column) throws SQLException {
        OracleColumn description = block.column(column);
        if (description.type() == OracleColumn.TYPE_NUMBER) {
            return OracleNumber.toLong(block.data().segment(), block.offset(column),
                    block.length(column));
        }
        if (OracleFloat.isBinaryFloat(description.type())) {
            return (long) OracleFloat.toDouble(block.data().segment(), block.offset(column),
                    block.length(column));
        }
        if (description.type() == OracleColumn.TYPE_BOOLEAN) {
            return block.length(column) > 0
                    && block.data().getByte(block.offset(column)) != 0 ? 1 : 0;
        }
        try {
            return Long.parseLong(stringAt(column).trim());
        } catch (NumberFormatException e) {
            throw new SQLException("column " + (column + 1) + " is not an integer: "
                    + stringAt(column), "22018", e);
        }
    }

    @Override
    protected double doubleAt(int column) throws SQLException {
        OracleColumn description = block.column(column);
        if (description.type() == OracleColumn.TYPE_NUMBER) {
            return OracleNumber.toDouble(block.data().segment(), block.offset(column),
                    block.length(column));
        }
        if (OracleFloat.isBinaryFloat(description.type())) {
            return OracleFloat.toDouble(block.data().segment(), block.offset(column),
                    block.length(column));
        }
        try {
            return Double.parseDouble(stringAt(column));
        } catch (NumberFormatException e) {
            throw new SQLException("column " + (column + 1) + " is not a number: "
                    + stringAt(column), "22018", e);
        }
    }

    @Override
    protected byte[] bytesAt(int column) throws SQLException {
        if (OracleColumn.isLob(block.column(column).type())) {
            return lobBytes(column);
        }
        int at = block.offset(column);
        int length = block.length(column);
        byte[] out = new byte[length]; // seclume-allow: user payload requested as bytes, not a secret
        for (int i = 0; i < length; i++) {
            out[i] = block.data().getByte(at + i);
        }
        return out;
    }

    /**
     * Oracle has no boolean type before 23c, and this driver does not use the
     * new one yet: a truth value is a number or a letter, and both are
     * accepted the way every other Oracle client accepts them.
     */
    @Override
    protected boolean booleanAt(int column) throws SQLException {
        OracleColumn description = block.column(column);
        if (description.type() == OracleColumn.TYPE_NUMBER) {
            return longAt(column) != 0;
        }
        String text = stringAt(column).trim();
        if (text.isEmpty()) {
            return false;
        }
        char first = text.charAt(0);
        return first == 'Y' || first == 'y' || first == 'T' || first == 't' || first == '1';
    }

    @Override
    protected Object objectAt(int column) throws SQLException {
        OracleColumn description = block.column(column);
        if (description.type() == OracleColumn.TYPE_NUMBER) {
            String text = stringAt(column);
            // A scale of -127 means none was declared, so there is nothing to
            // round to and a BigDecimal is the only honest answer.
            return text.indexOf('.') < 0 && description.scale() == 0
                    ? (Object) Long.valueOf(text)
                    : new java.math.BigDecimal(text);
        }
        if (OracleDate.isDate(description.type())) {
            return java.sql.Timestamp.valueOf(stringAt(column));
        }
        return stringAt(column);
    }

    @Override
    protected int columnIndexOf(String label) {
        for (int i = 0; i < block.columnCount(); i++) {
            if (block.column(i).name().equalsIgnoreCase(label)) {
                return i;
            }
        }
        return -1;
    }

    @Override
    protected ResultSetMetaData metaData() {
        return new OraResultSetMetaData(block.columns());
    }

    /**
     * Nothing to free here: the block belongs to the statement and the next
     * execution reuses it. Closing it would pull the memory out from under the
     * statement.
     */
    @Override
    protected void release() {
    }
}
