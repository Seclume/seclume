package space.seclume.postgresql.jdbc;

import java.nio.charset.StandardCharsets;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;

import space.seclume.internal.jdbc.OpaqueRowId;
import space.seclume.internal.jdbc.ReadOnlyResultSet;
import space.seclume.internal.jdbc.XmlValue;
import space.seclume.postgresql.PgSession;

/**
 * A {@code ResultSet} on top of a {@link ResultBlock}.
 *
 * <p>Everything formal - the cursor, {@code wasNull} and the many methods that
 * do not exist - lives in {@link ReadOnlyResultSet}. Only the values are here.
 *
 * <p>PostgreSQL sends them in the text format, and conversion only happens on
 * access. Whoever calls {@code getLong} gets the number without the detour
 * through a {@code String}.
 */
public final class PgResultSet extends ReadOnlyResultSet implements space.seclume.Sensitive {

    private final ResultBlock block;
    /**
     * A scratch array for turning bytes into a {@code String}.
     *
     * <p>{@code new String(byte[], charset)} needs an array, and allocating a
     * fresh one per value doubles the objects a text column costs: one for the
     * bytes, one for the string. The array is reused - the string constructor
     * copies out of it anyway.
     *
     * <p>Payload, never a secret: what a database sends back is what the
     * caller asked for. The rule about heap arrays is about passwords, and one
     * has no business being in a result set.
     */
    private byte[] scratch = new byte[64]; // seclume-allow: user payload on its way to a String, not a secret
    /** The same, for the values BigDecimal reads out of a char[]. */
    private char[] characters = new char[64]; // seclume-allow: user payload on its way to a number, not a secret


    private int row;
    /** The statement that can bring the next block, or {@code null}. */
    private final PgStatement owner;

    PgResultSet(ResultBlock block, Statement statement) {
        super(statement);
        this.block = block;
        this.owner = statement instanceof PgStatement pg ? pg : null;
    }

    /**
     * Asks the statement for the next block.
     *
     * <p>Only does anything when a fetch size is set and the portal is still
     * open; otherwise the whole result is here already and this says so.
     */
    @Override
    protected boolean fetchMore() throws SQLException {
        return owner != null && owner.fetchNextBlock();
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
        this.row = row;
    }

    @Override
    protected boolean isNullAt(int column) {
        return block.isNull(row, column);
    }

    /**
     * The text of a column - and for the two float types, Java's text rather
     * than the server's.
     *
     * <p>This is the only driver of the four that has a choice here: PostgreSQL
     * sends a {@code real} as characters, the other three send four or eight
     * bytes and there is no server rendering to pass on. So "pass the server's
     * text through" was never a rule the project could keep - it was an
     * accident of one protocol's text format, and it made the same value read
     * back differently depending on which database it came from. Measured
     * across all four: {@code 1e+20} here and {@code 1.0E20} everywhere else,
     * {@code 1e-07} against {@code 1.0E-7}, {@code -0} against {@code -0.0}.
     *
     * <p>Rendering through {@link Float#toString} instead gives one answer
     * everywhere, and it is the shortest text that reads back as the same
     * float. It also fixes a disagreement with pgjdbc rather than causing one:
     * a {@code real} holding 1234567 came out of the server as
     * {@code 1.234567e+06}, where pgjdbc answers {@code 1234567.0} - so this
     * driver did not have the vendor's rendering to begin with.
     *
     * <p>{@code numeric} is untouched. It is an exact decimal, the server's
     * text is its value, and turning it into a {@code double} to print it
     * would be the one conversion that loses something.
     */
    @Override
    protected String stringAt(int column) {
        int oid = block.fields().get(column).typeOid();
        if (binaryAt(column)) {
            // The bytes are a number, not text. Rendering them here keeps
            // getString the same answer in both formats - which is the one
            // promise a format switch must not break, and the reason this is
            // not left to the caller.
            try {
                return switch (oid) {
                    case PgOids.BOOL -> booleanAt(column) ? "t" : "f";
                    case PgOids.FLOAT4 -> Float.toString((float) doubleAt(column));
                    case PgOids.FLOAT8 -> Double.toString(doubleAt(column));
                    default -> Long.toString(integerAt(column));
                };
            } catch (SQLException unreadable) {
                throw new IllegalStateException(unreadable);
            }
        }
        if (oid == PgOids.FLOAT4) {
            return Float.toString((float) doubleAt(column));
        }
        if (oid == PgOids.FLOAT8) {
            return Double.toString(doubleAt(column));
        }
        return rawText(column);
    }

    // ---- the native window, for space.seclume.Sensitive ------------------

    @Override
    protected java.lang.foreign.MemorySegment rawSegmentAt(int column) {
        return block.data().segment();
    }

    @Override
    protected long rawOffsetAt(int column) {
        return block.offset(row, column);
    }

    @Override
    protected int rawLengthAt(int column) {
        return block.length(row, column);
    }

    @Override
    public int readInto(int columnIndex, java.lang.foreign.MemorySegment target)
            throws java.sql.SQLException {
        return copyRaw(columnIndex, target);
    }

    @Override
    public int length(int columnIndex) throws java.sql.SQLException {
        return rawLength(columnIndex);
    }

    /** The bytes the server sent, as they were sent. */
    private String rawText(int column) {
        int offset = block.offset(row, column);
        int length = block.length(row, column);
        if (scratch.length < length) {
            scratch = new byte[Math.max(length, scratch.length * 2)]; // seclume-allow: user payload on its way to a String, not a secret
        }
        java.lang.foreign.MemorySegment.copy(block.data().segment(),
                java.lang.foreign.ValueLayout.JAVA_BYTE, offset, scratch, 0, length);
        return new String(scratch, 0, length, StandardCharsets.UTF_8); // seclume-allow: user payload requested as text, not a secret
    }

    /**
     * Whether this column arrived as bytes rather than as digits.
     *
     * <p>Read from the server's own {@code RowDescription} and not from what
     * was asked for. The two agree, and asking the answer rather than the
     * question is the difference between a decoder that is right and one that
     * is right as long as nothing else changes - a describe after a
     * re-preparation, a server that declines the format, a portal somebody
     * else bound.
     */
    private boolean binaryAt(int column) {
        return block.fields().get(column).format() == 1;
    }

    /** A signed big-endian integer of the width the server sent. */
    private long integerAt(int column) throws SQLException {
        int offset = block.offset(row, column);
        int length = block.length(row, column);
        long value = 0;
        for (int i = 0; i < length; i++) {
            value = (value << 8) | (block.byteAt(offset + i) & 0xffL);
        }
        if (length > 0 && length < 8 && (block.byteAt(offset) & 0x80) != 0) {
            // Sign-extend: a smallint of -1 arrives as two bytes, not eight.
            value |= -1L << (length * 8);
        }
        if (length == 0 || length > 8) {
            throw new SQLException("column " + (column + 1) + " arrived as " + length
                    + " bytes, which is not an integer this driver reads", "22018");
        }
        return value;
    }

    /** Without a {@code String} and without {@code parseLong} - straight from the bytes. */
    @Override
    protected long longAt(int column) throws SQLException {
        if (binaryAt(column)) {
            return integerAt(column);
        }
        try {
            return block.decimalAt(block.offset(row, column), block.length(row, column));
        } catch (NumberFormatException e) {
            throw new SQLException("column " + (column + 1) + " is not an integer: "
                    + stringAt(column), "22018");
        }
    }

    @Override
    protected double doubleAt(int column) {
        if (block.fields().get(column).typeOid() == PgOids.MONEY) {
            return money(stringAt(column));
        }
        if (binaryAt(column)) {
            int length = block.length(row, column);
            try {
                long bits = integerAt(column);
                // float4 and float8 are IEEE 754 in network order, which is
                // exactly what the bits above are - only the width differs.
                return length == 4
                        ? Float.intBitsToFloat((int) bits)
                        : Double.longBitsToDouble(bits);
            } catch (SQLException impossible) {
                // integerAt only refuses a width no float has.
                throw new IllegalStateException("a float of " + length + " bytes", impossible);
            }
        }
        return space.seclume.internal.jdbc.TextNumber.decimalDouble(block.data(),
                block.offset(row, column), block.length(row, column));
    }

    @Override
    protected java.math.BigDecimal decimalAt(int column) {
        int length = block.length(row, column);
        if (characters.length < length) {
            characters = new char[Math.max(length, characters.length * 2)]; // seclume-allow: user payload on its way to a number, not a secret
        }
        return space.seclume.internal.jdbc.TextNumber.bigDecimal(block.data(),
                block.offset(row, column), length, characters);
    }

    @Override
    protected boolean booleanAt(int column) {
        byte first = block.byteAt(block.offset(row, column));
        if (binaryAt(column)) {
            // One byte, and it is the value rather than a letter for it.
            return first != 0;
        }
        return first == 't' || first == 'T' || first == '1' || first == 'y' || first == 'Y';
    }

    /** {@code bytea} arrives in the text format as {@code \x...}. */
    @Override
    protected byte[] bytesAt(int column) {
        int offset = block.offset(row, column);
        int length = block.length(row, column);
        if (length >= 2 && block.byteAt(offset) == '\\' && block.byteAt(offset + 1) == 'x') {
            byte[] out = new byte[(length - 2) / 2]; // seclume-allow: user payload, not a secret
            for (int i = 0; i < out.length; i++) {
                out[i] = (byte) ((hex(block.byteAt(offset + 2 + i * 2)) << 4)
                        | hex(block.byteAt(offset + 3 + i * 2)));
            }
            return out;
        }
        return stringAt(column).getBytes(StandardCharsets.UTF_8); // seclume-allow: user payload, not a secret
    }

    private static int hex(byte c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        throw new IllegalStateException("not a hex digit in a bytea value: " + (char) c);
    }

    /**
     * An {@code oid} column is a pointer into {@code pg_largeobject}, so the
     * {@code Blob} for one is a real locator and not the row's own bytes.
     *
     * <p>Every other binary column is a {@code bytea} and arrives whole, which
     * is what the inherited behaviour already says.
     */
    @Override
    protected java.sql.Blob blobAt(int column) throws SQLException {
        if (block.fields().get(column).typeOid() == PgOids.OID) {
            return new PgLargeObjectBlob(largeObjects(), longAt(column));
        }
        return super.blobAt(column);
    }

    /** The same pointer, read as a stream - which is the point of one. */
    @Override
    protected java.io.InputStream binaryStreamAt(int column) throws SQLException {
        if (block.fields().get(column).typeOid() == PgOids.OID) {
            return largeObjects().stream(longAt(column));
        }
        return super.binaryStreamAt(column);
    }

    /**
     * An {@code oid} column read as a {@code Clob}: the large object's bytes,
     * as UTF-8 - how {@code setClob} stored them.
     */
    @Override
    protected java.sql.Clob clobAt(int column) throws SQLException {
        if (block.fields().get(column).typeOid() == PgOids.OID) {
            return space.seclume.internal.jdbc.Lobs.text(largeObjectText(column));
        }
        return super.clobAt(column);
    }

    @Override
    protected java.io.Reader readerAt(int column) throws SQLException {
        if (block.fields().get(column).typeOid() == PgOids.OID) {
            return new java.io.StringReader(largeObjectText(column));
        }
        return super.readerAt(column);
    }

    private String largeObjectText(int column) throws SQLException {
        return new String(largeObjects().read(longAt(column)), // seclume-allow: user payload read from a large object, not a secret
                java.nio.charset.StandardCharsets.UTF_8);
    }

    private PgLargeObjects largeObjects() throws SQLException {
        if (owner == null) {
            throw new SQLException("this result set has no connection to read a large object "
                    + "through");
        }
        return new PgLargeObjects(owner.connection);
    }

    /**
     * PostgreSQL is the only one of the four with a real array type, and it
     * writes one as text like everything else - so the decoding is the text
     * form, not a second wire format.
     */
    @Override
    protected java.sql.Array arrayAt(int column) throws SQLException {
        int oid = block.fields().get(column).typeOid();
        if (!PgOids.isArray(oid)) {
            throw new SQLException("column " + (column + 1) + " is "
                    + PgOids.typeName(oid) + ", not an array", "42804");
        }
        return new PgArray(oid, stringAt(column));
    }

    /**
     * An {@code xml} column. Any text column would parse as well, but saying
     * so would be a lie about the column rather than a convenience: a
     * {@code varchar} that happens to hold XML is still a {@code varchar}, and
     * an application that reads it as one keeps working when the day comes
     * that it does not hold XML.
     */
    @Override
    protected java.sql.SQLXML sqlXmlAt(int column) throws SQLException {
        int oid = block.fields().get(column).typeOid();
        if (oid != PgOids.XML) {
            throw new SQLException("column " + (column + 1) + " is "
                    + PgOids.typeName(oid) + ", not xml - read it with getString", "42804");
        }
        return new XmlValue(stringAt(column));
    }

    /**
     * The row address, which in PostgreSQL is the {@code ctid} column and has
     * to be selected by name: {@code select ctid, * from t}.
     *
     * <p>It is worth knowing what such an address is worth here. A
     * {@code ctid} is the physical position of the tuple, and PostgreSQL moves
     * tuples - an {@code update} writes a new version elsewhere, and
     * {@code vacuum full} rewrites the table. So it identifies a row
     * <b>within one transaction</b> and not beyond it, which is exactly what
     * {@code ROWID_VALID_TRANSACTION} in the metadata says.
     */
    @Override
    protected java.sql.RowId rowIdAt(int column) throws SQLException {
        int oid = block.fields().get(column).typeOid();
        if (oid != PgOids.TID) {
            throw new SQLException("column " + (column + 1) + " is "
                    + PgOids.typeName(oid) + ", not a row address - select ctid to get one",
                    "42804");
        }
        return new OpaqueRowId(stringAt(column));
    }

    @Override
    protected Object objectAt(int column) throws SQLException {
        PgSession.Field field = block.fields().get(column);
        int index = column + 1;
        if (PgOids.isArray(field.typeOid())) {
            return getArray(index);
        }
        return switch (field.typeOid()) {
            case PgOids.BOOL -> getBoolean(index);
            // Integer for smallint as well - see PgOids.javaClass, and keep
            // the two in step: an ORM reads the class name and then casts.
            case PgOids.INT2, PgOids.INT4 -> getInt(index);
            case PgOids.INT8, PgOids.OID -> getLong(index);
            // One bit is a truth value, as pgjdbc reads it; a longer string
            // of bits stays text.
            case PgOids.BIT -> {
                String bits = stringAt(column);
                yield bits.length() == 1 ? (Object) Boolean.valueOf(bits.equals("1")) : bits;
            }
            case PgOids.FLOAT4 -> getFloat(index);
            case PgOids.FLOAT8 -> getDouble(index);
            case PgOids.MONEY -> money(stringAt(column));
            case PgOids.NUMERIC -> getBigDecimal(index);
            case PgOids.BYTEA -> getBytes(index);
            case PgOids.DATE -> getDate(index);
            case PgOids.TIME, PgOids.TIMETZ -> getTime(index);
            case PgOids.TIMESTAMP, PgOids.TIMESTAMPTZ -> getTimestamp(index);
            case PgOids.UUID -> UUID.fromString(stringAt(column));
            case PgOids.XML -> getSQLXML(index);
            case PgOids.TID -> getRowId(index);
            default -> stringAt(column);
        };
    }

    /**
     * {@code money} as pgjdbc reads it: the text the server wrote in its
     * lc_monetary, without the currency sign and the thousands separators,
     * negative in parentheses or with a minus. A locale that writes the
     * decimal point as a comma defeats this as it defeats pgjdbc.
     */
    static Double money(String text) {
        boolean negative = text.indexOf('-') >= 0 || text.indexOf('(') >= 0;
        StringBuilder digits = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if ((c >= '0' && c <= '9') || c == '.') {
                digits.append(c);
            }
        }
        double value = Double.parseDouble(digits.toString());
        return negative ? -value : value;
    }

    @Override
    protected int columnIndexOf(String label) {
        for (int i = 0; i < block.columnCount(); i++) {
            if (block.fields().get(i).name().equalsIgnoreCase(label)) {
                return i;
            }
        }
        return -1;
    }

    @Override
    protected ResultSetMetaData metaData() {
        return new PgResultSetMetaData(block.fields());
    }

    /**
     * Nothing to free here: the block belongs to the statement and is reused
     * by the next execution. Closing it here would pull the memory out from
     * under the statement.
     */
    @Override
    protected void release() {
    }
}
