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
public final class PgResultSet extends ReadOnlyResultSet {

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

    @Override
    protected String stringAt(int column) {
        int offset = block.offset(row, column);
        int length = block.length(row, column);
        if (scratch.length < length) {
            scratch = new byte[Math.max(length, scratch.length * 2)]; // seclume-allow: user payload on its way to a String, not a secret
        }
        java.lang.foreign.MemorySegment.copy(block.data().segment(),
                java.lang.foreign.ValueLayout.JAVA_BYTE, offset, scratch, 0, length);
        return new String(scratch, 0, length, StandardCharsets.UTF_8); // seclume-allow: user payload requested as text, not a secret
    }

    /** Without a {@code String} and without {@code parseLong} - straight from the bytes. */
    @Override
    protected long longAt(int column) throws SQLException {
        int offset = block.offset(row, column);
        int length = block.length(row, column);
        boolean negative = false;
        int i = 0;
        if (length > 0 && block.byteAt(offset) == '-') {
            negative = true;
            i = 1;
        }
        long value = 0;
        for (; i < length; i++) {
            int digit = (block.byteAt(offset + i) & 0xff) - '0';
            if (digit < 0 || digit > 9) {
                throw new SQLException("column " + (column + 1) + " is not an integer: "
                        + stringAt(column), "22018");
            }
            value = value * 10 + digit;
        }
        return negative ? -value : value;
    }

    @Override
    protected double doubleAt(int column) {
        // Without trim(): parseDouble strips whitespace itself, and the extra
        // String was one allocation per value - at a thousand rows a thousand
        // objects for nothing.
        return Double.parseDouble(stringAt(column));
    }

    @Override
    protected boolean booleanAt(int column) {
        byte first = block.byteAt(block.offset(row, column));
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
            case PgOids.INT2 -> getShort(index);
            case PgOids.INT4 -> getInt(index);
            case PgOids.INT8 -> getLong(index);
            case PgOids.FLOAT4 -> getFloat(index);
            case PgOids.FLOAT8 -> getDouble(index);
            case PgOids.NUMERIC -> getBigDecimal(index);
            case PgOids.BYTEA -> getBytes(index);
            case PgOids.DATE -> getDate(index);
            case PgOids.TIME -> getTime(index);
            case PgOids.TIMESTAMP, PgOids.TIMESTAMPTZ -> getTimestamp(index);
            case PgOids.UUID -> UUID.fromString(stringAt(column));
            case PgOids.XML -> getSQLXML(index);
            case PgOids.TID -> getRowId(index);
            default -> stringAt(column);
        };
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
