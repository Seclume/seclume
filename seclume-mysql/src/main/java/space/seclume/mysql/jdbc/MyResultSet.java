package space.seclume.mysql.jdbc;

import java.nio.charset.StandardCharsets;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;

import space.seclume.internal.jdbc.ReadOnlyResultSet;
import space.seclume.mysql.BinaryValues;
import space.seclume.mysql.MySession;
import space.seclume.mysql.MyTypes;

/**
 * A {@code ResultSet} on top of a {@link MyResultBlock}.
 *
 * <p>Everything formal - the cursor, {@code wasNull}, the 190 methods that do
 * not exist - lives in {@link ReadOnlyResultSet}. Only the values are here, and
 * they carry a catch PostgreSQL does not have: depending on the protocol the
 * same column arrives as a run of digits or as four bytes little-endian. That
 * is why every access branches once on {@code binary}.
 */
public final class MyResultSet extends ReadOnlyResultSet {

    private final MyResultBlock block;

    /** The statement that can bring the next block, or {@code null}. */
    private final MyStatement owner;

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

    MyResultSet(MyResultBlock block, Statement statement) {
        super(statement);
        this.block = block;
        this.owner = statement instanceof MyStatement my ? my : null;
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
        return block.length(column) < 0;
    }

    @Override
    protected String stringAt(int column) {
        if (block.isBinary()) {
            return BinaryValues.toText(block, column);
        }
        return block.textAt(block.offset(column), block.length(column));
    }

    /** Without a {@code String} and without {@code parseLong} - straight from the bytes. */
    @Override
    protected long longAt(int column) throws SQLException {
        if (block.isBinary()) {
            return BinaryValues.toLong(block, column);
        }
        int offset = block.offset(column);
        int length = block.length(column);
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
        if (block.isBinary()) {
            return BinaryValues.toDouble(block, column);
        }
        return Double.parseDouble(stringAt(column));
    }

    @Override
    protected byte[] bytesAt(int column) {
        int offset = block.offset(column);
        int length = block.length(column);
        byte[] out = new byte[length]; // seclume-allow: user payload requested as bytes, not a secret
        for (int i = 0; i < length; i++) {
            out[i] = block.byteAt(offset + i);
        }
        return out;
    }

    /**
     * MySQL has no boolean type of its own: {@code BOOLEAN} is a
     * {@code TINYINT(1)}, and everything other than 0 counts as true. For text
     * 't'/'T'/'y' are accepted on top, so that a result out of a {@code CASE}
     * clause does not come as a surprise.
     */
    @Override
    protected boolean booleanAt(int column) throws SQLException {
        int type = block.fields().get(column).type();
        if (block.isBinary() || MyTypes.binaryFixedLength(type) > 0) {
            return longAt(column) != 0;
        }
        int offset = block.offset(column);
        if (block.length(column) == 0) {
            return false;
        }
        byte first = block.byteAt(offset);
        if (first == 't' || first == 'T' || first == 'y' || first == 'Y') {
            return true;
        }
        if (first == 'f' || first == 'F' || first == 'n' || first == 'N') {
            return false;
        }
        return longAt(column) != 0;
    }

    @Override
    protected Object objectAt(int column) throws SQLException {
        MySession.Field field = block.fields().get(column);
        return switch (field.type()) {
            case MyTypes.TINY, MyTypes.SHORT, MyTypes.YEAR -> (int) longAt(column);
            case MyTypes.LONG, MyTypes.INT24 ->
                    field.unsigned() ? (Object) longAt(column) : (Object) (int) longAt(column);
            case MyTypes.LONGLONG -> longAt(column);
            case MyTypes.FLOAT -> (float) doubleAt(column);
            case MyTypes.DOUBLE -> doubleAt(column);
            case MyTypes.DECIMAL, MyTypes.NEWDECIMAL ->
                    new java.math.BigDecimal(stringAt(column).trim());
            case MyTypes.DATE, MyTypes.NEWDATE -> java.sql.Date.valueOf(stringAt(column));
            case MyTypes.TIME -> java.sql.Time.valueOf(shortTime(stringAt(column)));
            case MyTypes.DATETIME, MyTypes.TIMESTAMP ->
                    java.sql.Timestamp.valueOf(stringAt(column));
            case MyTypes.TINY_BLOB, MyTypes.MEDIUM_BLOB, MyTypes.LONG_BLOB, MyTypes.BLOB,
                 MyTypes.VARCHAR, MyTypes.VAR_STRING, MyTypes.STRING, MyTypes.GEOMETRY ->
                    field.binary() ? bytesAt(column) : stringAt(column);
            default -> stringAt(column);
        };
    }

    /** {@code Time.valueOf} cannot do fractional seconds - it cuts them off. */
    private static String shortTime(String text) {
        int dot = text.indexOf('.');
        return dot < 0 ? text : text.substring(0, dot);
    }

    @Override
    protected int columnIndexOf(String label) {
        for (int i = 0; i < block.columnCount(); i++) {
            if (block.fields().get(i).name().equalsIgnoreCase(label)) {
                return i;
            }
        }
        // In "select a as b" MySQL names both; whoever looks for the
        // original should find it too.
        for (int i = 0; i < block.columnCount(); i++) {
            if (block.fields().get(i).originalName().equalsIgnoreCase(label)) {
                return i;
            }
        }
        return -1;
    }

    @Override
    protected ResultSetMetaData metaData() {
        return new MyResultSetMetaData(block.fields());
    }

    /**
     * Nothing to free here: the block belongs to the statement and the next
     * execution reuses it. Closing it would pull the memory out from under the
     * statement.
     */
    @Override
    protected void release() {
    }

    /** Only so that the character set lives in one place. */
    static String text(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8); // seclume-allow: user payload, not a secret
    }
}
