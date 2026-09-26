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
public final class MyResultSet extends ReadOnlyResultSet implements space.seclume.Sensitive {

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
        int type = block.fields().get(column).type();
        if (type == MyTypes.YEAR) {
            // As a date, the way Connector/J writes it: 2024-01-01.
            long year = block.isBinary() ? BinaryValues.toLong(block, column)
                    : block.decimalAt(block.offset(column), block.length(column));
            return String.format("%04d-01-01", year);
        }
        if (type == MyTypes.BIT && !block.isBinary()) {
            // The bits as a number in both protocols - the text one sends
            // the raw bytes here, not digits.
            return Long.toString(BinaryValues.toLong(block, column));
        }
        if (block.isBinary()) {
            return BinaryValues.toText(block, column);
        }
        String text = block.textAt(block.offset(column), block.length(column));
        // The two protocols have to give the same answer. The binary one
        // decodes four or eight bytes and renders them with Float.toString,
        // so it says "0.0"; the text one used to hand through whatever the
        // server wrote, which is "0". One driver, one column, two strings -
        // found by reading every value through both a Statement and a
        // PreparedStatement in the differential run. Java's rendering wins
        // because it is the one an application gets from the value itself.
        return switch (block.fields().get(column).type()) {
            case MyTypes.FLOAT -> text.isEmpty() ? text : Float.toString(Float.parseFloat(text));
            case MyTypes.DOUBLE -> text.isEmpty() ? text
                    : Double.toString(Double.parseDouble(text));
            // And the same disagreement in the temporal types. On a
            // datetime(6) whose fraction happens to be zero, the server sends
            // ".000000" in the text protocol and leaves the field out
            // altogether in the binary one - so the text path said
            // "00:00:00.000000" and the binary path "00:00:00" for the same
            // stored value. Only the all-zero fraction is dropped; a real one
            // is six digits in both protocols already.
            case MyTypes.DATETIME, MyTypes.TIMESTAMP, MyTypes.TIME -> withoutEmptyFraction(text);
            default -> text;
        };
    }

    /** Without a {@code String} and without {@code parseLong} - straight from the bytes. */
    @Override
    protected long longAt(int column) throws SQLException {
        if (block.isBinary() || block.fields().get(column).type() == MyTypes.BIT) {
            // A bit column carries its bits in both protocols, not digits.
            return BinaryValues.toLong(block, column);
        }
        try {
            return block.decimalAt(block.offset(column), block.length(column));
        } catch (NumberFormatException e) {
            throw new SQLException("column " + (column + 1) + " is not an integer: "
                    + stringAt(column), "22018");
        }
    }

    @Override
    protected double doubleAt(int column) {
        if (block.isBinary()) {
            return BinaryValues.toDouble(block, column);
        }
        return block.decimalDoubleAt(block.offset(column), block.length(column));
    }

    @Override
    protected java.math.BigDecimal decimalAt(int column) throws SQLException {
        if (block.fields().get(column).type() == MyTypes.YEAR) {
            return java.math.BigDecimal.valueOf(longAt(column));
        }
        if (block.isBinary()) {
            // The binary protocol sends a decimal as text inside the row, but
            // everything around it is binary - stringAt knows which, this does
            // not.
            return super.decimalAt(column);
        }
        return block.bigDecimalAt(block.offset(column), block.length(column));
    }

    /**
     * MySQL has no XML type: XML lives in a text column, and that is where
     * {@code getSQLXML} has to read it from - Connector/J does the same. On
     * PostgreSQL, SQL Server and Oracle only a real XML column answers.
     */
    @Override
    protected java.sql.SQLXML sqlXmlAt(int column) throws SQLException {
        return new space.seclume.internal.jdbc.XmlValue(stringAt(column));
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
        if (block.isBinary() || type == MyTypes.BIT || MyTypes.binaryFixedLength(type) > 0) {
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
        if (MyTypes.isBooleanColumn(field.type(), field.columnLength(), block.tinyInt1isBit())) {
            // What every ORM meant when it wrote the column, and what
            // Connector/J answers - code that casts the result to Boolean
            // moves between the two drivers without a change.
            return booleanAt(column);
        }
        return switch (field.type()) {
            case MyTypes.TINY, MyTypes.SHORT, MyTypes.INT24 -> (int) longAt(column);
            // A date on the first of January, as Connector/J hands it out.
            case MyTypes.YEAR -> java.sql.Date.valueOf(stringAt(column));
            case MyTypes.LONG ->
                    field.unsigned() ? (Object) longAt(column) : (Object) (int) longAt(column);
            // bit(1) is a flag and reads as one; a wider bit is its bytes.
            case MyTypes.BIT -> field.columnLength() == 1 ? (Object) booleanAt(column)
                    : bytesAt(column);
            // bigint unsigned goes up to 2^64-1 and a long stops at
            // 2^63-1, so the top half of the range came back as a negative
            // number: 18446744073709551615 read as -1. Not an exception, not
            // a warning - the wrong value, quietly. getString was already
            // right (BinaryValues uses Long.toUnsignedString), which is how
            // the differential run against Connector/J caught it: the two
            // getters disagreed with each other.
            //
            // BigInteger is what Connector/J returns, and it is the only
            // standard type that holds the range.
            //
            // On the BigInteger: the rule against it is about key material,
            // which is what BigInteger holds everywhere else in this project
            // - an RSA modulus that cannot be wiped. This is a row value on
            // its way to the application, the same kind of object as the
            // BigDecimal two lines below and the String below that. A result
            // set is where application data lives; it is not the secret path.
            case MyTypes.LONGLONG -> field.unsigned()
                    // seclume-allow: a column value, not key material - see above
                    ? new java.math.BigInteger(stringAt(column).trim())
                    : (Object) longAt(column);
            case MyTypes.FLOAT -> (float) doubleAt(column);
            case MyTypes.DOUBLE -> doubleAt(column);
            case MyTypes.DECIMAL, MyTypes.NEWDECIMAL ->
                    new java.math.BigDecimal(stringAt(column).trim());
            case MyTypes.DATE, MyTypes.NEWDATE -> java.sql.Date.valueOf(stringAt(column));
            case MyTypes.TIME -> java.sql.Time.valueOf(shortTime(stringAt(column)));
            // DATETIME has no zone and so is a LocalDateTime, as in Connector/J
            // since 8.0.23; TIMESTAMP stays a Timestamp there as well.
            case MyTypes.DATETIME -> java.time.LocalDateTime.parse(
                    stringAt(column).replace(' ', 'T'));
            case MyTypes.TIMESTAMP ->
                    java.sql.Timestamp.valueOf(stringAt(column));
            case MyTypes.TINY_BLOB, MyTypes.MEDIUM_BLOB, MyTypes.LONG_BLOB, MyTypes.BLOB,
                 MyTypes.VARCHAR, MyTypes.VAR_STRING, MyTypes.STRING, MyTypes.GEOMETRY ->
                    // The character set decides, not the BINARY flag: MySQL
                    // sets that flag for text in a _bin collation too -
                    // utf8mb4_bin, and information_schema's own names - and
                    // those came back as byte[]. Liquibase cast one to String
                    // and stopped. Set 63 is binary; everything else is text.
                    field.charset() == 63 ? bytesAt(column) : stringAt(column);
            default -> stringAt(column);
        };
    }

    /**
     * Drops a fractional part that is nothing but zeros.
     *
     * <p>Deliberately narrow: {@code .000000} goes, {@code .100000} stays as
     * it is. Trimming trailing zeros in general would turn one server
     * rendering into another and lose the column's declared precision, which
     * is a different change and not one this is for.
     */
    private static String withoutEmptyFraction(String text) {
        int dot = text.indexOf('.');
        if (dot < 0) {
            return text;
        }
        for (int i = dot + 1; i < text.length(); i++) {
            if (text.charAt(i) != '0') {
                return text;
            }
        }
        return text.substring(0, dot);
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
        return new MyResultSetMetaData(block.fields(), block.tinyInt1isBit());
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

    // ---- the native window, for space.seclume.Sensitive ------------------

    @Override
    protected java.lang.foreign.MemorySegment rawSegmentAt(int column) {
        return block.data().segment();
    }

    @Override
    protected long rawOffsetAt(int column) {
        return block.offset(column);
    }

    @Override
    protected int rawLengthAt(int column) {
        return block.length(column);
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

}
