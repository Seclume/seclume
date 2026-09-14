package space.seclume.sqlserver.jdbc;

import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;

import space.seclume.internal.jdbc.ReadOnlyResultSet;
import space.seclume.sqlserver.tds.TdsColumn;
import space.seclume.sqlserver.tds.TdsTypes;
import space.seclume.sqlserver.tds.TdsValues;

/**
 * A {@code ResultSet} on top of a {@link TdsResultBlock}.
 *
 * <p>Everything formal - the cursor, {@code wasNull}, the many methods that do
 * not apply to a forward-only result - lives in {@link ReadOnlyResultSet}. Only
 * the values are here.
 *
 * <p>SQL Server sends everything in binary, which makes this simpler than
 * MySQL: there is no second format for the same column. What it costs instead
 * is a type table, because four bytes are an {@code int}, a {@code real}, a
 * {@code smallmoney} or a date - and only the column description says which.
 *
 * <p>No value is turned into a Java object here until somebody asks for it.
 * {@code getLong} reads the bytes and returns a {@code long}; nothing is
 * allocated on the way.
 */
public final class TdsResultSet extends ReadOnlyResultSet {

    private final TdsResultBlock block;

    /** The statement that can bring the next block, or {@code null}. */
    private final TdsStatement owner;

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

    TdsResultSet(TdsResultBlock block, Statement statement) {
        super(statement);
        this.block = block;
        this.owner = statement instanceof TdsStatement tds ? tds : null;
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
    protected String stringAt(int column) {
        TdsColumn description = block.column(column);
        return TdsValues.asText(block.data(), description.type(), block.offset(column),
                block.length(column), description.scale());
    }

    @Override
    protected long longAt(int column) {
        return TdsValues.asLong(block.data(), block.column(column).type(),
                block.offset(column), block.length(column));
    }

    @Override
    protected double doubleAt(int column) {
        return TdsValues.asDouble(block.data(), block.column(column).type(),
                block.offset(column), block.length(column));
    }

    @Override
    protected byte[] bytesAt(int column) {
        return TdsValues.asBytes(block.data(), block.offset(column), block.length(column));
    }

    @Override
    protected boolean booleanAt(int column) {
        return TdsValues.asBoolean(block.data(), block.column(column).type(),
                block.offset(column), block.length(column));
    }

    /**
     * The Java object JDBC promises for this column.
     *
     * <p>The dates go the way round through the text: the decoder already
     * produces the ISO form, and {@code Date.valueOf} and its relatives read
     * exactly that. A second decoding path into {@code java.time} would be a
     * second place to get the tick arithmetic wrong.
     */
    @Override
    protected Object objectAt(int column) throws SQLException {
        TdsColumn description = block.column(column);
        int size = description.size();
        return switch (description.type()) {
            case TdsTypes.BIT, TdsTypes.BITN -> booleanAt(column);
            case TdsTypes.INT1, TdsTypes.INT2, TdsTypes.INT4 -> (int) longAt(column);
            case TdsTypes.INT8 -> longAt(column);
            case TdsTypes.INTN -> block.length(column) <= 4
                    ? (Object) (int) longAt(column)
                    : (Object) longAt(column);
            case TdsTypes.FLT4 -> (float) doubleAt(column);
            case TdsTypes.FLT8 -> doubleAt(column);
            case TdsTypes.FLTN -> block.length(column) == 4
                    ? (Object) (float) doubleAt(column)
                    : (Object) doubleAt(column);
            case TdsTypes.DECIMAL, TdsTypes.DECIMALN, TdsTypes.NUMERIC, TdsTypes.NUMERICN,
                 TdsTypes.MONEY, TdsTypes.MONEY4, TdsTypes.MONEYN ->
                    new java.math.BigDecimal(stringAt(column));
            case TdsTypes.DATEN -> java.sql.Date.valueOf(stringAt(column));
            case TdsTypes.TIMEN -> java.sql.Time.valueOf(withoutFraction(stringAt(column)));
            case TdsTypes.DATETIME, TdsTypes.DATETIM4, TdsTypes.DATETIMN,
                 TdsTypes.DATETIME2N -> java.sql.Timestamp.valueOf(stringAt(column));
            case TdsTypes.DATETIMEOFFSETN ->
                    java.time.OffsetDateTime.parse(isoOffset(stringAt(column)));
            case TdsTypes.BINARY, TdsTypes.BIGBINARY, TdsTypes.VARBINARY,
                 TdsTypes.BIGVARBINARY, TdsTypes.IMAGE -> bytesAt(column);
            default -> {
                if (size == 0 && description.type() == TdsTypes.NULLTYPE) {
                    yield null;
                }
                yield stringAt(column);
            }
        };
    }

    /** {@code Time.valueOf} cannot do fractional seconds - it cuts them off. */
    private static String withoutFraction(String text) {
        int dot = text.indexOf('.');
        return dot < 0 ? text : text.substring(0, dot);
    }

    /**
     * {@code 2026-09-07 12:30:15 +02:00} into the ISO form
     * {@code 2026-09-07T12:30:15+02:00} that {@code OffsetDateTime} reads.
     */
    private static String isoOffset(String text) {
        int space = text.indexOf(' ');
        int beforeOffset = text.lastIndexOf(' ');
        if (space < 0 || beforeOffset == space) {
            return text;
        }
        return text.substring(0, space) + "T" + text.substring(space + 1, beforeOffset)
                + text.substring(beforeOffset + 1);
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
        return new TdsResultSetMetaData(block.columns());
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
