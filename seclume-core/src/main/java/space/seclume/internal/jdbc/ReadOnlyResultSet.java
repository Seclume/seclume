package space.seclume.internal.jdbc;

import java.io.InputStream;
import java.io.Reader;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.URL;
import java.sql.Array;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.Date;
import java.sql.NClob;
import java.sql.Ref;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.RowId;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLType;
import java.sql.SQLWarning;
import java.sql.SQLXML;
import java.sql.Statement;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Map;

/**
 * The scaffolding of a forward-only, read-only {@code ResultSet}.
 *
 * <p>{@code ResultSet} has over 190 methods, of which a driver of this shape
 * really answers about twenty. The rest are updating in place - which seclume
 * does not do and does not pretend to - and the cursor in any direction, which
 * a result of {@code TYPE_SCROLL_INSENSITIVE} has and a forward-only one
 * refuses.
 *
 * <p>{@code Array}, {@code SQLXML} and {@code RowId} sit between the two: they
 * are refused here and served by whichever driver actually has the type, which
 * is why they are hooks rather than a flat answer. {@code Ref} has no hook,
 * because none of the four servers has a type it could point at.
 *
 * <p>This class answers the unanswerable part once and for all, with
 * {@link SQLFeatureNotSupportedException}. A {@code ResultSet} that acts as if
 * it could go backwards and quietly returns the wrong thing is worse than one
 * that refuses honestly - so a forward-only result, whose earlier rows may
 * already be gone, refuses {@code previous()} rather than guess.
 *
 * <p>What a driver contributes are the values: the {@code ...At} methods. They
 * receive the <b>zero-based</b> column index of the current row; converting
 * from JDBC's one-based counting, checking the bounds and remembering
 * {@link #wasNull()} is this class's business.
 */
public abstract class ReadOnlyResultSet implements ResultSet {

    private final Statement statement;
    private int row = -1;
    private boolean lastWasNull;
    private boolean closed;

    /**
     * Whether the statement asked for {@code TYPE_SCROLL_INSENSITIVE}. The
     * driver then read the result whole - no fetch size, no pause - and the
     * cursor may move over it in any direction.
     */
    private final boolean scrollable;

    protected ReadOnlyResultSet(Statement statement) {
        this.statement = statement;
        boolean scroll = false;
        int limit = 0;
        try {
            scroll = statement != null
                    && statement.getResultSetType() == TYPE_SCROLL_INSENSITIVE;
            limit = statement == null ? 0 : statement.getMaxFieldSize();
        } catch (SQLException closed) {
            // A statement that cannot say is one that was not asked to scroll.
        }
        this.scrollable = scroll;
        this.maxFieldSize = limit;
    }

    /**
     * {@code Statement.setMaxFieldSize}: the most characters or bytes a text
     * or binary column hands out, the rest silently dropped - JDBC's words,
     * and what the vendors do. 0 for no limit, which is nearly always.
     */
    private final int maxFieldSize;
    /** Which columns the limit applies to, worked out on first need. */
    private boolean[] truncatable;

    private boolean truncatable(int column) throws SQLException {
        if (truncatable == null) {
            ResultSetMetaData description = metaData();
            boolean[] which = new boolean[columnCount()];
            for (int i = 0; i < which.length; i++) {
                which[i] = switch (description.getColumnType(i + 1)) {
                    case java.sql.Types.CHAR, java.sql.Types.VARCHAR, java.sql.Types.LONGVARCHAR,
                         java.sql.Types.NCHAR, java.sql.Types.NVARCHAR,
                         java.sql.Types.LONGNVARCHAR, java.sql.Types.BINARY,
                         java.sql.Types.VARBINARY, java.sql.Types.LONGVARBINARY -> true;
                    default -> false;
                };
            }
            truncatable = which;
        }
        return truncatable[column];
    }

    // ---- what a driver contributes ---------------------------------------

    /** How many rows the result has. */
    protected abstract int rowCount();

    /** How many columns the result has. */
    protected abstract int columnCount();

    /** Tells the subclass which row applies now. */
    protected abstract void moveTo(int row);

    /** Whether the cell is SQL NULL. */
    protected abstract boolean isNullAt(int column);

    protected abstract String stringAt(int column) throws SQLException;

    protected abstract long longAt(int column) throws SQLException;

    protected abstract double doubleAt(int column) throws SQLException;

    protected abstract byte[] bytesAt(int column) throws SQLException;

    protected abstract boolean booleanAt(int column) throws SQLException;

    protected abstract Object objectAt(int column) throws SQLException;

    /**
     * A large value as a {@code Clob}.
     *
     * <p>Over the value the row already carries, which is what
     * {@link Lobs} explains: accurate about the content, no claim about
     * laziness. A driver that can genuinely stream - Oracle, through its
     * locators - overrides this and hands out the real thing.
     */
    protected Clob clobAt(int column) throws SQLException {
        return Lobs.text(stringAt(column));
    }

    /** The same for a {@code Blob}. */
    protected Blob blobAt(int column) throws SQLException {
        return Lobs.binary(bytesAt(column));
    }

    /** A large text value as a reader. */
    protected Reader readerAt(int column) throws SQLException {
        return new java.io.StringReader(stringAt(column));
    }

    /** A large binary value as a stream. */
    protected InputStream binaryStreamAt(int column) throws SQLException {
        return new java.io.ByteArrayInputStream(bytesAt(column));
    }

    /**
     * An array column as a JDBC {@link Array}.
     *
     * <p>Refused unless a driver overrides it, because an array is the one
     * type where the servers genuinely differ: PostgreSQL has real array
     * columns and a text form for them, and the other three have no array
     * type at all. There is nothing sensible to do here in general.
     */
    protected Array arrayAt(int column) throws SQLException {
        throw noSuchType("ARRAY");
    }

    /** An XML column as a {@link SQLXML}; refused unless a driver overrides it. */
    protected SQLXML sqlXmlAt(int column) throws SQLException {
        throw noSuchType("SQLXML");
    }

    /**
     * A row address as a {@link RowId}.
     *
     * <p>Only a column that <i>is</i> one can answer this, which means the
     * driver has to have selected it: PostgreSQL's {@code ctid}, Oracle's
     * {@code rowid}. Asking an ordinary column for its row address is a
     * mistake rather than a missing feature, and the drivers that override
     * this say which of the two happened.
     */
    protected RowId rowIdAt(int column) throws SQLException {
        throw noSuchType("ROWID");
    }

    /**
     * A point in time the driver has decoded itself: an
     * {@link java.time.OffsetDateTime} for a value that carries its zone, a
     * {@link java.time.LocalDateTime} for one that does not - or {@code null},
     * and the value is read from its text as before.
     *
     * <p>For the drivers whose text form is not ISO: Oracle writes a
     * {@code TIMESTAMP WITH TIME ZONE} as ojdbc does, "... +2:00" or
     * "... Europe/Vienna", and neither reads back as an offset.
     */
    protected Object temporalAt(int column) throws SQLException {
        return null;
    }

    /** The zero-based index for a column name, or -1. */
    protected abstract int columnIndexOf(String label);

    protected abstract ResultSetMetaData metaData() throws SQLException;

    /** Releases the memory of the result. */
    protected abstract void release();

    // ---- movement --------------------------------------------------------

    @Override
    public final boolean next() throws SQLException {
        checkOpen();
        if (row + 1 >= rowCount()) {
            // The block is read; a driver that fetches in blocks gets its
            // chance here to bring the next one. Without that hook a result
            // set is exactly as large as the memory it needs.
            if (!fetchMore()) {
                row = rowCount();
                return false;
            }
            row = -1;
            if (rowCount() == 0) {
                return false;
            }
        }
        row++;
        moveTo(row);
        return true;
    }

    /**
     * Brings the next block of rows, if the driver reads in blocks.
     *
     * <p>{@code false} - the default - means the whole result is already
     * here, which is what a driver without block cursors does.
     *
     * @return whether a new block was read; it may still be empty
     */
    protected boolean fetchMore() throws SQLException {
        return false;
    }

    /**
     * Closes the result the way an application does: and if the statement
     * was told {@code closeOnCompletion()}, the statement with it.
     */
    @Override
    public final void close() throws SQLException {
        if (!closed) {
            discard();
            if (statement != null && !statement.isClosed() && statement.isCloseOnCompletion()) {
                statement.close();
            }
        }
    }

    /**
     * Closes the result the way the driver does - because the statement runs
     * again, moves to its next result or closes itself. That is not the
     * completion {@code closeOnCompletion()} waits for: a statement that
     * closed itself on its own next execution would be unusable.
     */
    public final void discard() {
        if (!closed) {
            closed = true;
            release();
        }
    }

    @Override
    public final boolean isClosed() {
        return closed;
    }

    @Override
    public final boolean wasNull() {
        return lastWasNull;
    }

    @Override
    public final boolean isBeforeFirst() throws SQLException {
        checkOpen();
        return row < 0 && rowCount() > 0;
    }

    @Override
    public final boolean isAfterLast() throws SQLException {
        checkOpen();
        return row >= rowCount() && rowCount() > 0;
    }

    @Override
    public final boolean isFirst() throws SQLException {
        checkOpen();
        return row == 0;
    }

    @Override
    public final boolean isLast() throws SQLException {
        checkOpen();
        return row == rowCount() - 1;
    }

    @Override
    public final int getRow() throws SQLException {
        checkOpen();
        return row < 0 || row >= rowCount() ? 0 : row + 1;
    }

    // ---- values ----------------------------------------------------------

    /**
     * Checks the index, remembers NULL, and returns the zero-based index.
     *
     * <p>Every value access goes through here - which is why {@code wasNull()}
     * is always right afterwards, without a subclass having to think about
     * it.
     */
    protected final int check(int columnIndex) throws SQLException {
        checkOpen();
        if (row < 0) {
            throw new SQLException("call next() before reading a value");
        }
        if (row >= rowCount()) {
            throw new SQLException("the result set is exhausted");
        }
        if (columnIndex < 1 || columnIndex > columnCount()) {
            throw new SQLException("column " + columnIndex + " is out of range 1.."
                    + columnCount());
        }
        int column = columnIndex - 1;
        lastWasNull = isNullAt(column);
        return column;
    }

    // ---- reading a column without it becoming a String -------------------

    /**
     * Where the column's bytes are, for a driver that keeps rows in native
     * memory.
     *
     * <p>Not abstract, because not every result set here is a window onto a
     * receive buffer: a catalogue answer built from a list has no such thing,
     * and pretending otherwise would put a copy behind an API whose entire
     * purpose is that there is no copy.
     */
    protected java.lang.foreign.MemorySegment rawSegmentAt(int column) throws SQLException {
        throw notBackedByMemory();
    }

    /** Where in that segment - see {@link #rawSegmentAt}. */
    protected long rawOffsetAt(int column) throws SQLException {
        throw notBackedByMemory();
    }

    /** How many bytes - see {@link #rawSegmentAt}. */
    protected int rawLengthAt(int column) throws SQLException {
        throw notBackedByMemory();
    }

    private SQLException notBackedByMemory() {
        return new SQLException("this result set is built from values rather than from the "
                + "server's answer, so there is no native window to read: "
                + getClass().getName(), "0A000");
    }

    /**
     * {@link space.seclume.Sensitive#length}, with the shared bounds check.
     *
     * <p>Here and not in each driver because {@link #check} is what decides
     * that there is a row, that the column exists, and whether it is null -
     * and four copies of that are four chances to get the null wrong.
     */
    protected final int rawLength(int columnIndex) throws SQLException {
        int column = check(columnIndex);
        return lastWasNull ? -1 : rawLengthAt(column);
    }

    /** {@link space.seclume.Sensitive#readInto}, with the shared bounds check. */
    protected final int copyRaw(int columnIndex, java.lang.foreign.MemorySegment target)
            throws SQLException {
        int column = check(columnIndex);
        if (lastWasNull) {
            return -1;
        }
        int length = rawLengthAt(column);
        if (target == null) {
            throw new SQLException("no segment to read column " + columnIndex + " into");
        }
        if (target.byteSize() < length) {
            // Refused rather than truncated. A key cut in half does not fail
            // here - it fails in whatever verifies a signature, hours later
            // and nowhere near this line.
            throw new SQLException("column " + columnIndex + " holds " + length
                    + " bytes and the segment given holds " + target.byteSize(), "22001");
        }
        java.lang.foreign.MemorySegment.copy(rawSegmentAt(column), rawOffsetAt(column),
                target, 0, length);
        return length;
    }

    @Override
    public final String getString(int columnIndex) throws SQLException {
        int column = check(columnIndex);
        if (lastWasNull) {
            return null;
        }
        String value = stringAt(column);
        return maxFieldSize > 0 && value.length() > maxFieldSize && truncatable(column)
                ? value.substring(0, maxFieldSize) : value;
    }

    @Override
    public final boolean getBoolean(int columnIndex) throws SQLException {
        int column = check(columnIndex);
        return !lastWasNull && booleanAt(column);
    }

    @Override
    public final byte getByte(int columnIndex) throws SQLException {
        return (byte) getLong(columnIndex);
    }

    @Override
    public final short getShort(int columnIndex) throws SQLException {
        return (short) getLong(columnIndex);
    }

    @Override
    public final int getInt(int columnIndex) throws SQLException {
        return (int) getLong(columnIndex);
    }

    @Override
    public final long getLong(int columnIndex) throws SQLException {
        int column = check(columnIndex);
        return lastWasNull ? 0 : longAt(column);
    }

    @Override
    public final float getFloat(int columnIndex) throws SQLException {
        return (float) getDouble(columnIndex);
    }

    @Override
    public final double getDouble(int columnIndex) throws SQLException {
        int column = check(columnIndex);
        return lastWasNull ? 0 : doubleAt(column);
    }

    @Override
    public final BigDecimal getBigDecimal(int columnIndex) throws SQLException {
        int column = check(columnIndex);
        return lastWasNull ? null : decimalAt(column);
    }

    /**
     * The column as a {@code BigDecimal}.
     *
     * <p>Through a {@code String}, which every driver can do and which is
     * right wherever the value is not simply digits in the receive buffer. A
     * driver whose text protocol puts it there overrides this and reads the
     * bytes - see {@code space.seclume.internal.jdbc.TextNumber}.
     */
    protected BigDecimal decimalAt(int column) throws SQLException {
        String text = stringAt(column);
        return text == null ? null : new BigDecimal(text.trim());
    }

    @Override
    @Deprecated
    public final BigDecimal getBigDecimal(int columnIndex, int scale) throws SQLException {
        BigDecimal value = getBigDecimal(columnIndex);
        return value == null ? null : value.setScale(scale, RoundingMode.HALF_UP);
    }

    @Override
    public final byte[] getBytes(int columnIndex) throws SQLException {
        int column = check(columnIndex);
        if (lastWasNull) {
            return null;
        }
        byte[] value = bytesAt(column); // seclume-allow: the value getBytes returns anyway
        return maxFieldSize > 0 && value.length > maxFieldSize && truncatable(column)
                ? java.util.Arrays.copyOf(value, maxFieldSize) : value;
    }

    @Override
    public final Object getObject(int columnIndex) throws SQLException {
        int column = check(columnIndex);
        if (lastWasNull) {
            return null;
        }
        if (maxFieldSize > 0 && truncatable(column)) {
            Object value = objectAt(column);
            return value instanceof String ? getString(columnIndex)
                    : value instanceof byte[] ? getBytes(columnIndex) : value;
        }
        return objectAt(column);
    }

    @Override
    public final Date getDate(int columnIndex) throws SQLException {
        String text = getString(columnIndex);
        if (text == null) {
            return null;
        }
        java.time.LocalDateTime decoded = inThisZone(temporalAt(columnIndex - 1));
        return decoded != null ? Date.valueOf(decoded.toLocalDate())
                : Date.valueOf(text.length() > 10 ? text.substring(0, 10) : text);
    }

    /** What {@link #temporalAt} decoded, as the JVM's zone sees it; null if nothing. */
    private static java.time.LocalDateTime inThisZone(Object decoded) {
        if (decoded instanceof java.time.OffsetDateTime zoned) {
            return zoned.atZoneSameInstant(java.time.ZoneId.systemDefault()).toLocalDateTime();
        }
        return decoded instanceof java.time.LocalDateTime local ? local : null;
    }

    /**
     * A time of day, whatever the column holds it in.
     *
     * <p>Oracle has no type for a time without a date - Hibernate maps one
     * to a timestamp there - so the value may arrive as a whole timestamp.
     * The time part of it is what was asked for; a fraction of a second is
     * dropped, as {@code java.sql.Time} has nowhere to keep it.
     */
    @Override
    public final Time getTime(int columnIndex) throws SQLException {
        String text = getString(columnIndex);
        if (text == null) {
            return null;
        }
        java.time.LocalDateTime decoded = inThisZone(temporalAt(columnIndex - 1));
        if (decoded != null) {
            return Time.valueOf(decoded.toLocalTime());
        }
        String value = text.trim().replace('T', ' ');
        int space = value.indexOf(' ');
        if (space > 0 && value.indexOf(':') > space) {
            value = value.substring(space + 1);
        }
        // A time with a zone - PostgreSQL's timetz, "13:14:15+02" - is the
        // instant it names, on the epoch day, in this JVM's zone: what pgjdbc
        // answers. Read as a plain time, the offset was part of the seconds
        // and getTime threw; found by the type catalog run.
        int zone = Math.max(value.lastIndexOf('+'), value.lastIndexOf('-'));
        if (zone > 0) {
            String time = value.substring(0, zone);
            String offset = value.substring(zone);
            if (offset.length() == 3) {
                offset += ":00";
            }
            java.time.OffsetTime at = java.time.OffsetTime.of(
                    java.time.LocalTime.parse(time), java.time.ZoneOffset.of(offset));
            return new Time(at.atDate(java.time.LocalDate.EPOCH).toInstant().toEpochMilli());
        }
        int dot = value.indexOf('.');
        return Time.valueOf(dot < 0 ? value : value.substring(0, dot));
    }

    /**
     * A point in time, whether or not the column carries a zone.
     *
     * <p>{@code Timestamp.valueOf} takes exactly one shape and throws on
     * anything else, and three of the four servers hand out a
     * {@code timestamptz} or {@code datetimeoffset} with the offset written
     * after it - "2026-09-20 09:29:16.153+02" on PostgreSQL,
     * "... .1530000 +00:00" on SQL Server. Those are the columns Hibernate
     * maps an {@code Instant} to, so the shape is ordinary rather than
     * exotic. Where an offset is there it is used, and the result names the
     * same point in time in the JVM's zone; where there is none nothing
     * changes.
     */
    @Override
    public final Timestamp getTimestamp(int columnIndex) throws SQLException {
        String text = getString(columnIndex);
        if (text == null) {
            return null;
        }
        Object decoded = temporalAt(columnIndex - 1);
        if (decoded instanceof java.time.OffsetDateTime zoned) {
            return Timestamp.from(zoned.toInstant());
        }
        if (decoded instanceof java.time.LocalDateTime local) {
            return Timestamp.valueOf(local);
        }
        Timestamp fast = zonedTimestamp(text);
        if (fast != null) {
            return fast;
        }
        java.time.OffsetDateTime zoned = withOffset(text);
        return zoned == null ? Timestamp.valueOf(text.replace('T', ' ').trim())
                : Timestamp.from(zoned.toInstant());
    }

    /**
     * The common shape of a point in time with its offset -
     * {@code 2026-09-24 13:14:15.123456+02}, {@code +02:00}, {@code +0530} -
     * straight to epoch milliseconds and nanoseconds, or {@code null} for
     * anything else, which then goes the general way.
     *
     * <p>The general way parses a LocalDateTime and a ZoneOffset and builds an
     * Instant: three objects and two parsers per value, which made getObject
     * on a PostgreSQL {@code timestamptz} take twice as long as through
     * pgjdbc. This is arithmetic on the characters.
     */
    static Timestamp zonedTimestamp(String text) {
        int length = text.length();
        if (length < 22 || text.charAt(4) != '-' || text.charAt(7) != '-'
                || (text.charAt(10) != ' ' && text.charAt(10) != 'T')
                || text.charAt(13) != ':' || text.charAt(16) != ':') {
            return null;
        }
        int year = digits(text, 0, 4);
        int month = digits(text, 5, 2);
        int day = digits(text, 8, 2);
        int hour = digits(text, 11, 2);
        int minute = digits(text, 14, 2);
        int second = digits(text, 17, 2);
        if ((year | month | day | hour | minute | second) < 0) {
            return null;
        }
        int p = 19;
        int nanos = 0;
        if (p < length && text.charAt(p) == '.') {
            p++;
            int scale = 100_000_000;
            int start = p;
            while (p < length && text.charAt(p) >= '0' && text.charAt(p) <= '9') {
                nanos += (text.charAt(p) - '0') * scale;
                scale /= 10;
                p++;
            }
            if (p - start > 9) {
                return null;                               // more than a nanosecond
            }
        }
        if (p < length && text.charAt(p) == ' ') {
            p++;
        }
        if (p >= length || (text.charAt(p) != '+' && text.charAt(p) != '-')) {
            return null;
        }
        int sign = text.charAt(p) == '-' ? -1 : 1;
        int offsetHours = digits(text, p + 1, 2);
        int offsetMinutes = 0;
        int end = p + 3;
        if (end < length && text.charAt(end) == ':') {
            offsetMinutes = digits(text, end + 1, 2);
            end += 3;
        } else if (end + 2 <= length) {
            offsetMinutes = digits(text, end, 2);
            end += 2;
        }
        if (offsetHours < 0 || offsetMinutes < 0 || end != length || month < 1 || month > 12
                || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) {
            return null;
        }
        long seconds = epochDay(year, month, day) * 86_400L + hour * 3600L + minute * 60L
                + second - sign * (offsetHours * 3600L + offsetMinutes * 60L);
        Timestamp stamp = new Timestamp(seconds * 1000);
        stamp.setNanos(nanos);
        return stamp;
    }

    /** Two or four decimal digits at {@code at}, or -1. */
    private static int digits(String text, int at, int count) {
        if (at + count > text.length()) {
            return -1;
        }
        int value = 0;
        for (int i = at; i < at + count; i++) {
            char c = text.charAt(i);
            if (c < '0' || c > '9') {
                return -1;
            }
            value = value * 10 + c - '0';
        }
        return value;
    }

    /** Days since 1970-01-01 of a proleptic Gregorian date - Howard Hinnant's algorithm. */
    private static long epochDay(int year, int month, int day) {
        long y = month <= 2 ? year - 1 : year;
        long era = Math.floorDiv(y, 400);
        long yearOfEra = y - era * 400;
        long dayOfYear = (153L * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1;
        long dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear;
        return era * 146_097 + dayOfEra - 719_468;
    }

    /**
     * The value as it stands, when it carries a zone; {@code null} when it
     * does not.
     *
     * <p>Written out rather than handed to a formatter because the four
     * spell the offset in four ways: {@code Z}, {@code +02}, {@code +02:00}
     * and {@code +0200}, the last two with or without a space in front.
     */
    private static java.time.OffsetDateTime withOffset(String raw) {
        String text = raw.trim().replace('T', ' ');
        int time = text.indexOf(' ');
        if (time < 0) {
            return null;
        }
        int zone = -1;
        for (int i = time + 1; i < text.length() && zone < 0; i++) {
            char c = text.charAt(i);
            if (c == '+' || c == '-' || c == 'Z' || c == 'z') {
                zone = i;
            }
        }
        if (zone < 0) {
            return null;
        }
        String stamp = text.substring(0, zone).trim();
        String offset = text.substring(zone).trim();
        if (offset.length() == 3) {
            offset = offset + ":00";                   // "+02" is a whole hour
        }
        try {
            return java.time.LocalDateTime.parse(stamp.replace(' ', 'T'))
                    .atOffset(java.time.ZoneOffset.of(offset.toUpperCase(java.util.Locale.ROOT)));
        } catch (java.time.DateTimeException notAZone) {
            return null;
        }
    }

    @Override
    public final <T> T getObject(int columnIndex, Class<T> type) throws SQLException {
        Object value = switch (type.getName()) {
            case "java.lang.String" -> getString(columnIndex);
            case "java.lang.Boolean", "boolean" -> getBoolean(columnIndex);
            case "java.lang.Byte", "byte" -> getByte(columnIndex);
            case "java.lang.Short", "short" -> getShort(columnIndex);
            case "java.lang.Integer", "int" -> getInt(columnIndex);
            case "java.lang.Long", "long" -> getLong(columnIndex);
            case "java.lang.Float", "float" -> getFloat(columnIndex);
            case "java.lang.Double", "double" -> getDouble(columnIndex);
            case "java.math.BigDecimal" -> getBigDecimal(columnIndex);
            case "[B" -> getBytes(columnIndex);
            case "java.sql.Date" -> getDate(columnIndex);
            case "java.sql.Time" -> getTime(columnIndex);
            case "java.sql.Timestamp" -> getTimestamp(columnIndex);
            case "java.time.LocalDate" -> {
                Date date = getDate(columnIndex);
                yield date == null ? null : date.toLocalDate();
            }
            case "java.time.LocalTime" -> {
                Time time = getTime(columnIndex);
                yield time == null ? null : time.toLocalTime();
            }
            case "java.time.LocalDateTime" -> {
                String text = getString(columnIndex);
                Object decoded = text == null ? null : temporalAt(columnIndex - 1);
                if (decoded instanceof java.time.LocalDateTime local) {
                    yield local;
                }
                java.time.OffsetDateTime zoned = text == null ? null
                        : decoded instanceof java.time.OffsetDateTime known ? known
                        : withOffset(text);
                if (zoned != null) {
                    // A column with a zone read as a value without one: the
                    // fields as they stand, not shifted into the JVM's zone.
                    yield zoned.toLocalDateTime();
                }
                Timestamp timestamp = getTimestamp(columnIndex);
                yield timestamp == null ? null : timestamp.toLocalDateTime();
            }
            case "java.time.OffsetDateTime" -> {
                String text = getString(columnIndex);
                if (text == null) {
                    yield null;
                }
                Object decoded = temporalAt(columnIndex - 1);
                if (decoded instanceof java.time.LocalDateTime local) {
                    yield local.atZone(java.time.ZoneId.systemDefault()).toOffsetDateTime();
                }
                java.time.OffsetDateTime zoned = decoded instanceof java.time.OffsetDateTime known
                        ? known : withOffset(text);
                yield zoned != null ? zoned
                        : Timestamp.valueOf(text.replace('T', ' ').trim()).toLocalDateTime()
                                .atZone(java.time.ZoneId.systemDefault()).toOffsetDateTime();
            }
            case "java.time.ZonedDateTime" -> {
                java.time.OffsetDateTime zoned =
                        getObject(columnIndex, java.time.OffsetDateTime.class);
                yield zoned == null ? null : zoned.toZonedDateTime();
            }
            case "java.time.Instant" -> {
                Timestamp timestamp = getTimestamp(columnIndex);
                yield timestamp == null ? null : timestamp.toInstant();
            }
            case "java.time.OffsetTime" -> {
                Time clock = getTime(columnIndex);
                yield clock == null ? null : clock.toLocalTime()
                        .atOffset(java.time.OffsetDateTime.now().getOffset());
            }
            case "java.util.UUID" -> {
                // Two shapes, and which one it is depends on the column: the
                // thirty-six characters of the text form, or the sixteen
                // bytes a binary(16) or raw(16) holds - which is what
                // Hibernate uses on MySQL and Oracle.
                int stored = metaData().getColumnType(columnIndex);
                if (stored == java.sql.Types.BINARY || stored == java.sql.Types.VARBINARY
                        || stored == java.sql.Types.LONGVARBINARY) {
                    byte[] bytes = getBytes(columnIndex);
                    yield bytes == null ? null : uuidOf(bytes);
                }
                String text = getString(columnIndex);
                yield text == null ? null : java.util.UUID.fromString(text.trim());
            }
            case "java.lang.Object" -> getObject(columnIndex);
            default -> throw new SQLFeatureNotSupportedException(
                    "seclume does not convert column " + columnIndex + " to " + type.getName());
        };
        return wasNull() ? null : type.cast(value);
    }

    /** Sixteen bytes, most significant first - the way all four store one. */
    private static java.util.UUID uuidOf(byte[] bytes) throws SQLException {
        if (bytes.length != 16) {
            throw new SQLException("a UUID is sixteen bytes, and this column holds "
                    + bytes.length);
        }
        long high = 0;
        long low = 0;
        for (int i = 0; i < 8; i++) {
            high = (high << 8) | (bytes[i] & 0xffL);
            low = (low << 8) | (bytes[i + 8] & 0xffL);
        }
        return new java.util.UUID(high, low);
    }

    // ---- access by column name -------------------------------------------

    @Override
    public final int findColumn(String columnLabel) throws SQLException {
        checkOpen();
        int index = columnIndexOf(columnLabel);
        if (index < 0) {
            throw new SQLException("there is no column called '" + columnLabel + "'");
        }
        return index + 1;
    }

    @Override
    public final String getString(String columnLabel) throws SQLException {
        return getString(findColumn(columnLabel));
    }

    @Override
    public final boolean getBoolean(String columnLabel) throws SQLException {
        return getBoolean(findColumn(columnLabel));
    }

    @Override
    public final byte getByte(String columnLabel) throws SQLException {
        return getByte(findColumn(columnLabel));
    }

    @Override
    public final short getShort(String columnLabel) throws SQLException {
        return getShort(findColumn(columnLabel));
    }

    @Override
    public final int getInt(String columnLabel) throws SQLException {
        return getInt(findColumn(columnLabel));
    }

    @Override
    public final long getLong(String columnLabel) throws SQLException {
        return getLong(findColumn(columnLabel));
    }

    @Override
    public final float getFloat(String columnLabel) throws SQLException {
        return getFloat(findColumn(columnLabel));
    }

    @Override
    public final double getDouble(String columnLabel) throws SQLException {
        return getDouble(findColumn(columnLabel));
    }

    @Override
    public final BigDecimal getBigDecimal(String columnLabel) throws SQLException {
        return getBigDecimal(findColumn(columnLabel));
    }

    @Override
    @Deprecated
    public final BigDecimal getBigDecimal(String columnLabel, int scale) throws SQLException {
        return getBigDecimal(findColumn(columnLabel), scale);
    }

    @Override
    public final byte[] getBytes(String columnLabel) throws SQLException {
        return getBytes(findColumn(columnLabel));
    }

    @Override
    public final Date getDate(String columnLabel) throws SQLException {
        return getDate(findColumn(columnLabel));
    }

    @Override
    public final Time getTime(String columnLabel) throws SQLException {
        return getTime(findColumn(columnLabel));
    }

    @Override
    public final Timestamp getTimestamp(String columnLabel) throws SQLException {
        return getTimestamp(findColumn(columnLabel));
    }

    @Override
    public final Object getObject(String columnLabel) throws SQLException {
        return getObject(findColumn(columnLabel));
    }

    @Override
    public final <T> T getObject(String columnLabel, Class<T> type) throws SQLException {
        return getObject(findColumn(columnLabel), type);
    }

    /**
     * A date read as of a given calendar's time zone.
     *
     * <p>The mirror of the setters: the column holds wall-clock fields with
     * no zone, the caller says which zone they are to be read in, and what
     * comes back is the point on the time line those fields name there. This
     * is how Hibernate reads an {@code Instant} - with a calendar in UTC -
     * and refusing it, as this did, meant such an entity could not be read.
     */
    @Override
    public final Date getDate(int columnIndex, Calendar calendar) throws SQLException {
        Date value = getDate(columnIndex);
        if (value == null || isDefaultCalendar(calendar)) {
            return value;
        }
        return new Date(shifted(value.toLocalDate().atStartOfDay(), calendar));
    }

    @Override
    public final Date getDate(String columnLabel, Calendar calendar) throws SQLException {
        return getDate(findColumn(columnLabel), calendar);
    }

    @Override
    public final Time getTime(int columnIndex, Calendar calendar) throws SQLException {
        Time value = getTime(columnIndex);
        if (value == null || isDefaultCalendar(calendar)) {
            return value;
        }
        return new Time(shifted(value.toLocalTime().atDate(java.time.LocalDate.EPOCH),
                calendar));
    }

    @Override
    public final Time getTime(String columnLabel, Calendar calendar) throws SQLException {
        return getTime(findColumn(columnLabel), calendar);
    }

    /**
     * A point in time, read as of the calendar's zone.
     *
     * <p><b>A column that carries its own offset is not shifted.</b> It
     * already names a point on the time line, and applying the calendar on
     * top of it moves the value by the difference between the two zones -
     * which is how an {@code Instant} written as 09:29 UTC came back as
     * 11:29 UTC on a machine two hours ahead. The calendar says how to read
     * fields that have no zone, and only those.
     */
    @Override
    public final Timestamp getTimestamp(int columnIndex, Calendar calendar)
            throws SQLException {
        Timestamp value = getTimestamp(columnIndex);
        if (value == null || isDefaultCalendar(calendar)) {
            return value;
        }
        String text = getString(columnIndex);
        if (text != null && withOffset(text) != null) {
            return value;
        }
        Timestamp shifted = new Timestamp(shifted(value.toLocalDateTime(), calendar));
        shifted.setNanos(value.getNanos());
        return shifted;
    }

    @Override
    public final Timestamp getTimestamp(String columnLabel, Calendar calendar)
            throws SQLException {
        return getTimestamp(findColumn(columnLabel), calendar);
    }

    /** Whether the calendar asks for anything the value does not already say. */
    private static boolean isDefaultCalendar(Calendar calendar) {
        return calendar == null
                || calendar.getTimeZone().equals(java.util.TimeZone.getDefault());
    }

    /** The epoch milliseconds of wall-clock fields read in the calendar's zone. */
    private static long shifted(java.time.LocalDateTime fields, Calendar calendar) {
        return fields.atZone(calendar.getTimeZone().toZoneId()).toInstant().toEpochMilli();
    }

    // ---- state -----------------------------------------------------------

    @Override
    public final ResultSetMetaData getMetaData() throws SQLException {
        checkOpen();
        return metaData();
    }

    @Override
    public final Statement getStatement() {
        return statement;
    }

    @Override
    public final int getType() {
        return scrollable ? TYPE_SCROLL_INSENSITIVE : TYPE_FORWARD_ONLY;
    }

    @Override
    public final int getConcurrency() {
        return CONCUR_READ_ONLY;
    }

    @Override
    public final int getHoldability() {
        return CLOSE_CURSORS_AT_COMMIT;
    }

    @Override
    public final int getFetchDirection() {
        return FETCH_FORWARD;
    }

    @Override
    public final void setFetchDirection(int direction) throws SQLException {
        // A hint: the rows are where they are, whatever is hinted.
        ResultSetTypes.requireDirection(direction);
    }

    @Override
    public final int getFetchSize() {
        return 0;
    }

    @Override
    public final void setFetchSize(int rows) {
        // Accepted and without effect: the result is already fully present.
    }

    @Override
    public final SQLWarning getWarnings() {
        return null;
    }

    @Override
    public final void clearWarnings() {
        // No warnings are collected, so there is nothing to clear.
    }

    @Override
    public final String getCursorName() throws SQLException {
        throw new SQLFeatureNotSupportedException("seclume has no named cursors");
    }

    protected final void checkOpen() throws SQLException {
        if (closed) {
            throw new SQLException("this result set is closed");
        }
    }

    @Override
    public final <T> T unwrap(Class<T> iface) throws SQLException {
        if (iface.isInstance(this)) {
            return iface.cast(this);
        }
        throw new SQLException("not a wrapper for " + iface.getName());
    }

    @Override
    public final boolean isWrapperFor(Class<?> iface) {
        return iface.isInstance(this);
    }

    // ---- the cursor in any direction, for a scrollable result -----------

    /**
     * Refuses a move for a forward-only result; a scrollable one is whole, so
     * every row number is a position in {@link #rowCount()}.
     */
    private void requireScrollable() throws SQLException {
        checkOpen();
        if (!scrollable) {
            throw new SQLFeatureNotSupportedException("this result set is forward-only - "
                    + "iterate with next(), or ask for TYPE_SCROLL_INSENSITIVE");
        }
    }

    /** Puts the cursor on {@code target} (zero-based), or before or after the rows. */
    private boolean moveCursor(int target) {
        int rows = rowCount();
        if (target < 0) {
            row = -1;
            return false;
        }
        if (target >= rows) {
            row = rows;
            return false;
        }
        row = target;
        moveTo(row);
        return true;
    }

    @Override
    public final boolean previous() throws SQLException {
        requireScrollable();
        return moveCursor(Math.min(row, rowCount()) - 1);
    }

    @Override
    public final void beforeFirst() throws SQLException {
        requireScrollable();
        row = -1;
    }

    @Override
    public final void afterLast() throws SQLException {
        requireScrollable();
        row = rowCount();
    }

    @Override
    public final boolean first() throws SQLException {
        requireScrollable();
        return moveCursor(0);
    }

    @Override
    public final boolean last() throws SQLException {
        requireScrollable();
        return moveCursor(rowCount() - 1);
    }

    /**
     * Row {@code rowNumber}, counted from one; a negative number counts from
     * the end, {@code -1} being the last row. Zero is before the first.
     */
    @Override
    public final boolean absolute(int rowNumber) throws SQLException {
        requireScrollable();
        if (rowNumber == 0) {
            row = -1;
            return false;
        }
        return moveCursor(rowNumber > 0 ? rowNumber - 1 : rowCount() + rowNumber);
    }

    @Override
    public final boolean relative(int rows) throws SQLException {
        requireScrollable();
        long target = (long) row + rows;
        return moveCursor((int) Math.max(-1, Math.min(target, rowCount())));
    }

    // ---- updating - there is none ----------------------------------------

    private static SQLFeatureNotSupportedException readOnly() {
        return new SQLFeatureNotSupportedException(
                "seclume result sets are read-only - change data with an UPDATE statement");
    }

    @Override
    public final boolean rowUpdated() throws SQLException {
        throw readOnly();
    }

    @Override
    public final boolean rowInserted() throws SQLException {
        throw readOnly();
    }

    @Override
    public final boolean rowDeleted() throws SQLException {
        throw readOnly();
    }

    @Override
    public final void insertRow() throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateRow() throws SQLException {
        throw readOnly();
    }

    @Override
    public final void deleteRow() throws SQLException {
        throw readOnly();
    }

    @Override
    public final void refreshRow() throws SQLException {
        throw readOnly();
    }

    @Override
    public final void cancelRowUpdates() throws SQLException {
        throw readOnly();
    }

    @Override
    public final void moveToInsertRow() throws SQLException {
        throw readOnly();
    }

    @Override
    public final void moveToCurrentRow() throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateNull(int columnIndex) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateBoolean(int columnIndex, boolean value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateByte(int columnIndex, byte value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateShort(int columnIndex, short value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateInt(int columnIndex, int value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateLong(int columnIndex, long value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateFloat(int columnIndex, float value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateDouble(int columnIndex, double value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateBigDecimal(int columnIndex, BigDecimal value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateString(int columnIndex, String value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateBytes(int columnIndex, byte[] value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateDate(int columnIndex, Date value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateTime(int columnIndex, Time value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateTimestamp(int columnIndex, Timestamp value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateAsciiStream(int columnIndex, InputStream stream, int length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateBinaryStream(int columnIndex, InputStream stream, int length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateCharacterStream(int columnIndex, Reader reader, int length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateObject(int columnIndex, Object value, int scale) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateObject(int columnIndex, Object value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateNull(String columnLabel) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateBoolean(String columnLabel, boolean value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateByte(String columnLabel, byte value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateShort(String columnLabel, short value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateInt(String columnLabel, int value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateLong(String columnLabel, long value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateFloat(String columnLabel, float value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateDouble(String columnLabel, double value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateBigDecimal(String columnLabel, BigDecimal value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateString(String columnLabel, String value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateBytes(String columnLabel, byte[] value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateDate(String columnLabel, Date value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateTime(String columnLabel, Time value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateTimestamp(String columnLabel, Timestamp value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateAsciiStream(String columnLabel, InputStream stream, int length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateBinaryStream(String columnLabel, InputStream stream, int length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateCharacterStream(String columnLabel, Reader reader, int length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateObject(String columnLabel, Object value, int scale)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateObject(String columnLabel, Object value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateRef(int columnIndex, Ref value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateRef(String columnLabel, Ref value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateBlob(int columnIndex, Blob value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateBlob(String columnLabel, Blob value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateClob(int columnIndex, Clob value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateClob(String columnLabel, Clob value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateArray(int columnIndex, Array value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateArray(String columnLabel, Array value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateRowId(int columnIndex, RowId value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateRowId(String columnLabel, RowId value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateNString(int columnIndex, String value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateNString(String columnLabel, String value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateNClob(int columnIndex, NClob value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateNClob(String columnLabel, NClob value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateSQLXML(int columnIndex, SQLXML value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateSQLXML(String columnLabel, SQLXML value) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateNCharacterStream(int columnIndex, Reader reader, long length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateNCharacterStream(String columnLabel, Reader reader, long length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateAsciiStream(int columnIndex, InputStream stream, long length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateBinaryStream(int columnIndex, InputStream stream, long length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateCharacterStream(int columnIndex, Reader reader, long length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateAsciiStream(String columnLabel, InputStream stream, long length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateBinaryStream(String columnLabel, InputStream stream, long length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateCharacterStream(String columnLabel, Reader reader, long length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateBlob(int columnIndex, InputStream stream, long length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateBlob(String columnLabel, InputStream stream, long length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateClob(int columnIndex, Reader reader, long length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateClob(String columnLabel, Reader reader, long length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateNClob(int columnIndex, Reader reader, long length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateNClob(String columnLabel, Reader reader, long length)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateNCharacterStream(int columnIndex, Reader reader) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateNCharacterStream(String columnLabel, Reader reader)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateAsciiStream(int columnIndex, InputStream stream) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateBinaryStream(int columnIndex, InputStream stream) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateCharacterStream(int columnIndex, Reader reader) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateAsciiStream(String columnLabel, InputStream stream)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateBinaryStream(String columnLabel, InputStream stream)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateCharacterStream(String columnLabel, Reader reader)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateBlob(int columnIndex, InputStream stream) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateBlob(String columnLabel, InputStream stream) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateClob(int columnIndex, Reader reader) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateClob(String columnLabel, Reader reader) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateNClob(int columnIndex, Reader reader) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateNClob(String columnLabel, Reader reader) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateObject(int columnIndex, Object value, SQLType targetSqlType,
                                   int scaleOrLength) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateObject(String columnLabel, Object value, SQLType targetSqlType,
                                   int scaleOrLength) throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateObject(int columnIndex, Object value, SQLType targetSqlType)
            throws SQLException {
        throw readOnly();
    }

    @Override
    public final void updateObject(String columnLabel, Object value, SQLType targetSqlType)
            throws SQLException {
        throw readOnly();
    }

    // ---- types seclume does not return ----------------------------------

    private static SQLFeatureNotSupportedException noSuchType(String type) {
        return new SQLFeatureNotSupportedException(
                "seclume does not return " + type + " values - read the column as a String "
                + "or byte[] instead");
    }

    /** One byte per character, as JDBC defines it - see {@link Lobs#asciiStream}. */
    @Override
    public final InputStream getAsciiStream(int columnIndex) throws SQLException {
        int column = check(columnIndex);
        return lastWasNull ? null : Lobs.asciiStream(stringAt(column));
    }

    @Override
    @Deprecated
    public final InputStream getUnicodeStream(int columnIndex) throws SQLException {
        throw noSuchType("stream");
    }

    @Override
    public final InputStream getBinaryStream(int columnIndex) throws SQLException {
        int column = check(columnIndex);
        return lastWasNull ? null : binaryStreamAt(column);
    }

    @Override
    public final InputStream getAsciiStream(String columnLabel) throws SQLException {
        return getAsciiStream(columnIndexOf(columnLabel) + 1);
    }

    @Override
    @Deprecated
    public final InputStream getUnicodeStream(String columnLabel) throws SQLException {
        throw noSuchType("stream");
    }

    @Override
    public final InputStream getBinaryStream(String columnLabel) throws SQLException {
        return getBinaryStream(columnIndexOf(columnLabel) + 1);
    }

    @Override
    public final Reader getCharacterStream(int columnIndex) throws SQLException {
        int column = check(columnIndex);
        return lastWasNull ? null : readerAt(column);
    }

    @Override
    public final Reader getCharacterStream(String columnLabel) throws SQLException {
        return getCharacterStream(columnIndexOf(columnLabel) + 1);
    }

    @Override
    public final Reader getNCharacterStream(int columnIndex) throws SQLException {
        return getCharacterStream(columnIndex);
    }

    @Override
    public final Reader getNCharacterStream(String columnLabel) throws SQLException {
        return getCharacterStream(columnLabel);
    }

    @Override
    public final String getNString(int columnIndex) throws SQLException {
        return getString(columnIndex);
    }

    @Override
    public final String getNString(String columnLabel) throws SQLException {
        return getString(columnLabel);
    }

    /**
     * With no mapping in it - which is what every caller passes that got its
     * map from {@code Connection.getTypeMap()} - this is {@code getObject}:
     * JDBC says so for an empty map. A mapping is refused, because none of
     * the four has a user-defined type this could map.
     */
    @Override
    public final Object getObject(int columnIndex, Map<String, Class<?>> map)
            throws SQLException {
        if (map == null || map.isEmpty()) {
            return getObject(columnIndex);
        }
        throw noSuchType("custom-mapped");
    }

    @Override
    public final Object getObject(String columnLabel, Map<String, Class<?>> map)
            throws SQLException {
        if (map == null || map.isEmpty()) {
            return getObject(columnLabel);
        }
        throw noSuchType("custom-mapped");
    }

    @Override
    public final Ref getRef(int columnIndex) throws SQLException {
        throw noSuchType("REF");
    }

    @Override
    public final Ref getRef(String columnLabel) throws SQLException {
        throw noSuchType("REF");
    }

    @Override
    public final Blob getBlob(int columnIndex) throws SQLException {
        int column = check(columnIndex);
        return lastWasNull ? null : blobAt(column);
    }

    @Override
    public final Blob getBlob(String columnLabel) throws SQLException {
        return getBlob(columnIndexOf(columnLabel) + 1);
    }

    @Override
    public final Clob getClob(int columnIndex) throws SQLException {
        int column = check(columnIndex);
        return lastWasNull ? null : clobAt(column);
    }

    @Override
    public final Clob getClob(String columnLabel) throws SQLException {
        return getClob(columnIndexOf(columnLabel) + 1);
    }

    /**
     * The national-character variant of {@link #getClob}.
     *
     * <p>None of the four servers hands the driver anything different for an
     * {@code NVARCHAR} than for a {@code VARCHAR} - the text has already been
     * decoded by the time it gets here - so this is the same value under the
     * interface JDBC asks for. Where a driver overrides {@code clobAt} with a
     * real locator, that one has to be an {@code NClob} as well, and it says
     * so if it is not.
     */
    @Override
    public final NClob getNClob(int columnIndex) throws SQLException {
        Clob clob = getClob(columnIndex);
        if (clob == null || clob instanceof NClob national) {
            return (NClob) clob;
        }
        throw new SQLException("this driver's large text values are not national-character "
                + "ones - read the column with getClob or getString");
    }

    @Override
    public final NClob getNClob(String columnLabel) throws SQLException {
        return getNClob(columnIndexOf(columnLabel) + 1);
    }

    @Override
    public final Array getArray(int columnIndex) throws SQLException {
        int column = check(columnIndex);
        return lastWasNull ? null : arrayAt(column);
    }

    @Override
    public final Array getArray(String columnLabel) throws SQLException {
        return getArray(columnIndexOf(columnLabel) + 1);
    }

    @Override
    public final RowId getRowId(int columnIndex) throws SQLException {
        int column = check(columnIndex);
        return lastWasNull ? null : rowIdAt(column);
    }

    @Override
    public final RowId getRowId(String columnLabel) throws SQLException {
        return getRowId(columnIndexOf(columnLabel) + 1);
    }

    @Override
    public final SQLXML getSQLXML(int columnIndex) throws SQLException {
        int column = check(columnIndex);
        return lastWasNull ? null : sqlXmlAt(column);
    }

    @Override
    public final SQLXML getSQLXML(String columnLabel) throws SQLException {
        return getSQLXML(columnIndexOf(columnLabel) + 1);
    }

    /** A text column read as a URL, which is all any of the four stores. */
    @Override
    public final URL getURL(int columnIndex) throws SQLException {
        String value = getString(columnIndex);
        if (value == null) {
            return null;
        }
        try {
            return java.net.URI.create(value).toURL();
        } catch (java.net.MalformedURLException | IllegalArgumentException notAUrl) {
            // Without the JDK's message, which quotes the value back. That
            // value is a row: it can be anything the application stored, and
            // this message goes into a log. The column and the cause are
            // enough to find it; the content is not this exception's to
            // publish.
            throw new SQLException("column " + columnIndex + " does not hold a URL",
                    "22P02", notAUrl);
        }
    }

    @Override
    public final URL getURL(String columnLabel) throws SQLException {
        return getURL(columnIndexOf(columnLabel) + 1);
    }
}
