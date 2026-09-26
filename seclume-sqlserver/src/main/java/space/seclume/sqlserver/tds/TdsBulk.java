package space.seclume.sqlserver.tds;

import java.math.BigDecimal;
import java.sql.SQLException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import space.seclume.internal.WireBuffer;

/**
 * The columns of a bulk load ({@code INSERT BULK}) and how their values go on
 * the wire.
 *
 * <p>An RPC parameter describes itself value by value; a bulk load describes
 * each column once, in a COLMETADATA token, and every row after it has to
 * match. So the types here are fixed per column - taken from the first rows'
 * Java values, the way a parameter's type is taken from its value - and
 * declared to the server in the {@code INSERT BULK} statement. Text goes as
 * {@code nvarchar}, whatever the target column is: the server converts it on
 * the way in, exactly as it converts a parameter, and no code page has to be
 * guessed on this side.
 */
public final class TdsBulk {

    /** The type a column is loaded as. */
    public enum Kind {
        INT, BIGINT, BIT, FLOAT, REAL, DECIMAL, NVARCHAR, NVARCHAR_MAX, VARBINARY,
        VARBINARY_MAX, DATE, TIME, DATETIME2, DATETIMEOFFSET, GUID
    }

    private static final int TOKEN_COLMETADATA = 0x81;
    private static final int TOKEN_ROW = 0xD1;
    private static final int TOKEN_DONE = 0xFD;
    private static final int TVP_ROW = 0x01;
    private static final int TVP_END = 0x00;
    private static final int MAX_NVARCHAR_CHARS = 4000;
    private static final int MAX_VARBINARY_BYTES = 8000;
    private static final int DECIMAL_SIZE = 17;
    private static final int MAX_PRECISION = 38;
    private static final int TIME_SCALE = 7;
    private static final int DAYS_1970 = 719162;

    /**
     * One column: its name, the type it is loaded as, a decimal's scale, and
     * whether the target column takes NULL - a NOT NULL integer, bit or float
     * column has to be described with the fixed-length type, or the server
     * answers "Invalid column type from bcp client".
     */
    public record Column(String name, Kind kind, int scale, boolean nullable) {

        /** Whether the value goes as a fixed-length type, without a length byte. */
        boolean fixed() {
            return !nullable && (kind == Kind.INT || kind == Kind.BIGINT || kind == Kind.BIT
                    || kind == Kind.FLOAT || kind == Kind.REAL);
        }

        /** As it stands in the {@code INSERT BULK} statement. */
        public String declaration() {
            return "[" + name.replace("]", "]]") + "] " + switch (kind) {
                case INT -> "int";
                case BIGINT -> "bigint";
                case BIT -> "bit";
                case FLOAT -> "float";
                case REAL -> "real";
                case DECIMAL -> "decimal(" + MAX_PRECISION + "," + scale + ")";
                case NVARCHAR -> "nvarchar(" + MAX_NVARCHAR_CHARS + ")";
                case NVARCHAR_MAX -> "nvarchar(max)";
                case VARBINARY -> "varbinary(" + MAX_VARBINARY_BYTES + ")";
                case VARBINARY_MAX -> "varbinary(max)";
                case DATE -> "date";
                case TIME -> "time(" + TIME_SCALE + ")";
                case DATETIME2 -> "datetime2(" + TIME_SCALE + ")";
                case DATETIMEOFFSET -> "datetimeoffset(" + TIME_SCALE + ")";
                case GUID -> "uniqueidentifier";
            };
        }
    }

    private TdsBulk() {
    }

    /**
     * The columns for {@code names}, each typed by its first non-null value in
     * {@code sample}; a column with none is text. A decimal column gets the
     * largest scale in the sample, a text or binary column {@code max} when a
     * sampled value needs it.
     */
    public static List<Column> columns(String[] names, List<Object[]> sample,
                                       boolean[] nullable) throws SQLException {
        List<Column> columns = new ArrayList<>(names.length);
        for (int c = 0; c < names.length; c++) {
            Kind kind = null;
            int scale = 0;
            boolean large = false;
            for (Object[] row : sample) {
                Object value = c < row.length ? row[c] : null;
                if (value == null) {
                    continue;
                }
                Kind own = kindOf(value, names[c]);
                if (kind == null) {
                    kind = own;
                } else if (kind == Kind.REAL && own == Kind.FLOAT
                        || kind == Kind.INT && own == Kind.BIGINT) {
                    // The wider of the two, when the sample has both: a double
                    // in a real column would lose half its digits unasked.
                    kind = own;
                }
                if (value instanceof BigDecimal number) {
                    scale = Math.max(scale, Math.max(number.scale(), 0));
                } else if (value instanceof String text && text.length() > MAX_NVARCHAR_CHARS) {
                    large = true;
                } else if (value instanceof byte[] bytes && bytes.length > MAX_VARBINARY_BYTES) {
                    large = true;
                }
            }
            if (kind == null) {
                kind = Kind.NVARCHAR;
            }
            if (large && kind == Kind.NVARCHAR) {
                kind = Kind.NVARCHAR_MAX;
            } else if (large && kind == Kind.VARBINARY) {
                kind = Kind.VARBINARY_MAX;
            }
            if (scale > MAX_PRECISION) {
                throw new SQLException("column " + names[c] + " needs a scale of " + scale
                        + ", SQL Server takes at most " + MAX_PRECISION, "22003");
            }
            columns.add(new Column(names[c], kind, scale, nullable == null || nullable[c]));
        }
        return columns;
    }

    private static Kind kindOf(Object value, String name) throws SQLException {
        return switch (value) {
            case Integer ignored -> Kind.INT;
            case Short ignored -> Kind.INT;
            case Byte ignored -> Kind.INT;
            case Long ignored -> Kind.BIGINT;
            case Boolean ignored -> Kind.BIT;
            case Double ignored -> Kind.FLOAT;
            case Float ignored -> Kind.REAL;
            case BigDecimal ignored -> Kind.DECIMAL;
            case String ignored -> Kind.NVARCHAR;
            case byte[] ignored -> Kind.VARBINARY;
            case LocalDate ignored -> Kind.DATE;
            case java.sql.Date ignored -> Kind.DATE;
            case LocalTime ignored -> Kind.TIME;
            case java.sql.Time ignored -> Kind.TIME;
            case LocalDateTime ignored -> Kind.DATETIME2;
            case java.sql.Timestamp ignored -> Kind.DATETIME2;
            case OffsetDateTime ignored -> Kind.DATETIMEOFFSET;
            case UUID ignored -> Kind.GUID;
            default -> throw new SQLException("column " + name + ": seclume does not bulk-load a "
                    + value.getClass().getName(), "22005");
        };
    }

    /**
     * Refuses a row that the columns cannot carry - before a byte of it is
     * written, because a bulk load cannot be broken off halfway through a
     * message.
     */
    public static void check(List<Column> columns, Object[] row, long number) throws SQLException {
        if (row.length != columns.size()) {
            throw new SQLException("row " + number + " has " + row.length + " values for "
                    + columns.size() + " columns", "22023");
        }
        for (int c = 0; c < row.length; c++) {
            Object value = row[c];
            Column column = columns.get(c);
            if (value == null) {
                if (!column.nullable()) {
                    throw new SQLException("row " + number + ", column " + column.name()
                            + ": NULL into a column that does not take it", "23502");
                }
                continue;
            }
            boolean fits = switch (column.kind()) {
                case INT -> value instanceof Integer || value instanceof Short
                        || value instanceof Byte
                        || value instanceof Long l && l == (int) (long) l;
                case BIGINT -> value instanceof Long || value instanceof Integer
                        || value instanceof Short || value instanceof Byte;
                case BIT -> value instanceof Boolean;
                case FLOAT -> value instanceof Double || value instanceof Float;
                // Only a float: a double would be cut to a float's precision
                // without a word (found in review, 25.09.2026).
                case REAL -> value instanceof Float;
                case DECIMAL -> value instanceof BigDecimal decimal
                        && Math.max(decimal.scale(), 0) <= column.scale()
                        && decimal.precision() - decimal.scale() + column.scale() <= MAX_PRECISION;
                case NVARCHAR -> value instanceof String text
                        && text.length() <= MAX_NVARCHAR_CHARS;
                case NVARCHAR_MAX -> value instanceof String;
                case VARBINARY -> value instanceof byte[] bytes
                        && bytes.length <= MAX_VARBINARY_BYTES;
                case VARBINARY_MAX -> value instanceof byte[];
                case DATE -> value instanceof LocalDate || value instanceof java.sql.Date;
                case TIME -> value instanceof LocalTime || value instanceof java.sql.Time;
                case DATETIME2 -> value instanceof LocalDateTime
                        || value instanceof java.sql.Timestamp;
                case DATETIMEOFFSET -> value instanceof OffsetDateTime;
                case GUID -> value instanceof UUID;
            };
            if (!fits) {
                throw new SQLException("row " + number + ", column " + column.name() + ": "
                        + describe(value) + " does not fit the column's " + column.declaration()
                        + ", which the first rows decided - put a value of the widest kind "
                        + "among the first rows", "22005");
            }
        }
    }

    private static String describe(Object value) {
        if (value instanceof String text) {
            return "a text of " + text.length() + " characters";
        }
        if (value instanceof BigDecimal number) {
            return "the decimal " + number.toPlainString();
        }
        return "a " + value.getClass().getSimpleName();
    }

    /** The COLMETADATA token: every column's type and name, once. */
    static void writeMetadata(WireBuffer out, List<Column> columns) {
        out.putByte((byte) TOKEN_COLMETADATA);
        out.putShortLe((short) columns.size());
        for (Column column : columns) {
            out.putIntLe(0);                          // user type
            out.putShortLe((short) (column.nullable() ? 0x0009 : 0x0008)); // nullable?, updatable
            typeInfo(out, column);
            TdsParameters.putBVarchar(out, column.name());
        }
    }

    private static void typeInfo(WireBuffer out, Column column) {
        if (column.fixed()) {
            out.putByte((byte) switch (column.kind()) {
                case INT -> TdsTypes.INT4;
                case BIGINT -> TdsTypes.INT8;
                case BIT -> TdsTypes.BIT;
                case FLOAT -> TdsTypes.FLT8;
                default -> TdsTypes.FLT4;
            });
            return;
        }
        switch (column.kind()) {
            case INT -> {
                out.putByte((byte) TdsTypes.INTN);
                out.putByte((byte) 4);
            }
            case BIGINT -> {
                out.putByte((byte) TdsTypes.INTN);
                out.putByte((byte) 8);
            }
            case BIT -> {
                out.putByte((byte) TdsTypes.BITN);
                out.putByte((byte) 1);
            }
            case FLOAT -> {
                out.putByte((byte) TdsTypes.FLTN);
                out.putByte((byte) 8);
            }
            case REAL -> {
                out.putByte((byte) TdsTypes.FLTN);
                out.putByte((byte) 4);
            }
            case DECIMAL -> {
                out.putByte((byte) TdsTypes.DECIMALN);
                out.putByte((byte) DECIMAL_SIZE);
                out.putByte((byte) MAX_PRECISION);
                out.putByte((byte) column.scale());
            }
            case NVARCHAR, NVARCHAR_MAX -> {
                out.putByte((byte) TdsTypes.NVARCHAR);
                out.putShortLe((short) (column.kind() == Kind.NVARCHAR
                        ? MAX_NVARCHAR_CHARS * 2 : 0xffff));
                out.putZeroes(5);                     // collation: UTF-16 needs none
            }
            case VARBINARY, VARBINARY_MAX -> {
                out.putByte((byte) TdsTypes.BIGVARBINARY);
                out.putShortLe((short) (column.kind() == Kind.VARBINARY
                        ? MAX_VARBINARY_BYTES : 0xffff));
            }
            case DATE -> out.putByte((byte) TdsTypes.DATEN);
            case TIME -> {
                out.putByte((byte) TdsTypes.TIMEN);
                out.putByte((byte) TIME_SCALE);
            }
            case DATETIME2 -> {
                out.putByte((byte) TdsTypes.DATETIME2N);
                out.putByte((byte) TIME_SCALE);
            }
            case DATETIMEOFFSET -> {
                out.putByte((byte) TdsTypes.DATETIMEOFFSETN);
                out.putByte((byte) TIME_SCALE);
            }
            case GUID -> {
                out.putByte((byte) TdsTypes.GUID);
                out.putByte((byte) 16);
            }
        }
    }

    /** One ROW token - the row has passed {@link #check} already. */
    static void writeRow(WireBuffer out, List<Column> columns, Object[] row) {
        out.putByte((byte) TOKEN_ROW);
        for (int c = 0; c < row.length; c++) {
            value(out, columns.get(c), row[c]);
        }
    }

    /**
     * A table-valued parameter's type info and value: TVP_TYPE_INFO with the
     * type's name, then TVP_COLMETADATA (nameless columns, all nullable), the
     * end token, each row after a row token, and the end token again. With no
     * columns - no rows to take them from - the metadata is the "null" marker,
     * which the server reads as an empty table.
     */
    public static void writeTable(WireBuffer out, String schema, String name,
                                  List<Column> columns, List<Object[]> rows) {
        out.putByte((byte) TdsTypes.TVP);
        TdsParameters.putBVarchar(out, "");           // the database: the current one
        TdsParameters.putBVarchar(out, schema);
        TdsParameters.putBVarchar(out, name);
        if (columns.isEmpty()) {
            out.putShortLe((short) 0xffff);
        } else {
            out.putShortLe((short) columns.size());
            for (Column column : columns) {
                out.putIntLe(0);                      // user type
                out.putShortLe((short) 0x0001);       // nullable
                typeInfo(out, column);
                TdsParameters.putBVarchar(out, "");   // a TVP column has no name here
            }
        }
        out.putByte((byte) TVP_END);                  // no ordering, no defaults
        for (Object[] row : rows) {
            out.putByte((byte) TVP_ROW);
            for (int c = 0; c < row.length; c++) {
                value(out, columns.get(c), row[c]);
            }
        }
        out.putByte((byte) TVP_END);
    }

    /** The DONE token that ends the rows. */
    static void writeDone(WireBuffer out) {
        out.putByte((byte) TOKEN_DONE);
        out.putShortLe((short) 0);
        out.putShortLe((short) 0);
        out.putLongLe(0);
    }

    private static void value(WireBuffer out, Column column, Object value) {
        Kind kind = column.kind();
        if (value == null) {
            switch (kind) {
                case NVARCHAR, VARBINARY -> out.putShortLe((short) 0xffff);
                case NVARCHAR_MAX, VARBINARY_MAX -> out.putLongLe(-1L);
                default -> out.putByte((byte) 0);
            }
            return;
        }
        boolean fixed = column.fixed();
        switch (kind) {
            case INT -> {
                if (!fixed) {
                    out.putByte((byte) 4);
                }
                out.putIntLe(((Number) value).intValue());
            }
            case BIGINT -> {
                if (!fixed) {
                    out.putByte((byte) 8);
                }
                out.putLongLe(((Number) value).longValue());
            }
            case BIT -> {
                if (!fixed) {
                    out.putByte((byte) 1);
                }
                out.putByte((byte) (((Boolean) value) ? 1 : 0));
            }
            case FLOAT -> {
                if (!fixed) {
                    out.putByte((byte) 8);
                }
                out.putLongLe(Double.doubleToLongBits(((Number) value).doubleValue()));
            }
            case REAL -> {
                if (!fixed) {
                    out.putByte((byte) 4);
                }
                out.putIntLe(Float.floatToIntBits(((Number) value).floatValue()));
            }
            case DECIMAL -> decimal(out, (BigDecimal) value, column.scale());
            case NVARCHAR -> {
                String text = (String) value;
                out.putShortLe((short) (text.length() * 2));
                TdsParameters.putUtf16(out, text);
            }
            case NVARCHAR_MAX -> {
                String text = (String) value;
                out.putLongLe((long) text.length() * 2);
                if (!text.isEmpty()) {
                    out.putIntLe(text.length() * 2);
                    TdsParameters.putUtf16(out, text);
                }
                out.putIntLe(0);
            }
            case VARBINARY -> {
                byte[] bytes = (byte[]) value;
                out.putShortLe((short) bytes.length);
                out.putBytes(java.lang.foreign.MemorySegment.ofArray(bytes), 0, bytes.length);
            }
            case VARBINARY_MAX -> {
                byte[] bytes = (byte[]) value;
                out.putLongLe(bytes.length);
                if (bytes.length > 0) {
                    out.putIntLe(bytes.length);
                    out.putBytes(java.lang.foreign.MemorySegment.ofArray(bytes), 0, bytes.length);
                }
                out.putIntLe(0);
            }
            case DATE -> {
                LocalDate date = value instanceof java.sql.Date sql ? sql.toLocalDate()
                        : (LocalDate) value;
                out.putByte((byte) 3);
                out.putUnsignedLe(date.toEpochDay() + DAYS_1970, 3);
            }
            case TIME -> {
                LocalTime time = value instanceof java.sql.Time sql ? sql.toLocalTime()
                        : (LocalTime) value;
                out.putByte((byte) 5);
                out.putUnsignedLe(time.toNanoOfDay() / 100, 5);
            }
            case DATETIME2 -> {
                LocalDateTime stamp = value instanceof java.sql.Timestamp sql
                        ? sql.toLocalDateTime() : (LocalDateTime) value;
                out.putByte((byte) 8);
                out.putUnsignedLe(stamp.toLocalTime().toNanoOfDay() / 100, 5);
                out.putUnsignedLe(stamp.toLocalDate().toEpochDay() + DAYS_1970, 3);
            }
            case DATETIMEOFFSET -> {
                OffsetDateTime stamp = (OffsetDateTime) value;
                LocalDateTime utc = stamp.withOffsetSameInstant(java.time.ZoneOffset.UTC)
                        .toLocalDateTime();
                out.putByte((byte) 10);
                out.putUnsignedLe(utc.toLocalTime().toNanoOfDay() / 100, 5);
                out.putUnsignedLe(utc.toLocalDate().toEpochDay() + DAYS_1970, 3);
                out.putUnsignedLe(stamp.getOffset().getTotalSeconds() / 60, 2);
            }
            case GUID -> {
                UUID id = (UUID) value;
                out.putByte((byte) 16);
                long high = id.getMostSignificantBits();
                long low = id.getLeastSignificantBits();
                out.putIntLe((int) (high >>> 32));
                out.putShortLe((short) (high >>> 16));
                out.putShortLe((short) high);
                for (int shift = 56; shift >= 0; shift -= 8) {
                    out.putByte((byte) (low >>> shift));
                }
            }
        }
    }

    /** A decimal at the column's scale: sign byte and sixteen bytes of magnitude. */
    private static void decimal(WireBuffer out, BigDecimal number, int scale) {
        String digits = number.setScale(scale, java.math.RoundingMode.UNNECESSARY)
                .abs().toPlainString().replace(".", "");
        int[] limbs = new int[4]; // seclume-allow: a bulk value, user payload and never a secret
        for (int i = 0; i < digits.length(); i++) {
            long carry = digits.charAt(i) - '0';
            for (int l = 0; l < limbs.length; l++) {
                long product = (limbs[l] & 0xffffffffL) * 10 + carry;
                limbs[l] = (int) product;
                carry = product >>> 32;
            }
        }
        out.putByte((byte) DECIMAL_SIZE);
        out.putByte((byte) (number.signum() < 0 ? 0 : 1));
        for (int limb : limbs) {
            out.putUnsignedLe(limb & 0xffffffffL, 4);
        }
    }
}
