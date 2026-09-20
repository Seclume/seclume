package space.seclume.oracle.net;

/**
 * One column of a result, as {@code DESCRIBE_INFO} describes it.
 *
 * @param name     the column name as the server spells it - upper case unless
 *                 it was quoted when the table was made
 * @param type     Oracle's own type number: 2 = NUMBER, 96 = CHAR, 1 = VARCHAR
 * @param precision the digit count, 0 when none was declared
 * @param scale    the decimal places; <b>-127</b> means a NUMBER without a
 *                 declared scale, which is not the same as scale 0 and is the
 *                 usual case for a computed value
 * @param bufferSize how many bytes a value takes at most on the wire;
 *                   <b>zero means the column carries no bytes at all</b>,
 *                   which is how an untyped {@code null} in the select list is
 *                   described
 * @param maxSize  the declared size
 * @param charset  the character set, 873 = AL32UTF8; 0 for types without one
 * @param nullable whether the column may hold NULL
 */
public record OracleColumn(String name, int type, int precision, int scale,
                           int bufferSize, int maxSize, int charset, boolean nullable) {

    /** Oracle's type number for {@code NUMBER}. */
    public static final int TYPE_NUMBER = 2;
    /** {@code VARCHAR2}. */
    public static final int TYPE_VARCHAR = 1;
    /** {@code CHAR} - a text literal in a query is one of these, not a VARCHAR. */
    public static final int TYPE_CHAR = 96;
    /** {@code DATE}. */
    public static final int TYPE_DATE = 12;
    /** {@code RAW}. */
    public static final int TYPE_RAW = 23;

    /** {@code TIMESTAMP}. */
    public static final int TYPE_TIMESTAMP = 180;

    /** {@code TIMESTAMP WITH TIME ZONE}. */
    public static final int TYPE_TIMESTAMP_ZONE = 181;

    /** {@code TIMESTAMP WITH LOCAL TIME ZONE}. */
    public static final int TYPE_TIMESTAMP_LOCAL = 231;

    /**
     * {@code BINARY_FLOAT} and {@code BINARY_DOUBLE} - IEEE 754, not Oracle's
     * own number format.
     *
     * <p>Hibernate maps a Java {@code double} to {@code binary_double}, so
     * every entity with one in it goes through these. The bytes are
     * transformed so that they sort as numbers do - see
     * {@code OracleFloat}.
     */
    public static final int TYPE_BINARY_FLOAT = 100;
    /** See {@link #TYPE_BINARY_FLOAT}. */
    public static final int TYPE_BINARY_DOUBLE = 101;

    /**
     * {@code BOOLEAN}, which Oracle has had since 23ai.
     *
     * <p>The type number is 252, and the
     * value is one byte per boolean - {@code 01} for true and {@code 00} for
     * false, with true arriving as two bytes where the second repeats the
     * first. Anything non-zero in the first byte is true, which is the
     * reading that survives both shapes.
     */
    public static final int TYPE_BOOLEAN = 252;

    /** {@code LONG} - text without a length limit, sent in chunks. */
    public static final int TYPE_LONG = 8;

    /** {@code LONG RAW} - the same for bytes. */
    public static final int TYPE_LONG_RAW = 24;

    /** {@code CLOB} - text that travels as a locator, not as a value. */
    public static final int TYPE_CLOB = 112;

    /** {@code BLOB} - the same for bytes. */
    public static final int TYPE_BLOB = 113;

    /**
     * Whether the column carries a locator instead of its contents.
     *
     * <p>The distinction matters twice over: the row is laid out differently,
     * and getting at the value costs a round trip of its own.
     */
    public static boolean isLob(int type) {
        return type == TYPE_CLOB || type == TYPE_BLOB;
    }

    /** A scale of -127 means "no scale was declared", not "no decimals". */
    public static final int SCALE_UNDECLARED = -127;

    /**
     * The matching {@link java.sql.Types} value.
     *
     * <p>A {@code NUMBER} is the awkward one: Oracle has a single numeric type
     * for everything, and what a caller wants back depends on its scale. A
     * scale of -127 means none was declared - a computed value - and there
     * {@code NUMERIC} is the honest answer rather than a guess at
     * {@code INTEGER}.
     */
    public int sqlType() {
        return switch (type) {
            case TYPE_NUMBER -> scale == 0 && precision > 0 && precision <= 9
                    ? java.sql.Types.INTEGER
                    : java.sql.Types.NUMERIC;
            case TYPE_VARCHAR -> java.sql.Types.VARCHAR;
            case TYPE_CHAR -> java.sql.Types.CHAR;
            case TYPE_DATE -> java.sql.Types.TIMESTAMP;
            case TYPE_TIMESTAMP -> java.sql.Types.TIMESTAMP;
            case TYPE_TIMESTAMP_ZONE, TYPE_TIMESTAMP_LOCAL ->
                    java.sql.Types.TIMESTAMP_WITH_TIMEZONE;
            case TYPE_RAW -> java.sql.Types.VARBINARY;
            case TYPE_BOOLEAN -> java.sql.Types.BOOLEAN;
            case TYPE_BINARY_FLOAT -> java.sql.Types.REAL;
            case TYPE_BINARY_DOUBLE -> java.sql.Types.DOUBLE;
            case TYPE_LONG -> java.sql.Types.LONGVARCHAR;
            case TYPE_LONG_RAW -> java.sql.Types.LONGVARBINARY;
            case TYPE_CLOB -> java.sql.Types.CLOB;
            case TYPE_BLOB -> java.sql.Types.BLOB;
            default -> java.sql.Types.OTHER;
        };
    }

    /** The type name as Oracle writes it. */
    public String typeName() {
        return switch (type) {
            case TYPE_NUMBER -> "NUMBER";
            case TYPE_VARCHAR -> "VARCHAR2";
            case TYPE_CHAR -> "CHAR";
            case TYPE_DATE -> "DATE";
            case TYPE_TIMESTAMP -> "TIMESTAMP";
            case TYPE_TIMESTAMP_ZONE -> "TIMESTAMP WITH TIME ZONE";
            case TYPE_TIMESTAMP_LOCAL -> "TIMESTAMP WITH LOCAL TIME ZONE";
            case TYPE_RAW -> "RAW";
            case TYPE_BOOLEAN -> "BOOLEAN";
            case TYPE_BINARY_FLOAT -> "BINARY_FLOAT";
            case TYPE_BINARY_DOUBLE -> "BINARY_DOUBLE";
            case TYPE_LONG -> "LONG";
            case TYPE_LONG_RAW -> "LONG RAW";
            case TYPE_CLOB -> "CLOB";
            case TYPE_BLOB -> "BLOB";
            default -> "UNKNOWN(" + type + ")";
        };
    }

    /** Whether the values arrive as text rather than as bytes or numbers. */
    public boolean isText() {
        return type == TYPE_VARCHAR || type == TYPE_CHAR;
    }
}
