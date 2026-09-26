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
 * @param charset  the character set, 873 = AL32UTF8, 2000 = AL16UTF16 (the
 *                 national one, which is what an NVARCHAR2 arrives in); 0 for
 *                 types without one
 * @param nullable whether the column may hold NULL
 * @param inline   whether the value comes in the row itself, because the
 *                 cursor was given a define asking for it - see
 *                 {@link #needsDefine}
 */
public record OracleColumn(String name, int type, int precision, int scale,
                           int bufferSize, int maxSize, int charset, boolean nullable,
                           String objectType, boolean inline) {

    /** A column of a built-in type - no object type name. */
    public OracleColumn(String name, int type, int precision, int scale, int bufferSize,
            int maxSize, int charset, boolean nullable) {
        this(name, type, precision, scale, bufferSize, maxSize, charset, nullable, "", false);
    }

    /** As described, the value not yet asked for inline. */
    public OracleColumn(String name, int type, int precision, int scale, int bufferSize,
            int maxSize, int charset, boolean nullable, String objectType) {
        this(name, type, precision, scale, bufferSize, maxSize, charset, nullable, objectType,
                false);
    }

    /**
     * Whether this column's values are LOBs that live only as long as the
     * fetch that brought them - JSON and VECTOR.
     *
     * <p>Their locators are not the handle to a stored LOB that a BLOB's is,
     * but to a value made for this fetch: read after the next one, they
     * answer ORA-24826. And each read is a round trip of its own. So a cursor
     * with such a column is given a define that asks for the value in the
     * row, and neither happens.
     */
    public boolean needsDefine() {
        return type == TYPE_JSON || type == TYPE_VECTOR;
    }

    /** The same column, its value asked for in the row. */
    public OracleColumn withInline() {
        return new OracleColumn(name, type, precision, scale, bufferSize, maxSize, charset,
                nullable, objectType, needsDefine());
    }

    /**
     * An object - a user-defined type, or one of Oracle's own such as
     * {@code XMLType}. What it is is in {@link #objectType()}, as
     * {@code SCHEMA.NAME}; the value is a pickled image, see
     * {@code TtcRow.readObject}.
     */
    public static final int TYPE_OBJECT = 109;

    /** Whether this is Oracle's {@code XMLType}, the one object this driver reads. */
    public boolean isXml() {
        return type == TYPE_OBJECT && objectType.endsWith("XMLTYPE");
    }

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

    /**
     * {@code ROWID} - the address of a row. Not a length-prefixed value on the
     * wire but five numbers of the protocol's own variable width; see
     * {@code TtcRow.readRowid} and {@link OracleRowid}.
     */
    public static final int TYPE_ROWID = 11;

    /**
     * {@code UROWID} - a row address as raw bytes, physical or the key of a
     * row in an index-organized table; see {@link OracleRowid#fromUrowid}.
     */
    public static final int TYPE_UROWID = 208;

    /** {@code BFILE} - a locator naming a file on the server; framed, not read. */
    public static final int TYPE_BFILE = 114;

    /** {@code INTERVAL YEAR TO MONTH}: four bytes of years, one of months. */
    public static final int TYPE_INTERVAL_YM = 182;

    /** {@code INTERVAL DAY TO SECOND}: days, hours, minutes, seconds, nanoseconds. */
    public static final int TYPE_INTERVAL_DS = 183;

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
     * {@code JSON}, Oracle's native type since 21c - a LOB locator on the
     * wire like a BLOB, and what it holds is OSON, not text. See
     * {@link OracleJson}.
     */
    public static final int TYPE_JSON = 119;

    /**
     * {@code VECTOR} (23ai) - a LOB locator on the wire like JSON, and what it
     * holds is a vector image; see {@link OracleVector}.
     */
    public static final int TYPE_VECTOR = 127;

    /**
     * A cursor - what a PL/SQL {@code SYS_REFCURSOR} parameter is on the wire.
     *
     * <p>Not a value type: what comes back in the bind is the number of a
     * cursor the server has opened, and the rows are fetched from it
     * afterwards exactly like the rows of a query.
     */
    public static final int TYPE_CURSOR = 102;

    /**
     * Whether the column carries a locator instead of its contents.
     *
     * <p>The distinction matters twice over: the row is laid out differently,
     * and getting at the value costs a round trip of its own.
     */
    public static boolean isLob(int type) {
        return type == TYPE_CLOB || type == TYPE_BLOB || type == TYPE_JSON
                || type == TYPE_VECTOR;
    }

    /** A scale of -127 means "no scale was declared", not "no decimals". */
    public static final int SCALE_UNDECLARED = -127;

    /** Oracle's national character set, AL16UTF16 - what an NVARCHAR2 is in. */
    public static final int AL16UTF16 = 2000;

    /** Whether this column is one of the national character types. */
    public boolean isNational() {
        return charset == AL16UTF16;
    }

    /**
     * The matching {@link java.sql.Types} value.
     *
     * <p>A {@code NUMBER} is {@code NUMERIC} whatever its precision and
     * scale, as ojdbc reports it. A guess at {@code INTEGER} for a
     * {@code NUMBER(9)} is not what code written against ojdbc sees, and
     * getObject hands out a BigDecimal either way.
     */
    public int sqlType() {
        return switch (type) {
            case TYPE_NUMBER -> java.sql.Types.NUMERIC;
            // Oracle sends the same wire type for varchar2 and nvarchar2;
            // only the character set tells them apart. Reporting both as
            // VARCHAR lost the distinction a national column exists for.
            case TYPE_VARCHAR -> isNational()
                    ? java.sql.Types.NVARCHAR : java.sql.Types.VARCHAR;
            case TYPE_CHAR -> isNational() ? java.sql.Types.NCHAR : java.sql.Types.CHAR;
            case TYPE_DATE -> java.sql.Types.TIMESTAMP;
            case TYPE_TIMESTAMP -> java.sql.Types.TIMESTAMP;
            case TYPE_TIMESTAMP_ZONE -> java.sql.Types.TIMESTAMP_WITH_TIMEZONE;
            // Read in the session's zone, it is a timestamp without one.
            case TYPE_TIMESTAMP_LOCAL ->
                    java.sql.Types.TIMESTAMP;
            case TYPE_RAW -> java.sql.Types.VARBINARY;
            case TYPE_BOOLEAN -> java.sql.Types.BOOLEAN;
            case TYPE_BINARY_FLOAT -> java.sql.Types.REAL;
            case TYPE_BINARY_DOUBLE -> java.sql.Types.DOUBLE;
            case TYPE_LONG -> java.sql.Types.LONGVARCHAR;
            case TYPE_LONG_RAW -> java.sql.Types.LONGVARBINARY;
            case TYPE_CLOB -> isNational() ? java.sql.Types.NCLOB : java.sql.Types.CLOB;
            case TYPE_BLOB -> java.sql.Types.BLOB;
            case TYPE_ROWID, TYPE_UROWID -> java.sql.Types.ROWID;
            case TYPE_OBJECT -> isXml() ? java.sql.Types.SQLXML : java.sql.Types.STRUCT;
            default -> java.sql.Types.OTHER;
        };
    }

    /** The type name as Oracle writes it. */
    public String typeName() {
        return switch (type) {
            case TYPE_NUMBER -> "NUMBER";
            case TYPE_VARCHAR -> isNational() ? "NVARCHAR2" : "VARCHAR2";
            case TYPE_CHAR -> isNational() ? "NCHAR" : "CHAR";
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
            case TYPE_CLOB -> isNational() ? "NCLOB" : "CLOB";
            case TYPE_BLOB -> "BLOB";
            case TYPE_ROWID -> "ROWID";
            // ojdbc says ROWID for both, and so does getColumnType
            case TYPE_UROWID -> "ROWID";
            case TYPE_BFILE -> "BFILE";
            case TYPE_INTERVAL_YM -> "INTERVALYM";
            case TYPE_INTERVAL_DS -> "INTERVALDS";
            case TYPE_OBJECT -> objectType;
            case TYPE_JSON -> "JSON";
            case TYPE_VECTOR -> "VECTOR";
            default -> "UNKNOWN(" + type + ")";
        };
    }

    /** Whether the values arrive as text rather than as bytes or numbers. */
    public boolean isText() {
        return type == TYPE_VARCHAR || type == TYPE_CHAR;
    }
}
