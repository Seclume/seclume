package space.seclume.postgresql.jdbc;

import java.sql.Types;

/**
 * The type numbers PostgreSQL sends in the {@code RowDescription}.
 *
 * <p>The values live in the server's {@code pg_type} and have been hard-wired
 * for decades; keeping them here as constants is not a cache but the
 * translation of the protocol. Anything not listed is treated as text - which
 * is always right with PostgreSQL, because every type has a text
 * representation, and it is more honest than guessing at a binary form.
 */
public final class PgOids {

    public static final int BOOL = 16;
    public static final int BYTEA = 17;
    public static final int CHAR = 18;
    public static final int NAME = 19;
    public static final int INT8 = 20;
    public static final int INT2 = 21;
    public static final int INT4 = 23;
    public static final int TEXT = 25;
    public static final int OID = 26;
    public static final int JSON = 114;
    public static final int XML = 142;
    public static final int FLOAT4 = 700;
    public static final int FLOAT8 = 701;
    public static final int BPCHAR = 1042;
    public static final int VARCHAR = 1043;
    public static final int DATE = 1082;
    public static final int TIME = 1083;
    public static final int TIMESTAMP = 1114;
    public static final int TIMESTAMPTZ = 1184;
    public static final int INTERVAL = 1186;
    public static final int TIMETZ = 1266;
    public static final int NUMERIC = 1700;
    public static final int UUID = 2950;
    public static final int JSONB = 3802;

    private PgOids() {
    }

    /** The matching {@link Types} value JDBC callers expect. */
    public static int sqlType(int oid) {
        return switch (oid) {
            case BOOL -> Types.BOOLEAN;
            case BYTEA -> Types.BINARY;
            case CHAR, BPCHAR -> Types.CHAR;
            case INT2 -> Types.SMALLINT;
            case INT4, OID -> Types.INTEGER;
            case INT8 -> Types.BIGINT;
            case FLOAT4 -> Types.REAL;
            case FLOAT8 -> Types.DOUBLE;
            case NUMERIC -> Types.NUMERIC;
            case DATE -> Types.DATE;
            case TIME, TIMETZ -> Types.TIME;
            case TIMESTAMP -> Types.TIMESTAMP;
            case TIMESTAMPTZ -> Types.TIMESTAMP_WITH_TIMEZONE;
            case VARCHAR, NAME, TEXT -> Types.VARCHAR;
            case XML -> Types.SQLXML;
            case JSON, JSONB -> Types.OTHER;
            case UUID -> Types.OTHER;
            default -> Types.OTHER;
        };
    }

    /** The name of the type, the way the server itself writes it. */
    public static String typeName(int oid) {
        return switch (oid) {
            case BOOL -> "bool";
            case BYTEA -> "bytea";
            case CHAR -> "char";
            case NAME -> "name";
            case INT8 -> "int8";
            case INT2 -> "int2";
            case INT4 -> "int4";
            case TEXT -> "text";
            case OID -> "oid";
            case JSON -> "json";
            case XML -> "xml";
            case FLOAT4 -> "float4";
            case FLOAT8 -> "float8";
            case BPCHAR -> "bpchar";
            case VARCHAR -> "varchar";
            case DATE -> "date";
            case TIME -> "time";
            case TIMESTAMP -> "timestamp";
            case TIMESTAMPTZ -> "timestamptz";
            case INTERVAL -> "interval";
            case TIMETZ -> "timetz";
            case NUMERIC -> "numeric";
            case UUID -> "uuid";
            case JSONB -> "jsonb";
            default -> "oid" + oid;
        };
    }

    /**
     * The class {@code getObject} returns for this type.
     *
     * <p>Has to match {@code PgResultSet.getObject} - the two together are the
     * contract an ORM asks for and then believes.
     */
    public static String javaClass(int oid) {
        return switch (oid) {
            case BOOL -> "java.lang.Boolean";
            case BYTEA -> "[B";
            case INT2 -> "java.lang.Short";
            case INT4, OID -> "java.lang.Integer";
            case INT8 -> "java.lang.Long";
            case FLOAT4 -> "java.lang.Float";
            case FLOAT8 -> "java.lang.Double";
            case NUMERIC -> "java.math.BigDecimal";
            case DATE -> "java.sql.Date";
            case TIME, TIMETZ -> "java.sql.Time";
            case TIMESTAMP, TIMESTAMPTZ -> "java.sql.Timestamp";
            case UUID -> "java.util.UUID";
            default -> "java.lang.String";
        };
    }

    /** Display width and precision, as far as the type fixes them. */
    public static int precision(int oid, int typeModifier) {
        return switch (oid) {
            case BOOL -> 1;
            case INT2 -> 5;
            case INT4, OID -> 10;
            case INT8 -> 19;
            case FLOAT4 -> 8;
            case FLOAT8 -> 17;
            // With numeric(p,s), p sits in the upper 16 bits of atttypmod - 4.
            case NUMERIC -> typeModifier < 0 ? 0 : ((typeModifier - 4) >> 16) & 0xffff;
            // With varchar(n)/bpchar(n), atttypmod is the length plus 4.
            case VARCHAR, BPCHAR -> typeModifier < 0 ? 0 : typeModifier - 4;
            case DATE -> 13;
            case TIME, TIMETZ -> 15;
            case TIMESTAMP, TIMESTAMPTZ -> 29;
            case UUID -> 36;
            default -> 0;
        };
    }

    /** Decimal places; only {@code numeric} and the time types have any. */
    public static int scale(int oid, int typeModifier) {
        return switch (oid) {
            case NUMERIC -> typeModifier < 0 ? 0 : (typeModifier - 4) & 0xffff;
            case TIME, TIMETZ, TIMESTAMP, TIMESTAMPTZ -> typeModifier < 0 ? 6 : typeModifier;
            default -> 0;
        };
    }

    /** Whether comparison and ordering treat this type as signed. */
    public static boolean isSigned(int oid) {
        return switch (oid) {
            case INT2, INT4, INT8, FLOAT4, FLOAT8, NUMERIC -> true;
            default -> false;
        };
    }
}
