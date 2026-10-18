package space.seclume.r2dbc;

import java.math.BigDecimal;
import java.math.BigInteger; // seclume-allow: an application value R2DBC may bind, not a credential
import java.nio.ByteBuffer;
import java.sql.Types;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.time.OffsetTime;
import java.time.ZonedDateTime;
import java.util.UUID;

/** What R2DBC binds, as JDBC takes it. */
final class SqlTypes {

    private SqlTypes() {
    }

    /** The {@code java.sql.Types} for a null bound with this Java type. */
    static int of(Class<?> type) {
        if (type == String.class || type == Character.class || type == UUID.class) {
            return Types.VARCHAR;
        }
        if (type == Integer.class || type == int.class) {
            return Types.INTEGER;
        }
        if (type == Long.class || type == long.class || type == BigInteger.class) { // seclume-allow: a bound value's type
            return Types.BIGINT;
        }
        if (type == Short.class || type == short.class) {
            return Types.SMALLINT;
        }
        if (type == Byte.class || type == byte.class) {
            return Types.TINYINT;
        }
        if (type == Boolean.class || type == boolean.class) {
            return Types.BOOLEAN;
        }
        if (type == Double.class || type == double.class) {
            return Types.DOUBLE;
        }
        if (type == Float.class || type == float.class) {
            return Types.REAL;
        }
        if (type == BigDecimal.class) {
            return Types.NUMERIC;
        }
        if (type == LocalDate.class) {
            return Types.DATE;
        }
        if (type == LocalTime.class) {
            return Types.TIME;
        }
        if (type == OffsetTime.class) {
            return Types.TIME_WITH_TIMEZONE;
        }
        if (type == LocalDateTime.class) {
            return Types.TIMESTAMP;
        }
        if (type == OffsetDateTime.class || type == ZonedDateTime.class || type == Instant.class) {
            return Types.TIMESTAMP_WITH_TIMEZONE;
        }
        if (type == byte[].class || type == ByteBuffer.class) {
            return Types.VARBINARY;
        }
        return Types.OTHER;
    }

    /** Whether a value is of a type this binds - a Class, a Thread or the like is a mistake. */
    static boolean bindable(Object value) {
        return value instanceof CharSequence || value instanceof Number
                || value instanceof Boolean || value instanceof Character
                || value instanceof byte[] || value instanceof ByteBuffer
                || value instanceof UUID || value instanceof java.time.temporal.Temporal
                || value instanceof io.r2dbc.spi.Blob || value instanceof io.r2dbc.spi.Clob
                || value instanceof Enum<?> || value.getClass().isArray();
    }

    /** A bound value in the form JDBC's setObject takes. */
    static Object jdbcValue(Object value) {
        if (value instanceof io.r2dbc.spi.Blob blob) {
            java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
            reactor.core.publisher.Flux.from(blob.stream()).doOnNext(chunk -> {
                byte[] part = new byte[chunk.remaining()];
                chunk.duplicate().get(part);
                bytes.writeBytes(part);
            }).blockLast();
            return bytes.toByteArray();
        }
        if (value instanceof io.r2dbc.spi.Clob clob) {
            StringBuilder text = new StringBuilder();
            reactor.core.publisher.Flux.from(clob.stream()).doOnNext(text::append).blockLast();
            return text.toString();
        }
        if (value instanceof Enum<?> constant) {
            return constant.name();
        }
        if (value instanceof ByteBuffer buffer) {
            ByteBuffer copy = buffer.duplicate();
            byte[] bytes = new byte[copy.remaining()];
            copy.get(bytes);
            return bytes;
        }
        if (value instanceof Instant instant) {
            return instant.atOffset(java.time.ZoneOffset.UTC);
        }
        if (value instanceof ZonedDateTime zoned) {
            return zoned.toOffsetDateTime();
        }
        if (value instanceof BigInteger big) { // seclume-allow: an application value, bound as a decimal
            return new BigDecimal(big);
        }
        return value;
    }
}
