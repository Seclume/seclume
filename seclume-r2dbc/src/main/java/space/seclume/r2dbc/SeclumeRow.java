package space.seclume.r2dbc;

import java.nio.ByteBuffer;
import java.sql.ResultSet;
import java.sql.SQLException;

import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;

/**
 * The row the result is on - valid while the mapping function runs, as R2DBC
 * says a row is, and read straight from the JDBC result set underneath, not
 * copied.
 *
 * <p>Values come as R2DBC drivers hand them out: {@code java.time} for dates
 * and times rather than {@code java.sql.Timestamp}, {@code ByteBuffer} for
 * bytes when asked for one. Indexes are R2DBC's, from 0.
 */
final class SeclumeRow implements Row {

    private final ResultSet rows;
    private final SeclumeRowMetadata metadata;

    SeclumeRow(ResultSet rows, SeclumeRowMetadata metadata) {
        this.rows = rows;
        this.metadata = metadata;
    }

    @Override
    public RowMetadata getMetadata() {
        return metadata;
    }

    @Override
    public <T> T get(int index, Class<T> type) {
        if (index < 0 || index >= metadata.size()) {
            throw new IndexOutOfBoundsException("column " + index + " of "
                    + metadata.size() + " (R2DBC counts from 0)");
        }
        return read(index + 1, type);
    }

    @Override
    public <T> T get(String name, Class<T> type) {
        return read(metadata.indexOf(name) + 1, type);
    }

    private <T> T read(int column, Class<T> type) {
        try {
            Object value;
            if (type == Object.class) {
                value = natural(rows.getObject(column));
            } else if (type == ByteBuffer.class) {
                byte[] bytes = rows.getBytes(column); // seclume-allow: a column's value as the application asked for it, not a credential
                value = bytes == null ? null : ByteBuffer.wrap(bytes);
            } else if (type == io.r2dbc.spi.Blob.class) {
                byte[] bytes = rows.getBytes(column); // seclume-allow: a column's value as the application asked for it, not a credential
                value = bytes == null ? null
                        : io.r2dbc.spi.Blob.from(reactor.core.publisher.Mono.just(ByteBuffer.wrap(bytes)));
            } else if (type == io.r2dbc.spi.Clob.class) {
                String text = rows.getString(column);
                value = text == null ? null
                        : io.r2dbc.spi.Clob.from(reactor.core.publisher.Mono.just(text));
            } else if (type.isInterface()
                    || java.lang.reflect.Modifier.isAbstract(type.getModifiers())) {
                // Number, CharSequence, Temporal...: the value as it comes,
                // if it is one - what R2DBC drivers answer for a supertype.
                Object natural = natural(rows.getObject(column));
                if (natural != null && !type.isInstance(natural)) {
                    throw new IllegalArgumentException("column " + column + " is a "
                            + natural.getClass().getName() + ", not a " + type.getName());
                }
                value = natural;
            } else {
                value = rows.getObject(column, boxed(type));
            }
            @SuppressWarnings("unchecked")
            T typed = (T) value;
            return typed;
        } catch (SQLException e) {
            throw (RuntimeException) Errors.translate(e);
        }
    }

    /** {@code int.class} as {@code Integer.class} and so on: JDBC's getObject takes no primitive. */
    private static Class<?> boxed(Class<?> type) {
        if (!type.isPrimitive()) {
            return type;
        }
        return java.lang.invoke.MethodType.methodType(type).wrap().returnType();
    }

    /** JDBC's object for a column as R2DBC's: java.time where JDBC still has java.sql. */
    static Object natural(Object value) throws java.sql.SQLException {
        if (value instanceof byte[] bytes) {
            return ByteBuffer.wrap(bytes);
        }
        // A LOB as R2DBC hands one out without being asked for a type: its
        // value, as with the byte and text columns - Oracle's getObject
        // answers with the JDBC LOB, which no R2DBC caller expects.
        if (value instanceof java.sql.Blob blob) {
            try {
                long length = blob.length();
                // seclume-allow: a BLOB column's value as R2DBC hands it out, not a credential
                return ByteBuffer.wrap(blob.getBytes(1, (int) Math.min(length, Integer.MAX_VALUE)));
            } finally {
                blob.free();
            }
        }
        if (value instanceof java.sql.Clob clob) {
            try {
                long length = clob.length();
                return clob.getSubString(1, (int) Math.min(length, Integer.MAX_VALUE));
            } finally {
                clob.free();
            }
        }
        if (value instanceof java.sql.Timestamp timestamp) {
            return timestamp.toLocalDateTime();
        }
        if (value instanceof java.sql.Date date) {
            return date.toLocalDate();
        }
        if (value instanceof java.sql.Time time) {
            return time.toLocalTime();
        }
        return value;
    }
}
