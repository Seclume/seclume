package space.seclume.internal.jdbc;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.Writer;
import java.sql.Blob;
import java.sql.NClob;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;

/**
 * A {@code Clob} or {@code Blob} over a value that has already arrived.
 *
 * <p>These used to be refused, with an honest reason: a {@code Clob} promises
 * that a value can be read in pieces and need not fit in memory, and a driver
 * whose rows arrive whole cannot keep that promise. The reason was right and
 * the conclusion was wrong. Hibernate reads a {@code @Lob} column through
 * {@code getClob}, so refusing meant that one of the most ordinary annotations
 * in Spring Data did not work on any of the four - and told the application so
 * with "read the column as a String instead", which is advice it cannot take.
 *
 * <p>So the promise is narrowed rather than broken: what these return is
 * <b>accurate about the content</b> and makes no claim about laziness. The
 * value is in memory because the row it came in already was. A driver that can
 * genuinely stream - Oracle, through its locators - overrides the hooks in
 * {@link ReadOnlyResultSet} and does not come here.
 *
 * <p>The write half of both interfaces is refused. A result set of this
 * project is read-only, and a {@code Clob} handed out of it that accepted
 * writes would look like it changed the row.
 */
public final class Lobs {

    private Lobs() {
    }

    /** A {@code Clob} - an {@code NClob}, so it serves {@code getNClob} too. */
    public static NClob text(String value) {
        return new TextLob(value);
    }

    /** A {@code Blob} over bytes the row already holds. */
    public static Blob binary(byte[] value) {
        return new ByteLob(value);
    }

    /**
     * The characters of a string as bytes, without copying it into a
     * {@code byte[]}.
     *
     * <p>{@code getAsciiStream} is defined as one byte per character, and
     * {@code String.getBytes} is forbidden in this project for a good reason -
     * it is the shortest path from a value to a heap array nobody can wipe.
     * Reading the characters out one at a time needs neither.
     */
    public static InputStream asciiStream(String value) {
        return new InputStream() {
            private int at;

            @Override
            public int read() {
                return at < value.length() ? value.charAt(at++) & 0xFF : -1;
            }

            @Override
            public int available() {
                return value.length() - at;
            }
        };
    }

    private record TextLob(String value) implements NClob {

        @Override
        public long length() {
            return value.length();
        }

        @Override
        public String getSubString(long position, int length) throws SQLException {
            int from = offsetOf(position, value.length());
            return value.substring(from, Math.min(from + Math.max(length, 0), value.length()));
        }

        @Override
        public Reader getCharacterStream() {
            return new StringReader(value);
        }

        @Override
        public InputStream getAsciiStream() {
            return asciiStream(value);
        }

        @Override
        public long position(String searched, long start) throws SQLException {
            int found = value.indexOf(searched, offsetOf(start, value.length()));
            return found < 0 ? -1 : found + 1;
        }

        @Override
        public long position(java.sql.Clob searched, long start) throws SQLException {
            return position(searched.getSubString(1, (int) searched.length()), start);
        }

        @Override
        public Reader getCharacterStream(long position, long length) throws SQLException {
            return new StringReader(getSubString(position, (int) length));
        }

        @Override
        public void free() {
            // Nothing is held that the row does not hold anyway.
        }

        @Override
        public int setString(long position, String replacement) throws SQLException {
            throw readOnly();
        }

        @Override
        public int setString(long position, String replacement, int offset, int length)
                throws SQLException {
            throw readOnly();
        }

        @Override
        public OutputStream setAsciiStream(long position) throws SQLException {
            throw readOnly();
        }

        @Override
        public Writer setCharacterStream(long position) throws SQLException {
            throw readOnly();
        }

        @Override
        public void truncate(long length) throws SQLException {
            throw readOnly();
        }
    }

    private record ByteLob(byte[] value) implements Blob {

        @Override
        public long length() {
            return value.length;
        }

        @Override
        public byte[] getBytes(long position, int length) throws SQLException {
            int from = offsetOf(position, value.length);
            int to = Math.min(from + Math.max(length, 0), value.length);
            byte[] part = new byte[to - from];
            System.arraycopy(value, from, part, 0, part.length);
            return part;
        }

        @Override
        public InputStream getBinaryStream() {
            return new ByteArrayInputStream(value);
        }

        @Override
        public InputStream getBinaryStream(long position, long length) throws SQLException {
            byte[] part = getBytes(position, (int) length);
            return new ByteArrayInputStream(part);
        }

        @Override
        public long position(byte[] searched, long start) throws SQLException {
            int from = offsetOf(start, value.length);
            outer:
            for (int at = from; at + searched.length <= value.length; at++) {
                for (int i = 0; i < searched.length; i++) {
                    if (value[at + i] != searched[i]) {
                        continue outer;
                    }
                }
                return at + 1;
            }
            return -1;
        }

        @Override
        public long position(Blob searched, long start) throws SQLException {
            // seclume-allow: Blob.getBytes, the caller's own value, not a String's
            return position(searched.getBytes(1, (int) searched.length()), start);
        }

        @Override
        public void free() {
            // Nothing is held that the row does not hold anyway.
        }

        @Override
        public int setBytes(long position, byte[] replacement) throws SQLException {
            throw readOnly();
        }

        @Override
        public int setBytes(long position, byte[] replacement, int offset, int length)
                throws SQLException {
            throw readOnly();
        }

        @Override
        public OutputStream setBinaryStream(long position) throws SQLException {
            throw readOnly();
        }

        @Override
        public void truncate(long length) throws SQLException {
            throw readOnly();
        }
    }

    /** JDBC counts a large object's positions from one, not from zero. */
    private static int offsetOf(long position, int length) throws SQLException {
        if (position < 1) {
            throw new SQLException("a large object starts at position 1, not at " + position);
        }
        if (position - 1 > length) {
            throw new SQLException("position " + position + " is past the end of a value of "
                    + length);
        }
        return (int) (position - 1);
    }

    private static SQLFeatureNotSupportedException readOnly() {
        return new SQLFeatureNotSupportedException(
                "this large object belongs to a result that is read-only - write the value "
                + "with an update statement instead");
    }
}
