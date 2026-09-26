package space.seclume.internal.jdbc;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.NClob;
import java.sql.SQLException;
import java.util.Arrays;

/**
 * What {@code Connection.createBlob} and {@code createClob} hand out on MySQL,
 * SQL Server and Oracle: an empty LOB the application writes into, bound with
 * {@code setBlob} or {@code setClob}, which send what was written as an
 * ordinary parameter - long ones in pieces.
 *
 * <p>The contents stay here and not in a temporary LOB on the server, and on
 * Oracle that is a choice: what {@code createClob} promises is "a Clob object
 * with no data" to fill and give to a statement, and that is all frameworks
 * do with it. A server-side temporary LOB - to hand to PL/SQL, or to write
 * gigabytes into without holding them - is another thing. PostgreSQL's CLOB is
 * a large object, and that driver makes one on the server.
 *
 * <p>Positions count from 1, as everywhere in JDBC. Writing within the LOB
 * <b>overwrites</b> and writing past its end grows it - JDBC says so for
 * {@code setString}, {@code setBytes} and the streams. Oracle's own LOB here
 * used to cut everything behind a write off, so "overwrite three characters
 * in the middle" lost the rest; {@code LobCreateTest} makes the same edits
 * through the vendors' drivers and compares.
 */
public final class WritableLobs {

    private WritableLobs() {
    }

    /** An empty character LOB. */
    public static NClob text() {
        return new Text();
    }

    /** An empty binary LOB. */
    public static Blob binary() {
        return new Binary();
    }

    private static long start(long position) throws SQLException {
        if (position < 1) {
            throw new SQLException("a LOB position counts from 1, not " + position, "22003");
        }
        return position - 1;
    }

    private static final class Text implements NClob {

        private StringBuilder value = new StringBuilder(); // seclume-allow: application-written LOB payload

        private StringBuilder alive() throws SQLException {
            if (value == null) {
                throw new SQLException("this LOB has been freed");
            }
            return value;
        }

        @Override
        public long length() throws SQLException {
            return alive().length();
        }

        @Override
        public String getSubString(long position, int length) throws SQLException {
            int from = (int) Math.min(start(position), alive().length());
            return alive().substring(from, Math.min(alive().length(), from + Math.max(0, length)));
        }

        @Override
        public Reader getCharacterStream() throws SQLException {
            return new StringReader(alive().toString());
        }

        @Override
        public Reader getCharacterStream(long position, long length) throws SQLException {
            return new StringReader(getSubString(position, (int) length));
        }

        @Override
        public InputStream getAsciiStream() throws SQLException {
            // seclume-allow: application-written LOB payload
            return new ByteArrayInputStream(alive().toString().getBytes(StandardCharsets.US_ASCII));
        }

        @Override
        public long position(String searched, long start) throws SQLException {
            int at = alive().indexOf(searched, (int) start(start));
            return at < 0 ? -1 : at + 1;
        }

        @Override
        public long position(Clob searched, long start) throws SQLException {
            return position(searched.getSubString(1, (int) searched.length()), start);
        }

        @Override
        public int setString(long position, String text) throws SQLException {
            return setString(position, text, 0, text.length());
        }

        @Override
        public int setString(long position, String text, int offset, int length)
                throws SQLException {
            int at = (int) start(position);
            StringBuilder target = alive();
            while (target.length() < at) {
                target.append(' ');
            }
            String part = text.substring(offset, offset + length);
            int overlap = Math.min(part.length(), target.length() - at);
            target.replace(at, at + overlap, part.substring(0, overlap));
            target.append(part, overlap, part.length());
            return length;
        }

        @Override
        public OutputStream setAsciiStream(long position) throws SQLException {
            long[] at = {start(position) + 1};
            return new OutputStream() {
                @Override
                public void write(int b) throws java.io.IOException {
                    try {
                        setString(at[0]++, String.valueOf((char) (b & 0x7f)));
                    } catch (SQLException e) {
                        throw new java.io.IOException(e);
                    }
                }
            };
        }

        @Override
        public Writer setCharacterStream(long position) throws SQLException {
            long[] at = {start(position) + 1};
            return new Writer() {
                @Override
                public void write(char[] buffer, int offset, int length) // seclume-allow: the Writer contract
                        throws java.io.IOException {
                    try {
                        setString(at[0], new String(buffer, offset, length)); // seclume-allow: application-written LOB payload
                        at[0] += length;
                    } catch (SQLException e) {
                        throw new java.io.IOException(e);
                    }
                }

                @Override
                public void flush() {
                    // Written straight into the LOB; nothing is held back.
                }

                @Override
                public void close() {
                    // Nothing to release.
                }
            };
        }

        @Override
        public void truncate(long length) throws SQLException {
            alive().setLength((int) Math.min(length, alive().length()));
        }

        @Override
        public void free() {
            value = null;
        }
    }

    private static final class Binary implements Blob {

        private byte[] value = new byte[0]; // seclume-allow: application-written LOB payload
        private int length;
        private boolean freed;

        private byte[] alive() throws SQLException {
            if (freed) {
                throw new SQLException("this LOB has been freed");
            }
            return value;
        }

        @Override
        public long length() throws SQLException {
            alive();
            return length;
        }

        @Override
        public byte[] getBytes(long position, int count) throws SQLException {
            int from = (int) Math.min(start(position), length);
            return Arrays.copyOfRange(alive(), from, Math.min(length, from + Math.max(0, count)));
        }

        @Override
        public InputStream getBinaryStream() throws SQLException {
            return new ByteArrayInputStream(alive(), 0, length);
        }

        @Override
        public InputStream getBinaryStream(long position, long count) throws SQLException {
            return new ByteArrayInputStream(getBytes(position, (int) count));
        }

        @Override
        public long position(byte[] pattern, long start) throws SQLException {
            byte[] bytes = alive();
            outer:
            for (int i = (int) start(start); i <= length - pattern.length; i++) {
                for (int j = 0; j < pattern.length; j++) {
                    if (bytes[i + j] != pattern[j]) {
                        continue outer;
                    }
                }
                return i + 1;
            }
            return -1;
        }

        @Override
        public long position(Blob pattern, long start) throws SQLException {
            return position(pattern.getBytes(1, (int) pattern.length()), start); // seclume-allow: Blob.getBytes on application payload
        }

        @Override
        public int setBytes(long position, byte[] bytes) throws SQLException {
            return setBytes(position, bytes, 0, bytes.length);
        }

        @Override
        public int setBytes(long position, byte[] bytes, int offset, int count)
                throws SQLException {
            int at = (int) start(position);
            int end = at + count;
            if (end > alive().length) {
                value = Arrays.copyOf(value, Math.max(end, value.length * 2));
            }
            System.arraycopy(bytes, offset, value, at, count);
            length = Math.max(length, end);
            return count;
        }

        @Override
        public OutputStream setBinaryStream(long position) throws SQLException {
            long[] at = {start(position) + 1};
            return new OutputStream() {
                @Override
                public void write(int b) throws java.io.IOException {
                    write(new byte[] {(byte) b}, 0, 1);
                }

                @Override
                public void write(byte[] bytes, int offset, int count) throws java.io.IOException {
                    try {
                        setBytes(at[0], bytes, offset, count);
                        at[0] += count;
                    } catch (SQLException e) {
                        throw new java.io.IOException(e);
                    }
                }
            };
        }

        @Override
        public void truncate(long newLength) throws SQLException {
            alive();
            length = (int) Math.min(newLength, length);
        }

        @Override
        public void free() {
            freed = true;
            value = null;
        }
    }
}
