package space.seclume.oracle.jdbc;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.Writer;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.NClob;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;

import space.seclume.internal.WireBuffer;
import space.seclume.oracle.OracleSession;
import space.seclume.oracle.net.TtcLob;

/**
 * A {@code CLOB} or {@code BLOB} that stays on the server until it is asked for.
 *
 * <p>The row carries a locator, not the value - 112 bytes for a persistent
 * LOB; a temporary one is 38, which is why the length travels in the message
 * rather than being assumed. This holds a copy of
 * that locator and fetches what a caller actually wants - which is the point of
 * {@code Clob} and {@code Blob} in the first place: a value that need not fit
 * in memory. {@code getSubString(1000, 4096)} costs one round trip and brings
 * 4096 characters, not the other 195 904.
 *
 * <p>Oracle counts from 1, and the offset and amount of a read are fields of
 * the call - both measured, see {@code docs/protocol/oracle-lob.md}. A read
 * past the end yields nothing, which is how the streams below know they are
 * done - they never ask for a length. There is an operation for the length
 * (0x0001) and {@link #length} uses it, but a stream that asked first would pay
 * a round trip for a number it does not need.
 *
 * <p>The locator lives in native memory, like everything else here. It is not a
 * secret - it names a value, it does not carry one - but it also has no
 * business on the Java heap when nothing forces it there.
 */
final class OraLob implements AutoCloseable {

    /** How much one block of a stream fetches - characters or bytes. */
    private static final int BLOCK = 8000;

    private final OracleSession session;
    private final WireBuffer locator;
    private boolean freed;

    private OraLob(OracleSession session, WireBuffer source, int at) {
        this.session = session;
        this.locator = new WireBuffer(TtcLob.LOCATOR_LENGTH);
        this.locator.putBytes(source.segment(), at, TtcLob.LOCATOR_LENGTH);
    }

    /** Takes its own copy of the locator: the row it came from moves on. */
    static Clob clob(OracleSession session, WireBuffer source, int at) {
        return new AsClob(new OraLob(session, source, at));
    }

    static Blob blob(OracleSession session, WireBuffer source, int at) {
        return new AsBlob(new OraLob(session, source, at));
    }

    /**
     * Reads {@code amount} units from {@code offset}, counted from 1.
     *
     * <p>The caller owns the buffer that comes back and closes it.
     */
    private WireBuffer read(long offset, long amount) throws SQLException {
        if (freed) {
            throw new SQLException("this LOB has been freed", "HY000");
        }
        WireBuffer value = new WireBuffer(1024);
        session.readLob(locator, 0, TtcLob.LOCATOR_LENGTH, offset, amount, value);
        return value;
    }

    /** Oracle sends character data as UTF-16, big-endian - measured, not assumed. */
    private static String text(WireBuffer value) {
        int bytes = value.position();
        StringBuilder out = new StringBuilder(bytes / 2); // seclume-allow: user payload as text, not a secret
        for (int i = 0; i + 1 < bytes; i += 2) {
            out.append((char) (((value.getByte(i) & 0xff) << 8) | (value.getByte(i + 1) & 0xff)));
        }
        return out.toString();
    }

    private static byte[] bytes(WireBuffer value) {
        int length = value.position();
        byte[] out = new byte[length]; // seclume-allow: user payload as bytes, not a secret
        for (int i = 0; i < length; i++) {
            out[i] = value.getByte(i);
        }
        return out;
    }

    String substring(long position, int length) throws SQLException {
        try (WireBuffer value = read(position, length)) {
            return text(value);
        }
    }

    byte[] slice(long position, int length) throws SQLException {
        try (WireBuffer value = read(position, length)) {
            return bytes(value);
        }
    }

    /**
     * How long the value is - one call, and the value stays on the server.
     *
     * <p>This used to read the whole thing and count, which was correct and
     * needlessly expensive. Oracle has an operation for it (0x0001); the
     * message is the one a read uses, with offset and amount at zero. Measured
     * against a recording, every byte of it - see
     * {@code docs/protocol/oracle-lob.md}.
     */
    long length() throws SQLException {
        if (freed) {
            throw new SQLException("this LOB has been freed", "HY000");
        }
        return session.lobLength(locator, 0, TtcLob.LOCATOR_LENGTH);
    }

    /** Reads in blocks, one round trip each, and stops when a block comes back empty. */
    Reader reader() {
        return new Reader() {
            private long next = 1;
            private String block = "";
            private int at;
            private boolean ended;

            @Override
            // seclume-allow: the caller's buffer for user payload - Reader.read has this shape
            public int read(char[] target, int offset, int length) throws java.io.IOException {
                if (at >= block.length()) {
                    if (ended) {
                        return -1;
                    }
                    try {
                        block = substring(next, BLOCK);
                    } catch (SQLException e) {
                        throw new java.io.IOException(e);
                    }
                    if (block.isEmpty()) {
                        ended = true;
                        return -1;
                    }
                    next += block.length();
                    ended = block.length() < BLOCK;
                    at = 0;
                }
                int count = Math.min(length, block.length() - at);
                block.getChars(at, at + count, target, offset);
                at += count;
                return count;
            }

            @Override
            public void close() {
                // The LOB itself is closed by whoever owns it.
            }
        };
    }

    InputStream stream() {
        return new InputStream() {
            private long next = 1;
            private byte[] block = new byte[0]; // seclume-allow: user payload, not a secret
            private int at;
            private boolean ended;

            @Override
            public int read() throws java.io.IOException {
                byte[] one = new byte[1]; // seclume-allow: user payload, not a secret
                int count = read(one, 0, 1);
                return count < 0 ? -1 : one[0] & 0xff;
            }

            @Override
            public int read(byte[] target, int offset, int length) throws java.io.IOException {
                if (at >= block.length) {
                    if (ended) {
                        return -1;
                    }
                    try {
                        block = slice(next, BLOCK);
                    } catch (SQLException e) {
                        throw new java.io.IOException(e);
                    }
                    if (block.length == 0) {
                        ended = true;
                        return -1;
                    }
                    next += block.length;
                    ended = block.length < BLOCK;
                    at = 0;
                }
                int count = Math.min(length, block.length - at);
                System.arraycopy(block, at, target, offset, count);
                at += count;
                return count;
            }
        };
    }

    @Override
    public void close() {
        if (!freed) {
            freed = true;
            locator.close();
        }
    }

    private static SQLFeatureNotSupportedException readOnly() {
        return new SQLFeatureNotSupportedException(
                "seclume reads LOBs but does not write through a locator - "
                + "set the value as a String or byte[] on the statement instead");
    }

    /** The {@code Clob} face of it. */
    private static final class AsClob implements NClob {

        private final OraLob lob;

        AsClob(OraLob lob) {
            this.lob = lob;
        }

        @Override
        public long length() throws SQLException {
            return lob.length();
        }

        @Override
        public String getSubString(long position, int length) throws SQLException {
            return lob.substring(position, length);
        }

        @Override
        public Reader getCharacterStream() {
            return lob.reader();
        }

        @Override
        public Reader getCharacterStream(long position, long length) throws SQLException {
            return new StringReader(lob.substring(position, (int) length));
        }

        @Override
        public InputStream getAsciiStream() {
            return lob.stream();
        }

        @Override
        public long position(String searched, long start) throws SQLException {
            throw readOnly();
        }

        @Override
        public long position(Clob searched, long start) throws SQLException {
            throw readOnly();
        }

        @Override
        public int setString(long position, String value) throws SQLException {
            throw readOnly();
        }

        @Override
        public int setString(long position, String value, int offset, int length)
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

        @Override
        public void free() {
            lob.close();
        }
    }

    /** The {@code Blob} face of it. */
    private static final class AsBlob implements Blob {

        private final OraLob lob;

        AsBlob(OraLob lob) {
            this.lob = lob;
        }

        @Override
        public long length() throws SQLException {
            return lob.length();
        }

        @Override
        public byte[] getBytes(long position, int length) throws SQLException {
            return lob.slice(position, length);
        }

        @Override
        public InputStream getBinaryStream() {
            return lob.stream();
        }

        @Override
        public InputStream getBinaryStream(long position, long length) throws SQLException {
            return new java.io.ByteArrayInputStream(lob.slice(position, (int) length));
        }

        @Override
        public long position(byte[] searched, long start) throws SQLException {
            throw readOnly();
        }

        @Override
        public long position(Blob searched, long start) throws SQLException {
            throw readOnly();
        }

        @Override
        public int setBytes(long position, byte[] value) throws SQLException {
            throw readOnly();
        }

        @Override
        public int setBytes(long position, byte[] value, int offset, int length)
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

        @Override
        public void free() {
            lob.close();
        }
    }
}
