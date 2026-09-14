package space.seclume.oracle.jdbc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.Writer;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.NClob;
import java.sql.SQLException;

/**
 * The {@code Clob} and {@code Blob} that {@code createClob()} hands out.
 *
 * <p>It holds its contents here, not on the server, and that is deliberate.
 * What {@code createClob} promises is narrow: „creates a Clob object with no
 * data" that can be filled and then given to a {@code PreparedStatement}. It
 * says nothing about a temporary LOB on the server, and the pattern that
 * frameworks actually use —
 *
 * <pre>
 *   Clob c = connection.createClob();
 *   c.setString(1, text);
 *   statement.setClob(1, c);
 * </pre>
 *
 * <p>— needs none: {@code setClob} sends the value as an ordinary parameter,
 * and long parameters go out in pieces since {@code NsChannel.sendSplit}.
 *
 * <p><b>What this is not.</b> A server-side temporary LOB, the kind you hand to
 * a PL/SQL procedure or write gigabytes into without holding them. That needs
 * three more calls of TTC function 96, and the operation codes for them are
 * measured and written down in {@code docs/protocol/oracle-lob.md} — together
 * with the catch that a temporary locator is <b>38 bytes, not 112</b>. Whoever
 * needs it will find the groundwork there rather than a guess here.
 */
final class OraLocalLob implements NClob, Blob {

    private StringBuilder text;      // seclume-allow: user payload, not a secret
    private ByteArrayOutputStream bytes;

    private OraLocalLob(boolean character) {
        if (character) {
            this.text = new StringBuilder(); // seclume-allow: user payload, not a secret
        } else {
            this.bytes = new ByteArrayOutputStream();
        }
    }

    static NClob clob() {
        return new OraLocalLob(true);
    }

    static Blob blob() {
        return new OraLocalLob(false);
    }

    private void mustBeText() throws SQLException {
        if (text == null) {
            throw new SQLException("this is a BLOB, not a CLOB", "22005");
        }
    }

    private void mustBeBytes() throws SQLException {
        if (bytes == null) {
            throw new SQLException("this is a CLOB, not a BLOB", "22005");
        }
    }

    /** Oracle counts from 1; a position of 0 is a mistake, not an empty result. */
    private static int index(long position) throws SQLException {
        if (position < 1) {
            throw new SQLException("a LOB position starts at 1, not " + position, "22011");
        }
        return (int) (position - 1);
    }

    @Override
    public long length() throws SQLException {
        return text != null ? text.length() : bytes.size();
    }

    // ---- CLOB ------------------------------------------------------------

    @Override
    public String getSubString(long position, int length) throws SQLException {
        mustBeText();
        int from = Math.min(index(position), text.length());
        int to = (int) Math.min((long) from + length, text.length());
        return text.substring(from, to);
    }

    @Override
    public Reader getCharacterStream() throws SQLException {
        mustBeText();
        return new StringReader(text.toString());
    }

    @Override
    public Reader getCharacterStream(long position, long length) throws SQLException {
        return new StringReader(getSubString(position, (int) length));
    }

    @Override
    public InputStream getAsciiStream() throws SQLException {
        mustBeText();
        return new ByteArrayInputStream(
                text.toString().getBytes(java.nio.charset.StandardCharsets.US_ASCII)); // seclume-allow: user payload, not a secret
    }

    @Override
    public int setString(long position, String value) throws SQLException {
        return setString(position, value, 0, value.length());
    }

    @Override
    public int setString(long position, String value, int offset, int length)
            throws SQLException {
        mustBeText();
        int at = index(position);
        while (text.length() < at) {
            text.append(' ');
        }
        text.setLength(at);
        text.append(value, offset, offset + length);
        return length;
    }

    @Override
    public Writer setCharacterStream(long position) throws SQLException {
        mustBeText();
        int at = index(position);
        text.setLength(Math.min(at, text.length()));
        return new Writer() {
            @Override
            public void write(char[] buffer, int offset, int length) { // seclume-allow: the caller's buffer for user payload
                text.append(buffer, offset, length);
            }

            @Override
            public void flush() {
                // Nothing is buffered elsewhere.
            }

            @Override
            public void close() {
                // Nothing to release.
            }
        };
    }

    @Override
    public OutputStream setAsciiStream(long position) throws SQLException {
        mustBeText();
        text.setLength(Math.min(index(position), text.length()));
        return new OutputStream() {
            @Override
            public void write(int value) {
                text.append((char) (value & 0xff));
            }
        };
    }

    @Override
    public long position(String searched, long start) throws SQLException {
        mustBeText();
        int found = text.indexOf(searched, index(start));
        return found < 0 ? -1 : found + 1;
    }

    @Override
    public long position(Clob searched, long start) throws SQLException {
        return position(searched.getSubString(1, (int) searched.length()), start);
    }

    // ---- BLOB ------------------------------------------------------------

    @Override
    public byte[] getBytes(long position, int length) throws SQLException {
        mustBeBytes();
        byte[] all = bytes.toByteArray(); // seclume-allow: user payload, not a secret
        int from = Math.min(index(position), all.length);
        int to = (int) Math.min((long) from + length, all.length);
        return java.util.Arrays.copyOfRange(all, from, to);
    }

    @Override
    public InputStream getBinaryStream() throws SQLException {
        mustBeBytes();
        return new ByteArrayInputStream(bytes.toByteArray());
    }

    @Override
    public InputStream getBinaryStream(long position, long length) throws SQLException {
        return new ByteArrayInputStream(getBytes(position, (int) length));
    }

    @Override
    public int setBytes(long position, byte[] value) throws SQLException {
        return setBytes(position, value, 0, value.length);
    }

    @Override
    public int setBytes(long position, byte[] value, int offset, int length)
            throws SQLException {
        mustBeBytes();
        if (index(position) != bytes.size()) {
            byte[] kept = bytes.toByteArray(); // seclume-allow: user payload, not a secret
            bytes = new ByteArrayOutputStream();
            bytes.write(kept, 0, Math.min(index(position), kept.length));
        }
        bytes.write(value, offset, length);
        return length;
    }

    @Override
    public OutputStream setBinaryStream(long position) throws SQLException {
        mustBeBytes();
        byte[] kept = bytes.toByteArray(); // seclume-allow: user payload, not a secret
        bytes = new ByteArrayOutputStream();
        bytes.write(kept, 0, Math.min(index(position), kept.length));
        return bytes;
    }

    @Override
    public long position(byte[] searched, long start) throws SQLException {
        mustBeBytes();
        byte[] all = bytes.toByteArray(); // seclume-allow: user payload, not a secret
        outer:
        for (int at = index(start); at + searched.length <= all.length; at++) {
            for (int i = 0; i < searched.length; i++) {
                if (all[at + i] != searched[i]) {
                    continue outer;
                }
            }
            return at + 1;
        }
        return -1;
    }

    @Override
    public long position(Blob searched, long start) throws SQLException {
        // seclume-allow: Blob.getBytes on user payload, not String.getBytes on a secret
        return position(searched.getBytes(1, (int) searched.length()), start);
    }

    // ---- both ------------------------------------------------------------

    @Override
    public void truncate(long length) throws SQLException {
        if (text != null) {
            text.setLength((int) Math.min(length, text.length()));
            return;
        }
        byte[] kept = bytes.toByteArray(); // seclume-allow: user payload, not a secret
        bytes = new ByteArrayOutputStream();
        bytes.write(kept, 0, (int) Math.min(length, kept.length));
    }

    @Override
    public void free() {
        if (text != null) {
            text.setLength(0);
        } else {
            bytes = new ByteArrayOutputStream();
        }
    }
}
