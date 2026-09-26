package space.seclume.internal.jdbc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.sql.SQLException;

/**
 * A stream parameter, read to its end so that it can be sent as a value.
 *
 * <p>The length a caller gives is a promise, and it is held to. A stream that
 * ends before it is an error rather than a shorter value - the caller said how
 * large the value is, and a silently shorter row is the one outcome nobody
 * could notice. A stream that goes on past it is read only as far as the
 * length, which is what the JDBC contract describes. A negative length means
 * the caller does not know, and the stream decides.
 *
 * <p>The stream is closed afterwards in every case: it was handed over, and
 * nothing else reads it once its value has been taken.
 */
public final class StreamValues {

    /** The length a caller passes when it has none. */
    public static final long UNKNOWN = -1;

    private static final int CHUNK = 8192;

    private StreamValues() {
    }

    /** The bytes of a stream; {@code null} for a {@code null} stream. */
    public static byte[] bytes(InputStream stream, long length) throws SQLException {
        if (stream == null) {
            return null;
        }
        check(length);
        ByteArrayOutputStream out = new ByteArrayOutputStream(
                length >= 0 ? (int) Math.min(length, 1 << 20) : CHUNK);
        byte[] buffer = new byte[CHUNK]; // seclume-allow: user payload, not a secret
        long total = 0;
        try (InputStream open = stream) {
            while (length < 0 || total < length) {
                int wanted = (int) (length < 0 ? CHUNK : Math.min(CHUNK, length - total));
                int read = open.read(buffer, 0, wanted);
                if (read < 0) {
                    break;
                }
                out.write(buffer, 0, read);
                total += read;
            }
        } catch (IOException e) {
            throw new SQLException("the stream for a parameter failed: " + e.getMessage(),
                    "22000", e);
        }
        endedEarly(total, length, "bytes");
        return out.toByteArray();
    }

    /**
     * An ASCII stream as text - one character per byte.
     *
     * <p>Read as ISO-8859-1 rather than as ASCII, so that a byte above 127 is
     * kept as the character it most likely was instead of turning into a
     * replacement character.
     */
    public static String ascii(InputStream stream, long length) throws SQLException {
        byte[] bytes = bytes(stream, length);
        return bytes == null ? null
                : new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1); // seclume-allow: user payload, not a secret
    }

    /** The characters of a reader; {@code null} for a {@code null} reader. */
    public static String text(Reader reader, long length) throws SQLException {
        if (reader == null) {
            return null;
        }
        check(length);
        StringBuilder text = new StringBuilder( // seclume-allow: user payload, not a secret
                length >= 0 ? (int) Math.min(length, 1 << 20) : CHUNK);
        char[] buffer = new char[CHUNK]; // seclume-allow: user payload, not a secret
        long total = 0;
        try (Reader open = reader) {
            while (length < 0 || total < length) {
                int wanted = (int) (length < 0 ? CHUNK : Math.min(CHUNK, length - total));
                int read = open.read(buffer, 0, wanted);
                if (read < 0) {
                    break;
                }
                text.append(buffer, 0, read);
                total += read;
            }
        } catch (IOException e) {
            throw new SQLException("the reader for a parameter failed: " + e.getMessage(),
                    "22000", e);
        }
        endedEarly(total, length, "characters");
        return text.toString();
    }

    private static void check(long length) throws SQLException {
        if (length > Integer.MAX_VALUE - 8) {
            throw new SQLException("a stream parameter of " + length + " is more than one "
                    + "value can hold - it is read into memory before it is sent", "22001");
        }
    }

    private static void endedEarly(long total, long length, String unit) throws SQLException {
        if (length >= 0 && total < length) {
            throw new SQLException("the stream ended after " + total + " of the " + length
                    + " " + unit + " it was said to hold", "22000");
        }
    }
}
