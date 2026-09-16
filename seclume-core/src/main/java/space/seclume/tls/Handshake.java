package space.seclume.tls;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * TLS 1.3 handshake messages: the framing, the two Hellos, the extensions.
 *
 * <p>Read in place, like everything else in this module - a handshake message
 * arrives inside a record that is already in native memory, and turning it into
 * objects would put a server's certificate and our own key share on the heap
 * for no gain.
 *
 * <p>Three shapes here are worth naming, because each is a place where a
 * plausible reading is the wrong one:
 *
 * <ul>
 *   <li>the message length is <b>three bytes</b>, not two and not four. Every
 *       other length in TLS is two, which is exactly why this one gets
 *       misread;
 *   <li><b>{@code legacy_version} is 0x0303 in both Hellos</b> and means
 *       nothing. The real version is in the {@code supported_versions}
 *       extension, and a client that trusts the header talks TLS 1.2 to a
 *       server that offered 1.3;
 *   <li>{@code legacy_session_id} is <b>not</b> empty in practice. Middleboxes
 *       expect a 32-byte value echoed back, so the field has to be read and
 *       compared rather than skipped as the dead weight it nominally is.
 * </ul>
 */
public final class Handshake {

    private Handshake() {
    }

    public static final int CLIENT_HELLO = 1;
    public static final int SERVER_HELLO = 2;
    public static final int NEW_SESSION_TICKET = 4;
    public static final int END_OF_EARLY_DATA = 5;
    public static final int ENCRYPTED_EXTENSIONS = 8;
    public static final int CERTIFICATE = 11;
    public static final int CERTIFICATE_REQUEST = 13;
    public static final int CERTIFICATE_VERIFY = 15;
    public static final int FINISHED = 20;

    public static final int EXTENSION_SERVER_NAME = 0;
    public static final int EXTENSION_SUPPORTED_GROUPS = 10;
    public static final int EXTENSION_SIGNATURE_ALGORITHMS = 13;
    public static final int EXTENSION_PRE_SHARED_KEY = 41;
    public static final int EXTENSION_SUPPORTED_VERSIONS = 43;
    public static final int EXTENSION_COOKIE = 44;
    public static final int EXTENSION_PSK_KEY_EXCHANGE_MODES = 45;
    public static final int EXTENSION_KEY_SHARE = 51;

    /** The four bytes of type and length that every message starts with. */
    public static final int HEADER = 4;
    /** Both Hellos carry this in the header and it means nothing. */
    public static final int LEGACY_VERSION = 0x0303;
    private static final int RANDOM = 32;

    // ---- framing ----------------------------------------------------------

    public static int type(MemorySegment data, long offset) {
        return data.get(ValueLayout.JAVA_BYTE, offset) & 0xff;
    }

    /** The body length - three bytes, which is the trap. */
    public static int length(MemorySegment data, long offset) {
        return ((data.get(ValueLayout.JAVA_BYTE, offset + 1) & 0xff) << 16)
                | ((data.get(ValueLayout.JAVA_BYTE, offset + 2) & 0xff) << 8)
                | (data.get(ValueLayout.JAVA_BYTE, offset + 3) & 0xff);
    }

    /** Header and body together. */
    public static int totalLength(MemorySegment data, long offset) {
        return HEADER + length(data, offset);
    }

    /**
     * Walks the messages packed into one range.
     *
     * <p>A single record often carries several - EncryptedExtensions,
     * Certificate, CertificateVerify and Finished arrive together - and a
     * message may equally be split across records. This handles the first;
     * the second belongs to whoever reassembles records.
     */
    public static void messages(MemorySegment data, long offset, int length, Reader reader) {
        long at = 0;
        while (length - at >= HEADER) {
            int total = totalLength(data, offset + at);
            if (total <= 0 || at + total > length) {
                return;                       // truncated or nonsense; stop here
            }
            reader.message(type(data, offset + at), offset + at + HEADER,
                    total - HEADER);
            at += total;
        }
    }

    /** What {@link #messages} calls for each message. */
    @FunctionalInterface
    public interface Reader {
        /**
         * @param type the handshake type
         * @param at   where the body starts
         * @param length how long the body is
         */
        void message(int type, long at, int length);
    }

    // ---- the two Hellos ---------------------------------------------------

    /** The 32 bytes of randomness, at the same place in both Hellos. */
    public static long randomOffset(long body) {
        return body + 2;
    }

    /** The echoed session id - length byte first. */
    public static int sessionIdLength(MemorySegment data, long body) {
        return data.get(ValueLayout.JAVA_BYTE, body + 2 + RANDOM) & 0xff;
    }

    public static long sessionIdOffset(long body) {
        return body + 2 + RANDOM + 1;
    }

    /** The one suite a ServerHello chose. */
    public static int cipherSuite(MemorySegment data, long body) {
        return u16(data, sessionIdOffset(body) + sessionIdLength(data, body));
    }

    /**
     * Where a ServerHello's extensions start, and how long they are.
     *
     * @return the offset; {@code out[0]} receives the length
     */
    public static long serverHelloExtensions(MemorySegment data, long body, int[] out) {
        long at = sessionIdOffset(body) + sessionIdLength(data, body)
                + 2        // cipher suite
                + 1;       // legacy compression method
        out[0] = u16(data, at);
        return at + 2;
    }

    /** The same for a ClientHello, which has two more lists in the way. */
    public static long clientHelloExtensions(MemorySegment data, long body, int[] out) {
        long at = sessionIdOffset(body) + sessionIdLength(data, body);
        at += 2 + u16(data, at);                                    // cipher suites
        at += 1 + (data.get(ValueLayout.JAVA_BYTE, at) & 0xff);     // compression methods
        out[0] = u16(data, at);
        return at + 2;
    }

    // ---- extensions -------------------------------------------------------

    /**
     * Walks a block of extensions.
     *
     * <p>Bounded the same way the TCP options are, and for the same reason: a
     * length that runs past the end must stop the walk rather than read into
     * whatever follows. An extension of length zero is legal here, unlike a TCP
     * option, so only the overrun is a reason to stop.
     */
    public static void extensions(MemorySegment data, long offset, int length,
            ExtensionReader reader) {
        long at = 0;
        while (length - at >= 4) {
            int type = u16(data, offset + at);
            int extensionLength = u16(data, offset + at + 2);
            if (at + 4 + extensionLength > length) {
                return;
            }
            reader.extension(type, offset + at + 4, extensionLength);
            at += 4 + extensionLength;
        }
    }

    /** What {@link #extensions} calls for each one. */
    @FunctionalInterface
    public interface ExtensionReader {
        void extension(int type, long at, int length);
    }

    /**
     * The key share inside a <b>ServerHello</b>'s {@code key_share} extension.
     *
     * <p>A server sends exactly one entry and no list around it; a client sends
     * a list with its own length. Reading the server's shape with the client's
     * parser takes the first two bytes of the group as a length and yields
     * confident nonsense, so the two are separate methods rather than one with
     * a flag.
     *
     * @return the group; {@code out[0]} receives the offset of the key and
     *         {@code out[1]} its length
     */
    public static int serverKeyShare(MemorySegment data, long at, long[] out) {
        int group = u16(data, at);
        out[0] = at + 4;
        out[1] = u16(data, at + 2);
        return group;
    }

    /** The version a server selected, inside {@code supported_versions}. */
    public static int selectedVersion(MemorySegment data, long at) {
        return u16(data, at);
    }

    static int u16(MemorySegment data, long at) {
        return ((data.get(ValueLayout.JAVA_BYTE, at) & 0xff) << 8)
                | (data.get(ValueLayout.JAVA_BYTE, at + 1) & 0xff);
    }
}
