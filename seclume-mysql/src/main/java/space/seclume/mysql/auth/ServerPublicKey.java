package space.seclume.mysql.auth;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.crypto.RsaPublicKey;
import space.seclume.internal.Base64Off;

/**
 * The public key the server sends in PEM format.
 *
 * <p>It is <b>not</b> a secret - it may sit on the heap, and a driver may cache
 * it so that not every connection has to request it anew. It is still parsed
 * off-heap here: the result goes straight into the encryption of the password,
 * and two encodings for the same value would be two places where something can
 * go wrong.
 *
 * <p>PEM is base64 between two marker lines. What sits inside is a
 * {@code SubjectPublicKeyInfo} per X.509 - the same structure
 * {@link RsaPublicKey#fromSubjectPublicKeyInfo} reads.
 */
public final class ServerPublicKey {

    private static final byte[] BEGIN =
            "-----BEGIN".getBytes(java.nio.charset.StandardCharsets.US_ASCII); // seclume-allow: a public PEM marker, no secret

    private ServerPublicKey() {
    }

    /**
     * Reads a PEM block out of native memory.
     *
     * @throws IllegalArgumentException if the text is not PEM - better a clear
     *         abort than a key made of random bytes
     */
    public static RsaPublicKey parsePem(MemorySegment pem, long offset, int length) {
        int start = lineAfterMarker(pem, offset, length);
        int end = start < 0 ? -1 : markerBefore(pem, offset, length, start);
        if (start < 0 || end <= start) {
            throw new IllegalArgumentException(
                    "the server did not send a PEM public key - the answer starts with "
                    + describe(pem, offset, Math.min(length, 10)));
        }
        try (Arena arena = Arena.ofConfined()) {
            int bodyLength = end - start;
            MemorySegment compact = arena.allocate(bodyLength);
            int compacted = 0;
            for (int i = 0; i < bodyLength; i++) {
                byte b = pem.get(ValueLayout.JAVA_BYTE, offset + start + i);
                if (b != '\n' && b != '\r' && b != ' ' && b != '\t') {
                    compact.set(ValueLayout.JAVA_BYTE, compacted++, b);
                }
            }
            MemorySegment der = arena.allocate(Base64Off.decodedUpperBound(compacted));
            int derLength = Base64Off.decode(compact, 0, compacted, der, 0);
            return RsaPublicKey.fromSubjectPublicKeyInfo(der.asSlice(0, derLength));
        }
    }

    /** Start of the base64 lines: behind the line break of the BEGIN line. */
    private static int lineAfterMarker(MemorySegment pem, long offset, int length) {
        if (!startsWith(pem, offset, length, BEGIN)) {
            return -1;
        }
        for (int i = 0; i < length; i++) {
            if (pem.get(ValueLayout.JAVA_BYTE, offset + i) == '\n') {
                return i + 1;
            }
        }
        return -1;
    }

    /** End of the base64 lines: the dash the END line starts with. */
    private static int markerBefore(MemorySegment pem, long offset, int length, int start) {
        for (int i = start; i < length; i++) {
            if (pem.get(ValueLayout.JAVA_BYTE, offset + i) == '-') {
                return i;
            }
        }
        return -1;
    }

    private static boolean startsWith(MemorySegment pem, long offset, int length, byte[] marker) {
        if (length < marker.length) {
            return false;
        }
        for (int i = 0; i < marker.length; i++) {
            if (pem.get(ValueLayout.JAVA_BYTE, offset + i) != marker[i]) {
                return false;
            }
        }
        return true;
    }

    /** For the error message: the first bytes as hex, not as text. */
    private static String describe(MemorySegment segment, long offset, int length) {
        StringBuilder text = new StringBuilder(length * 3);
        for (int i = 0; i < length; i++) {
            text.append(String.format("%02x ", segment.get(ValueLayout.JAVA_BYTE, offset + i)));
        }
        return text.toString().trim();
    }
}
