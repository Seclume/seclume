package space.seclume.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Hmac;

/**
 * AWS Signature Version 4, with the secret key never leaving native memory.
 *
 * <p>Two providers need this and they need different halves of it: the RDS IAM
 * token is a <b>query-signed GET</b> whose signature is part of a URL, and
 * Secrets Manager is a <b>header-signed POST</b>. Everything under that -
 * deriving the signing key through four HMACs, hashing the canonical request,
 * writing ASCII into a segment - is the same, and it is the part that touches
 * the key.
 *
 * <p>The key itself is read from a {@link space.seclume.secret.SecretProvider}
 * into a segment, used for the first HMAC, and wiped before this class returns.
 * Nothing derived from it is a Java object either: the intermediate HMAC
 * results stay in the caller's arena. What does become a {@code String} is the
 * finished signature, and a signature is public by construction - it is sent
 * to AWS in the clear and says nothing about the key it was made with.
 */
public final class AwsSigV4 {

    public static final String ALGORITHM = "AWS4-HMAC-SHA256";
    public static final String TERMINATOR = "aws4_request";
    /** SHA-256 of an empty payload - what a GET signs as its body hash. */
    public static final String EMPTY_PAYLOAD =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /** Long enough for any AWS secret key, short enough to stay cheap. */
    private static final int MAX_KEY_BYTES = 256;

    private AwsSigV4() {
    }

    /**
     * The scope a signature is valid in: day, region, service, terminator.
     */
    public static String scope(String day, String region, String service) {
        return day + "/" + region + "/" + service + "/" + TERMINATOR;
    }

    /**
     * Signs {@code toSign} with the key derived from the AWS secret key.
     *
     * <p>{@code AWS4 + key -> day -> region -> service -> aws4_request}, each
     * step an HMAC over the previous result, and the last one over the string
     * to sign. The key is wiped in a {@code finally} - which matters here more
     * than usual, because every step in between would otherwise leave a
     * derivative of it in the arena for the rest of the request.
     *
     * @return the signature, in the caller's arena
     */
    public static MemorySegment sign(Arena arena, SecretKey secretKey, String toSign,
            String day, String region, String service) {
        MemorySegment key = arena.allocate(MAX_KEY_BYTES);
        MemorySegment prefixed = arena.allocate(MAX_KEY_BYTES + 4);
        try {
            int length = secretKey.write(key);
            if (length <= 0) {
                throw new IllegalStateException(
                        "the AWS secret key source gave nothing - nothing can be signed "
                        + "without it");
            }
            byte[] aws4 = {'A', 'W', 'S', '4'}; // seclume-allow: four constant letters, not a secret
            MemorySegment.copy(aws4, 0, prefixed, ValueLayout.JAVA_BYTE, 0, 4);
            MemorySegment.copy(key, 0, prefixed, 4, length);

            MemorySegment step = hmac(arena, prefixed, 0, 4 + length, day);
            step = hmac(arena, step, 0, step.byteSize(), region);
            step = hmac(arena, step, 0, step.byteSize(), service);
            step = hmac(arena, step, 0, step.byteSize(), TERMINATOR);
            return hmac(arena, step, 0, step.byteSize(), toSign);
        } finally {
            key.fill((byte) 0);
            prefixed.fill((byte) 0);
        }
    }

    /**
     * How the key gets here.
     *
     * <p>A one-method interface rather than a {@code SecretProvider} so that
     * this class stays in {@code internal} and does not reach up into
     * {@code secret} - which would make the dependency run the wrong way
     * round.
     */
    @FunctionalInterface
    public interface SecretKey {
        /** @return how many bytes were written */
        int write(MemorySegment target);
    }

    public static MemorySegment hmac(Arena arena, MemorySegment key, long offset, long length,
            String message) {
        try (Hmac mac = new Hmac(HashAlgorithm.SHA_256, key, offset, length)) {
            MemorySegment text = arena.allocate(message.length() * 3L + 1);
            int written = writeAscii(text, message);
            mac.update(text, 0, written);
            MemorySegment out = arena.allocate(mac.macLength());
            mac.doFinal(out, 0);
            return out;
        }
    }

    /** SHA-256 of a string, hex-encoded - for canonical requests and payloads. */
    public static String sha256Hex(String text) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment in = arena.allocate(text.length() * 3L + 1);
            int written = writeAscii(in, text);
            MemorySegment out = arena.allocate(HashAlgorithm.SHA_256.digestLength());
            HashAlgorithm.SHA_256.hash(in, 0, written, out, 0);
            return hex(out);
        }
    }

    /** UTF-8 without a heap array in between. @return bytes written */
    public static int writeAscii(MemorySegment target, String text) {
        int at = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < 0x80) {
                target.set(ValueLayout.JAVA_BYTE, at++, (byte) c);
            } else if (c < 0x800) {
                target.set(ValueLayout.JAVA_BYTE, at++, (byte) (0xc0 | (c >> 6)));
                target.set(ValueLayout.JAVA_BYTE, at++, (byte) (0x80 | (c & 0x3f)));
            } else {
                target.set(ValueLayout.JAVA_BYTE, at++, (byte) (0xe0 | (c >> 12)));
                target.set(ValueLayout.JAVA_BYTE, at++, (byte) (0x80 | ((c >> 6) & 0x3f)));
                target.set(ValueLayout.JAVA_BYTE, at++, (byte) (0x80 | (c & 0x3f)));
            }
        }
        return at;
    }

    public static String hex(MemorySegment bytes) {
        StringBuilder text = new StringBuilder((int) bytes.byteSize() * 2); // seclume-allow: a signature or a digest, both public by design
        for (long i = 0; i < bytes.byteSize(); i++) {
            int value = bytes.get(ValueLayout.JAVA_BYTE, i) & 0xff;
            text.append(Character.forDigit(value >> 4, 16));
            text.append(Character.forDigit(value & 0xf, 16));
        }
        return text.toString();
    }

    /**
     * {@link #urlEncode} for bytes that must not become a {@code String} - a
     * session token in a query - segment to segment.
     *
     * @return the bytes written at {@code at}
     */
    public static int urlEncode(MemorySegment source, int length, MemorySegment target,
                                long at) {
        long out = at;
        for (int i = 0; i < length; i++) {
            int b = source.get(ValueLayout.JAVA_BYTE, i) & 0xff;
            boolean safe = (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
                    || (b >= '0' && b <= '9') || b == '-' || b == '_' || b == '.' || b == '~';
            if (safe) {
                target.set(ValueLayout.JAVA_BYTE, out++, (byte) b);
            } else {
                target.set(ValueLayout.JAVA_BYTE, out++, (byte) '%');
                target.set(ValueLayout.JAVA_BYTE, out++, (byte) HEX_UPPER.charAt(b >> 4));
                target.set(ValueLayout.JAVA_BYTE, out++, (byte) HEX_UPPER.charAt(b & 0xf));
            }
        }
        return (int) (out - at);
    }

    private static final String HEX_UPPER = "0123456789ABCDEF";

    /** What AWS expects: RFC 3986, and a slash is not safe. */
    public static String urlEncode(String text) {
        StringBuilder out = new StringBuilder(text.length() + 8); // seclume-allow: a user name, a key id or a secret's name - never the secret
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            boolean safe = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
            if (safe) {
                out.append(c);
            } else {
                out.append('%')
                        .append(Character.toUpperCase(Character.forDigit((c >> 4) & 0xf, 16)))
                        .append(Character.toUpperCase(Character.forDigit(c & 0xf, 16)));
            }
        }
        return out.toString();
    }
}
