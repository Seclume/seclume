package space.seclume.internal;

/**
 * Base64 that is no secret - a JWT's parts, a signature, a public key, a
 * server's answer - decoded onto the heap, in plain Java.
 *
 * <p>Not {@code java.util.Base64}: on unpatched JVMs with AVX-512 VBMI its
 * decoder runs an intrinsic that CVE-2026-114938 makes exploitable with
 * crafted input (fixed in 25.0.5.1). The text decoded here is the attacker's
 * as often as not - a token before its signature is checked, what a server
 * answered - so it is decoded by a loop of our own, which no JVM flag or
 * update changes, and strictly: no whitespace, no characters of the other
 * alphabet, the last unit whole, no bits set beyond the last byte - the
 * one point where it is stricter than the JDK, which no encoder trips over.
 */
public final class Base64Text {

    private Base64Text() {
    }

    /** RFC 4648 section 4: {@code +} and {@code /}; padding optional, as the JDK has it. */
    public static byte[] decode(String text) {
        return decode(text, false);
    }

    /** RFC 4648 section 5: {@code -} and {@code _}, padding optional - as in a JWT. */
    public static byte[] decodeUrl(String text) {
        return decode(text, true);
    }

    private static byte[] decode(String text, boolean url) {
        int length = text.length();
        int padding = 0;
        while (padding < 2 && length > 0 && text.charAt(length - 1) == '=') {
            length--;
            padding++;
        }
        int last = length % 4;
        if (last == 1) {
            throw new IllegalArgumentException("base64 of " + length + " characters is not whole");
        }
        // Padding may be left out, as java.util.Base64 lets it; given, it fills
        // the last unit exactly.
        if (padding > 0 && last + padding != 4) {
            throw new IllegalArgumentException("base64 of " + length + " characters and "
                    + padding + " padding is not whole");
        }
        byte[] out = new byte[length / 4 * 3 + (last == 0 ? 0 : last - 1)];
        int accumulator = 0;
        int bits = 0;
        int at = 0;
        for (int i = 0; i < length; i++) {
            int value = value(text.charAt(i), url);
            if (value < 0) {
                // The position only: whoever logs this need not see the text.
                throw new IllegalArgumentException("not a base64" + (url ? "url" : "")
                        + " character at position " + i);
            }
            accumulator = (accumulator << 6) | value;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out[at++] = (byte) (accumulator >>> bits);
            }
        }
        if ((accumulator & ((1 << bits) - 1)) != 0) {
            throw new IllegalArgumentException("base64 with bits set beyond its last byte");
        }
        return out;
    }

    private static int value(char c, boolean url) {
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        }
        if (c >= 'a' && c <= 'z') {
            return c - 'a' + 26;
        }
        if (c >= '0' && c <= '9') {
            return c - '0' + 52;
        }
        if (c == (url ? '-' : '+')) {
            return 62;
        }
        if (c == (url ? '_' : '/')) {
            return 63;
        }
        return -1;
    }
}
