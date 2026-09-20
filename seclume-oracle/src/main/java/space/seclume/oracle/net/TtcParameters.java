package space.seclume.oracle.net;

import java.io.IOException;

import space.seclume.internal.WireBuffer;

/**
 * The key-value encoding of TTC - how the login data travels there and back.
 *
 * <p>Oracle writes numbers in a length-prefixed form: one byte says how many
 * bytes follow, then the value big-endian. A zero is a single {@code 0x00}, a
 * 13 is {@code 01 0d}, a 257 is {@code 02 01 01}. That saves bytes on the small
 * numbers that make up most of a protocol - and it means every field has to be
 * read, none can be skipped by arithmetic.
 *
 * <p>A pair is then: length and bytes of the name, length and bytes of the
 * value, and a number of flags. The flags are not decoration - for
 * {@code AUTH_VFR_DATA} the server puts the <b>verifier type</b> in there, and
 * that decides which of the two password schemes applies.
 *
 * <p>Derived from {@code python-oracledb} 4.0.2, which Oracle publishes
 * under UPL-1.0 or Apache-2.0; see {@code PROVENANCE.md}.
 */
public final class TtcParameters {

    private TtcParameters() {
    }

    /** Writes a number in Oracle's length-prefixed form. */
    public static void putNumber(WireBuffer out, long value) {
        if (value == 0) {
            out.putByte((byte) 0);
            return;
        }
        int bytes = 8;
        while (bytes > 1 && (value >>> ((bytes - 1) * 8)) == 0) {
            bytes--;
        }
        out.putByte((byte) bytes);
        for (int i = bytes - 1; i >= 0; i--) {
            out.putByte((byte) (value >>> (i * 8)));
        }
    }

    /**
     * Writes a number with a fixed width.
     *
     * <p>Normally the shortest form is used, and the server accepts it - but
     * not everywhere. In the header of the second login stage the reference
     * client writes a 1 in two bytes, and one byte there shifts everything
     * that follows.
     */
    public static void putNumberWide(WireBuffer out, long value, int bytes) {
        out.putByte((byte) bytes);
        for (int i = bytes - 1; i >= 0; i--) {
            out.putByte((byte) (value >>> (i * 8)));
        }
    }

    /** Writes text as a length byte and its ASCII bytes. */
    public static void putText(WireBuffer out, String text) {
        out.putByte((byte) text.length());
        for (int i = 0; i < text.length(); i++) {
            out.putByte((byte) text.charAt(i));
        }
    }

    /**
     * Writes one key-value pair.
     *
     * <p>The name goes over twice-prefixed - once as a number, once as the
     * byte length. That is not redundancy in the protocol but two layers: the
     * number is the field length, the byte count belongs to the chunked byte
     * string.
     */
    public static void putPair(WireBuffer out, String name, String value, long flags) {
        putNumber(out, name.length());
        putText(out, name);
        putNumber(out, value.length());
        if (!value.isEmpty()) {
            putText(out, value);
        }
        putNumber(out, flags);
    }

    /** Reads a number in the length-prefixed form. */
    public static long number(WireBuffer in) {
        int bytes = in.getByte() & 0xff;
        long value = 0;
        for (int i = 0; i < bytes; i++) {
            value = (value << 8) | (in.getByte() & 0xff);
        }
        return value;
    }

    /**
     * Reads a length-prefixed byte string as text.
     *
     * <p>Only for names and for values that are hex or numbers - never for
     * something derived from a password. That would put it on the heap, which
     * is the one thing this library exists to prevent.
     */
    public static String text(WireBuffer in, int length) {
        int chunk = in.getByte() & 0xff;
        if (chunk != length) {
            // A value longer than 252 bytes arrives in chunks; the login
            // fields are all shorter, so this would be a misread length.
            throw new IllegalStateException("expected " + length
                    + " bytes, the chunk announces " + chunk);
        }
        char[] text = new char[length]; // seclume-allow: parameter names and hex values, protocol text and never a secret
        for (int i = 0; i < length; i++) {
            text[i] = (char) (in.getByte() & 0xff);
        }
        return new String(text); // seclume-allow: protocol text, never a secret
    }

    /** One pair as the server sends it. */
    public record Pair(String name, String value, long flags) {
    }

    /** Reads one key-value pair. */
    public static Pair readPair(WireBuffer in) throws IOException {
        int nameLength = (int) number(in);
        String name = text(in, nameLength);
        int valueLength = (int) number(in);
        String value = valueLength == 0 ? "" : text(in, valueLength);
        long flags = number(in);
        return new Pair(name, value, flags);
    }
}
