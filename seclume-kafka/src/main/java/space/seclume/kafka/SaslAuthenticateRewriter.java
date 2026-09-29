package space.seclume.kafka;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

import space.seclume.internal.SeclumeSslEngine;
import space.seclume.secret.SecretScope;

/**
 * Follows the Kafka requests a client sends, frame by frame, and writes the
 * secret into the one that carries it: a SaslAuthenticate request (API key
 * 36) whose auth bytes hold a placeholder of {@link SaslPlaceholders}.
 *
 * <p>That request is rebuilt in native memory - the placeholder replaced by
 * the secret, and the two lengths that follow from it, the auth bytes' and
 * the frame's, written there as well: a length is a fact about the secret.
 * Every other byte goes through unchanged, and nothing is looked at beyond
 * each frame's size and API key.
 *
 * <p>The frames: a four-byte size, then the request header - API key,
 * version, correlation id, client id (int16 length), and from
 * SaslAuthenticate v2 on the tagged fields - then the auth bytes, an int32
 * length before v2 and an unsigned varint of length + 1 after.
 */
final class SaslAuthenticateRewriter implements SeclumeSslEngine.Outgoing {

    static final short SASL_AUTHENTICATE = 36;

    /** Bytes of the current request not yet passed on; 0 at the start of the next. */
    private long remaining;

    @Override
    public Step next(ByteBuffer plain) throws IOException {
        if (remaining == 0) {
            if (plain.remaining() < 6) {
                throw new IOException("a Kafka request whose size and API key arrived apart");
            }
            int at = plain.position();
            int size = plain.getInt(at);
            if (size < 2) {
                throw new IOException("a Kafka request of " + size + " bytes");
            }
            long total = size + 4L;
            if (plain.getShort(at + 4) == SASL_AUTHENTICATE && total <= plain.remaining()) {
                Step replaced = replace(plain, at, (int) total);
                if (replaced != null) {
                    return replaced;
                }
            }
            remaining = total;
        }
        int n = (int) Math.min(Math.min(remaining, plain.remaining()),
                SeclumeSslEngine.MAX_PLAINTEXT);
        remaining -= n;
        return Step.unchanged(n);
    }

    /** The request rebuilt with the secret, or null when it carries no placeholder. */
    static Step replace(ByteBuffer plain, int at, int total) throws IOException {
        int end = at + total;
        int placeholder = indexOf(plain, at, end, SaslPlaceholders.PREFIX);
        if (placeholder < 0) {
            return null;
        }
        int placeholderEnd = placeholder + SaslPlaceholders.PREFIX.length;
        while (placeholderEnd < end && SaslPlaceholders.placeholderChar(plain.get(placeholderEnd))) {
            placeholderEnd++;
        }
        byte[] name = new byte[placeholderEnd - placeholder];
        plain.get(placeholder, name);

        short version = plain.getShort(at + 6);
        boolean flexible = version >= 2;
        int p = at + 12;                                     // after size, key, version, id
        short clientIdLength = plain.getShort(p);
        p += 2 + Math.max(0, clientIdLength);
        if (flexible) {
            p = skipTaggedFields(plain, p, end);
        }
        int lengthAt = p;
        long authLength;
        int authStart;
        if (flexible) {
            long[] varint = unsignedVarint(plain, p, end);
            authLength = varint[0] - 1;
            authStart = p + (int) varint[1];
        } else {
            authLength = plain.getInt(p);
            authStart = p + 4;
        }
        long authEnd = authStart + authLength;
        if (authLength < 0 || authEnd > end || placeholder < authStart
                || placeholderEnd > authEnd) {
            throw new IOException("a placeholder outside the auth bytes of a SaslAuthenticate "
                    + "request - not sent");
        }
        SecretScope secret = SaslPlaceholders.take(new String(name, StandardCharsets.US_ASCII)); // seclume-allow: the placeholder's name, not the secret
        if (secret == null) {
            throw new IOException("a SaslAuthenticate request with a placeholder that stands "
                    + "for nothing - its login was closed, or it was sent twice");
        }
        try (secret) {
            long newAuthLength = authLength - name.length + secret.length();
            byte[] lengthField = flexible ? unsignedVarint(newAuthLength + 1)
                    : ByteBuffer.allocate(4).putInt((int) newAuthLength).array(); // seclume-allow: a length, written off the heap below; this array holds the length only
            long newTotal = (long) total - (authStart - lengthAt) + lengthField.length
                    - name.length + secret.length();
            if (newTotal > SeclumeSslEngine.MAX_PLAINTEXT) {
                throw new IOException("the SaslAuthenticate request would be " + newTotal
                        + " bytes with the secret in it - more than one TLS record");
            }
            MemorySegment source = MemorySegment.ofBuffer(plain.duplicate().clear());
            SecretScope out = SecretScope.allocate((int) newTotal);
            try {
                MemorySegment o = out.segment();
                o.set(ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.BIG_ENDIAN), 0,
                        (int) (newTotal - 4));
                long w = 4;
                MemorySegment.copy(source, at + 4, o, w, lengthAt - (at + 4));
                w += lengthAt - (at + 4);
                MemorySegment.copy(lengthField, 0, o, ValueLayout.JAVA_BYTE, w,
                        lengthField.length);
                w += lengthField.length;
                MemorySegment.copy(source, authStart, o, w, placeholder - authStart);
                w += placeholder - authStart;
                MemorySegment.copy(secret.segment(), 0, o, w, secret.length());
                w += secret.length();
                MemorySegment.copy(source, placeholderEnd, o, w, end - placeholderEnd);
                w += end - placeholderEnd;
                out.length((int) w);
            } catch (RuntimeException e) {
                out.close();
                throw e;
            }
            return Step.replace(total, out);
        }
    }

    private static int skipTaggedFields(ByteBuffer in, int p, int end) throws IOException {
        long[] count = unsignedVarint(in, p, end);
        p += (int) count[1];
        for (long i = 0; i < count[0]; i++) {
            p += (int) unsignedVarint(in, p, end)[1];                  // the tag
            long[] size = unsignedVarint(in, p, end);
            p += (int) size[1] + (int) size[0];
        }
        return p;
    }

    /** {value, bytes it took}. */
    private static long[] unsignedVarint(ByteBuffer in, int p, int end) throws IOException {
        long value = 0;
        for (int i = 0; i < 5; i++) {
            if (p + i >= end) {
                break;
            }
            int b = in.get(p + i) & 0xff;
            value |= (long) (b & 0x7f) << (7 * i);
            if ((b & 0x80) == 0) {
                return new long[] {value, i + 1};
            }
        }
        throw new IOException("a malformed varint in a SaslAuthenticate request");
    }

    private static byte[] unsignedVarint(long value) {
        byte[] out = new byte[5];
        int n = 0;
        while ((value & ~0x7fL) != 0) {
            out[n++] = (byte) ((value & 0x7f) | 0x80);
            value >>>= 7;
        }
        out[n++] = (byte) value;
        return java.util.Arrays.copyOf(out, n);
    }

    private static int indexOf(ByteBuffer in, int from, int to, byte[] what) {
        outer:
        for (int i = from; i <= to - what.length; i++) {
            for (int j = 0; j < what.length; j++) {
                if (in.get(i + j) != what[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
