package space.seclume.crypto;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.lang.foreign.ValueLayout;

/**
 * HKDF (RFC 5869), off-heap, on top of the {@link Hmac} already here.
 *
 * <p>Two functions and no state. Extract turns key material of any shape into a
 * pseudorandom key of one hash length; expand turns that into as many bytes as
 * are asked for. TLS 1.3 is built almost entirely out of the pair, which is why
 * this is the first thing the TLS work needs.
 *
 * <p><b>Everything stays in native memory.</b> Inputs and outputs are
 * {@link MemorySegment}s and nothing is copied to a {@code byte[]} on the way
 * through, because what travels through here is key material and the whole
 * point of this library is that key material is not on the Java heap.
 */
public final class Hkdf {

    private Hkdf() {
    }

    /**
     * {@code HKDF-Extract(salt, IKM)} - one HMAC, salt as the key.
     *
     * @param out receives {@code macLength} bytes
     */
    public static void extract(HashAlgorithm algorithm, MemorySegment salt, MemorySegment ikm,
            MemorySegment out, long outOffset) {
        try (Hmac hmac = new Hmac(algorithm, salt)) {
            hmac.update(ikm);
            hmac.doFinal(out, outOffset);
        }
    }

    /**
     * {@code HKDF-Expand(PRK, info, L)}.
     *
     * <p>T(1) = HMAC(PRK, info || 0x01), and every block after it starts with
     * the previous one. The counter is a single byte, so no more than 255 hash
     * lengths can ever be asked for - the check is here rather than left to
     * produce quietly wrong bytes at block 256.
     */
    public static void expand(HashAlgorithm algorithm, MemorySegment prk, MemorySegment info,
            MemorySegment out, long outOffset, int length) {
        int macLength;
        try (Hmac probe = new Hmac(algorithm, prk)) {
            macLength = probe.macLength();
        }
        int blocks = (length + macLength - 1) / macLength;
        if (blocks > 255) {
            throw new IllegalArgumentException("HKDF-Expand can produce at most 255 blocks, "
                    + length + " bytes would need " + blocks);
        }
        try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
            MemorySegment previous = arena.allocate(macLength);
            MemorySegment block = arena.allocate(macLength);
            int written = 0;
            for (int counter = 1; counter <= blocks; counter++) {
                try (Hmac hmac = new Hmac(algorithm, prk)) {
                    if (counter > 1) {
                        hmac.update(previous);
                    }
                    if (info != null && info.byteSize() > 0) {
                        hmac.update(info);
                    }
                    hmac.update((byte) counter);
                    hmac.doFinal(block, 0);
                }
                int take = Math.min(macLength, length - written);
                MemorySegment.copy(block, 0, out, outOffset + written, take);
                MemorySegment.copy(block, 0, previous, 0, macLength);
                written += take;
            }
            // The last block held key material that nobody asked for.
            previous.fill((byte) 0);
            block.fill((byte) 0);
        }
    }

    /**
     * {@code HKDF-Expand-Label} of RFC 8446, section 7.1.
     *
     * <p>The info string is a structure rather than a concatenation, and its
     * shape is where this is easy to get subtly wrong: a two-byte length, then
     * a one-byte-prefixed label that always begins with {@code "tls13 "}, then
     * a one-byte-prefixed context. Getting the prefix or the order wrong yields
     * bytes that look perfectly random and agree with nothing.
     */
    public static void expandLabel(HashAlgorithm algorithm, MemorySegment secret, String label,
            MemorySegment context, MemorySegment out, long outOffset, int length) {
        // The label is a constant of the protocol - "derived", "key", "iv",
        // "c hs traffic" - and never a secret. What must stay off the heap is
        // the segment it is applied to, and that never leaves native memory.
        String prefixed = "tls13 " + label;
        byte[] full = prefixed.getBytes(StandardCharsets.US_ASCII); // seclume-allow: a label
        if (full.length > 255) {
            throw new IllegalArgumentException("label too long: " + label);
        }
        long contextLength = context == null ? 0 : context.byteSize();
        if (contextLength > 255) {
            throw new IllegalArgumentException("context too long: " + contextLength + " bytes");
        }
        try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
            MemorySegment info = arena.allocate(2 + 1 + full.length + 1 + contextLength);
            int at = 0;
            info.set(ValueLayout.JAVA_BYTE, at++, (byte) (length >>> 8));
            info.set(ValueLayout.JAVA_BYTE, at++, (byte) length);
            info.set(ValueLayout.JAVA_BYTE, at++, (byte) full.length);
            MemorySegment.copy(full, 0, info, ValueLayout.JAVA_BYTE, at, full.length);
            at += full.length;
            info.set(ValueLayout.JAVA_BYTE, at++, (byte) contextLength);
            if (contextLength > 0) {
                MemorySegment.copy(context, 0, info, at, contextLength);
            }
            expand(algorithm, secret, info, out, outOffset, length);
        }
    }
}
