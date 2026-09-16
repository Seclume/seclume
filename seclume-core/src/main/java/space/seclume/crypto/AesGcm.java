package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * AES-GCM (NIST SP 800-38D), entirely in native memory.
 *
 * <p>The AEAD TLS 1.3 needs, written here rather than taken from the JCA for
 * one measured reason: through {@code Cipher} the traffic key is a
 * {@code byte[]} that shows up in a heap dump and that {@code SecretKeySpec}
 * will not let anybody wipe. See {@code AeadKeyTest} and {@code docs/tls.md}.
 *
 * <p>Twelve-byte nonces only, which is what TLS 1.3 uses and what GCM is
 * defined most simply for: the counter block is the nonce followed by the
 * number one. Other lengths need the nonce hashed through GHASH first, and a
 * case that nothing here can reach is a case nothing here can test.
 *
 * <p>The tag is always sixteen bytes, and decryption compares it in constant
 * time. A tag comparison that returns early is how a forgery oracle is built.
 */
public final class AesGcm {

    private AesGcm() {
    }

    public static final int NONCE = 12;
    public static final int TAG = 16;

    /**
     * Encrypts in place and appends the tag.
     *
     * @param out receives {@code length} bytes of ciphertext and then {@link #TAG} more
     */
    public static void encrypt(AesKey key, MemorySegment nonce, long nonceOffset,
            MemorySegment aad, long aadOffset, long aadLength,
            MemorySegment in, long inOffset, long length,
            MemorySegment out, long outOffset) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment hashKey = arena.allocate(16);
            hashKey.fill((byte) 0);
            Aes.encryptBlock(key, hashKey);

            MemorySegment counter = arena.allocate(16);
            counterBlock(counter, nonce, nonceOffset);

            // J0 encrypted is what the tag is masked with, and it must be taken
            // before the counter moves on to the data.
            MemorySegment tagMask = arena.allocate(16);
            MemorySegment.copy(counter, 0, tagMask, 0, 16);
            Aes.encryptBlock(key, tagMask);

            gctr(key, counter, in, inOffset, length, out, outOffset);

            try (Ghash ghash = new Ghash(hashKey, 0)) {
                ghash.update(aad, aadOffset, aadLength);
                ghash.update(out, outOffset, length);
                ghash.updateLengths(aadLength, length);
                MemorySegment tag = arena.allocate(16);
                ghash.doFinal(tag, 0);
                for (int i = 0; i < TAG; i++) {
                    out.set(ValueLayout.JAVA_BYTE, outOffset + length + i,
                            (byte) (tag.get(ValueLayout.JAVA_BYTE, i)
                                    ^ tagMask.get(ValueLayout.JAVA_BYTE, i)));
                }
            }
            hashKey.fill((byte) 0);
            tagMask.fill((byte) 0);
        }
    }

    /**
     * Checks the tag and decrypts.
     *
     * <p>The tag is checked <b>before</b> a single byte of plaintext is handed
     * back. Decrypt-then-verify has produced padding oracles for twenty years,
     * and a caller who is given plaintext to look at before the tag is checked
     * will look at it.
     *
     * @param length the length of the ciphertext without the tag
     * @return false if the tag does not match; then nothing was written
     */
    public static boolean decrypt(AesKey key, MemorySegment nonce, long nonceOffset,
            MemorySegment aad, long aadOffset, long aadLength,
            MemorySegment in, long inOffset, long length,
            MemorySegment out, long outOffset) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment hashKey = arena.allocate(16);
            hashKey.fill((byte) 0);
            Aes.encryptBlock(key, hashKey);

            MemorySegment counter = arena.allocate(16);
            counterBlock(counter, nonce, nonceOffset);
            MemorySegment tagMask = arena.allocate(16);
            MemorySegment.copy(counter, 0, tagMask, 0, 16);
            Aes.encryptBlock(key, tagMask);

            MemorySegment expected = arena.allocate(16);
            try (Ghash ghash = new Ghash(hashKey, 0)) {
                ghash.update(aad, aadOffset, aadLength);
                ghash.update(in, inOffset, length);
                ghash.updateLengths(aadLength, length);
                ghash.doFinal(expected, 0);
            }
            int different = 0;
            for (int i = 0; i < TAG; i++) {
                int computed = (expected.get(ValueLayout.JAVA_BYTE, i)
                        ^ tagMask.get(ValueLayout.JAVA_BYTE, i)) & 0xff;
                int given = in.get(ValueLayout.JAVA_BYTE, inOffset + length + i) & 0xff;
                different |= computed ^ given;
            }
            hashKey.fill((byte) 0);
            tagMask.fill((byte) 0);
            if (different != 0) {
                return false;
            }
            gctr(key, counter, in, inOffset, length, out, outOffset);
            return true;
        }
    }

    /** The counter block of a twelve-byte nonce: the nonce, then 0x00000001. */
    private static void counterBlock(MemorySegment counter, MemorySegment nonce,
            long nonceOffset) {
        MemorySegment.copy(nonce, nonceOffset, counter, 0, NONCE);
        counter.set(ValueLayout.JAVA_BYTE, 12, (byte) 0);
        counter.set(ValueLayout.JAVA_BYTE, 13, (byte) 0);
        counter.set(ValueLayout.JAVA_BYTE, 14, (byte) 0);
        counter.set(ValueLayout.JAVA_BYTE, 15, (byte) 1);
    }

    /** CTR mode over the data, starting at the block after J0. */
    private static void gctr(AesKey key, MemorySegment counter, MemorySegment in, long inOffset,
            long length, MemorySegment out, long outOffset) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment block = arena.allocate(16);
            long at = 0;
            while (at < length) {
                increment(counter);
                MemorySegment.copy(counter, 0, block, 0, 16);
                Aes.encryptBlock(key, block);
                long take = Math.min(16, length - at);
                for (int i = 0; i < take; i++) {
                    out.set(ValueLayout.JAVA_BYTE, outOffset + at + i,
                            (byte) (in.get(ValueLayout.JAVA_BYTE, inOffset + at + i)
                                    ^ block.get(ValueLayout.JAVA_BYTE, i)));
                }
                at += take;
            }
            block.fill((byte) 0);
        }
    }

    /** The low 32 bits of the counter block, big endian, plus one. */
    private static void increment(MemorySegment counter) {
        for (int i = 15; i >= 12; i--) {
            int value = (counter.get(ValueLayout.JAVA_BYTE, i) & 0xff) + 1;
            counter.set(ValueLayout.JAVA_BYTE, i, (byte) value);
            if (value <= 0xff) {
                break;
            }
        }
    }
}
