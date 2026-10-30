package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;

/**
 * AES-GCM-SIV (RFC 8452), entirely in native memory.
 *
 * <p>The AEAD of seclume's field encryption, chosen over AES-GCM for one
 * property: it survives a repeated nonce. GCM with a nonce used twice gives
 * away the XOR of the two plaintexts and the hash key, from which anyone can
 * forge. GCM-SIV derives the counter from a hash of the message, so a repeated
 * nonce reveals only that two messages were equal - and that is exactly what a
 * deterministic, searchable column needs: one fixed nonce per column makes it a
 * deterministic authenticated encryption, with equality as the only leak.
 *
 * <p>Built from the pieces seclume already has for TLS. POLYVAL is GHASH with
 * the bytes turned around (RFC 8452, appendix A), so it runs on {@link Ghash}
 * and inherits its branch-free multiplication; the block cipher is
 * {@link Aes} with its constant-time S-box. The per-nonce keys are derived
 * into memory of this call and wiped before it returns.
 *
 * <p>Twelve-byte nonce, sixteen-byte tag, 16- or 32-byte key: the only
 * parameters RFC 8452 defines. Decryption checks the tag in constant time and,
 * if it does not match, wipes the plaintext it had to produce to compute it -
 * SIV decrypts before it can verify, so "nothing handed out" is kept by
 * erasing rather than by not writing.
 */
public final class AesGcmSiv {

    public static final int NONCE = 12;
    public static final int TAG = 16;

    /** RFC 8452 section 6: P and A are each at most 2^36 bytes. */
    static final long MAX_LENGTH = 1L << 36;

    private static final ValueLayout.OfLong BE_LONG =
            ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.BIG_ENDIAN);
    private static final ValueLayout.OfInt LE_INT =
            ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

    /** The reduction constant of {@link Ghash}, for multiplying by x there. */
    private static final long R = 0xe100000000000000L;

    private AesGcmSiv() {
    }

    /**
     * Encrypts and appends the tag.
     *
     * @param key 16 or 32 bytes from {@code keyOffset}: the key-generating key
     * @param out receives {@code length} bytes of ciphertext and then {@link #TAG}
     *            more; it may be {@code in} itself, at the same offset
     */
    public static void encrypt(MemorySegment key, long keyOffset, int keyLength,
            MemorySegment nonce, long nonceOffset,
            MemorySegment aad, long aadOffset, long aadLength,
            MemorySegment in, long inOffset, long length,
            MemorySegment out, long outOffset) {
        checkLengths(aadLength, length);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keys = deriveKeys(key, keyOffset, keyLength, nonce, nonceOffset, arena);
            MemorySegment tag = arena.allocate(16);
            try (AesKey encryption = new AesKey(keys, 16, keyLength)) {
                tag(keys, encryption, nonce, nonceOffset, aad, aadOffset, aadLength,
                        in, inOffset, length, tag, arena);
                ctr(encryption, tag, in, inOffset, length, out, outOffset, arena);
                MemorySegment.copy(tag, 0, out, outOffset + length, TAG);
            } finally {
                keys.fill((byte) 0);
            }
        }
    }

    /**
     * Decrypts and checks the tag.
     *
     * @param length the length of the ciphertext without the tag
     * @param out    receives {@code length} bytes; on a mismatch it holds zeroes
     * @return false if the tag does not match
     */
    public static boolean decrypt(MemorySegment key, long keyOffset, int keyLength,
            MemorySegment nonce, long nonceOffset,
            MemorySegment aad, long aadOffset, long aadLength,
            MemorySegment in, long inOffset, long length,
            MemorySegment out, long outOffset) {
        checkLengths(aadLength, length);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keys = deriveKeys(key, keyOffset, keyLength, nonce, nonceOffset, arena);
            MemorySegment given = arena.allocate(16);
            MemorySegment.copy(in, inOffset + length, given, 0, TAG);
            MemorySegment expected = arena.allocate(16);
            try (AesKey encryption = new AesKey(keys, 16, keyLength)) {
                ctr(encryption, given, in, inOffset, length, out, outOffset, arena);
                tag(keys, encryption, nonce, nonceOffset, aad, aadOffset, aadLength,
                        out, outOffset, length, expected, arena);
            } finally {
                keys.fill((byte) 0);
            }
            if (!ConstantTime.equals(expected, given)) {
                out.asSlice(outOffset, length).fill((byte) 0);
                return false;
            }
            return true;
        }
    }

    private static void checkLengths(long aadLength, long length) {
        if (aadLength < 0 || aadLength > MAX_LENGTH || length < 0 || length > MAX_LENGTH) {
            throw new IllegalArgumentException("AES-GCM-SIV takes at most 2^36 bytes of data "
                    + "and of associated data");
        }
    }

    /**
     * RFC 8452 section 4: AES under the key-generating key of
     * {@code LE32(i) || nonce}, the first eight bytes of each. Sixteen bytes
     * of message-authentication key, then 16 or 32 of message-encryption key.
     */
    private static MemorySegment deriveKeys(MemorySegment key, long keyOffset, int keyLength,
            MemorySegment nonce, long nonceOffset, Arena arena) {
        if (keyLength != 16 && keyLength != 32) {
            throw new IllegalArgumentException("AES-GCM-SIV keys are 16 or 32 bytes, got "
                    + keyLength);
        }
        int count = keyLength == 16 ? 4 : 6;
        MemorySegment keys = arena.allocate(16 + keyLength);
        MemorySegment blocks = arena.allocate(4 * 16L);
        MemorySegment scratch = arena.allocate(16);
        try (AesKey generating = new AesKey(key, keyOffset, keyLength)) {
            for (int first = 0; first < count; first += 4) {
                int take = Math.min(4, count - first);
                for (int b = 0; b < take; b++) {
                    blocks.set(LE_INT, b * 16L, first + b);
                    MemorySegment.copy(nonce, nonceOffset, blocks, b * 16L + 4, NONCE);
                }
                Aes.encryptBlocks(generating, blocks, take, scratch);
                for (int b = 0; b < take; b++) {
                    MemorySegment.copy(blocks, b * 16L, keys, (first + b) * 8L, 8);
                }
            }
        } finally {
            blocks.fill((byte) 0);
            scratch.fill((byte) 0);
        }
        return keys;
    }

    /**
     * RFC 8452 section 4: POLYVAL over the padded AAD, the padded plaintext
     * and their bit lengths; the nonce XORed into the first twelve bytes, the
     * top bit cleared, and the whole block encrypted.
     */
    private static void tag(MemorySegment keys, AesKey encryption,
            MemorySegment nonce, long nonceOffset,
            MemorySegment aad, long aadOffset, long aadLength,
            MemorySegment plain, long plainOffset, long length,
            MemorySegment tag, Arena arena) {
        MemorySegment hashKey = arena.allocate(16);
        MemorySegment block = arena.allocate(16);
        try {
            ghashKey(keys, hashKey);
            try (Ghash ghash = new Ghash(hashKey, 0)) {
                polyval(ghash, aad, aadOffset, aadLength, block);
                polyval(ghash, plain, plainOffset, length, block);
                // LE64(bits of A) || LE64(bits of P), turned around.
                block.set(BE_LONG, 0, length * 8);
                block.set(BE_LONG, 8, aadLength * 8);
                ghash.update(block, 0);
                ghash.doFinal(block, 0);
            }
            for (int i = 0; i < 16; i++) {
                tag.set(ValueLayout.JAVA_BYTE, i, block.get(ValueLayout.JAVA_BYTE, 15 - i));
            }
            for (int i = 0; i < NONCE; i++) {
                tag.set(ValueLayout.JAVA_BYTE, i, (byte) (tag.get(ValueLayout.JAVA_BYTE, i)
                        ^ nonce.get(ValueLayout.JAVA_BYTE, nonceOffset + i)));
            }
            tag.set(ValueLayout.JAVA_BYTE, 15,
                    (byte) (tag.get(ValueLayout.JAVA_BYTE, 15) & 0x7f));
            Aes.encryptBlock(encryption, tag);
        } finally {
            hashKey.fill((byte) 0);
            block.fill((byte) 0);
        }
    }

    /**
     * GHASH's key for POLYVAL's: mulX_GHASH(ByteReverse(H)), RFC 8452
     * appendix A. Multiplying by x in GHASH's bit order is one step of
     * {@link Ghash}'s own loop - a shift and a masked reduction, no branch.
     */
    private static void ghashKey(MemorySegment keys, MemorySegment out) {
        for (int i = 0; i < 16; i++) {
            out.set(ValueLayout.JAVA_BYTE, i, keys.get(ValueLayout.JAVA_BYTE, 15 - i));
        }
        long high = out.get(BE_LONG, 0);
        long low = out.get(BE_LONG, 8);
        long carry = -(low & 1L);
        low = (low >>> 1) | (high << 63);
        high = (high >>> 1) ^ (R & carry);
        out.set(BE_LONG, 0, high);
        out.set(BE_LONG, 8, low);
    }

    /** Each sixteen-byte block, zero-padded at its end, turned around and fed to GHASH. */
    private static void polyval(Ghash ghash, MemorySegment data, long offset, long length,
            MemorySegment block) {
        for (long at = 0; at < length; at += 16) {
            int take = (int) Math.min(16, length - at);
            block.fill((byte) 0);
            for (int i = 0; i < take; i++) {
                block.set(ValueLayout.JAVA_BYTE, 15 - i,
                        data.get(ValueLayout.JAVA_BYTE, offset + at + i));
            }
            ghash.update(block, 0);
        }
        block.fill((byte) 0);
    }

    /**
     * AES-CTR from the tag with its top bit set, the counter being the first
     * four bytes, little endian, wrapping at 2^32.
     */
    private static void ctr(AesKey key, MemorySegment tag, MemorySegment in, long inOffset,
            long length, MemorySegment out, long outOffset, Arena arena) {
        MemorySegment counter = arena.allocate(16);
        MemorySegment blocks = arena.allocate(4 * 16L);
        MemorySegment scratch = arena.allocate(16);
        try {
            MemorySegment.copy(tag, 0, counter, 0, 16);
            counter.set(ValueLayout.JAVA_BYTE, 15,
                    (byte) (counter.get(ValueLayout.JAVA_BYTE, 15) | 0x80));
            long at = 0;
            while (at < length) {
                int count = (int) Math.min(4, (length - at + 15) / 16);
                for (int b = 0; b < count; b++) {
                    MemorySegment.copy(counter, 0, blocks, b * 16L, 16);
                    counter.set(LE_INT, 0, counter.get(LE_INT, 0) + 1);
                }
                Aes.encryptBlocks(key, blocks, count, scratch);
                int take = (int) Math.min(count * 16L, length - at);
                for (int i = 0; i < take; i++) {
                    out.set(ValueLayout.JAVA_BYTE, outOffset + at + i,
                            (byte) (in.get(ValueLayout.JAVA_BYTE, inOffset + at + i)
                                    ^ blocks.get(ValueLayout.JAVA_BYTE, i)));
                }
                at += take;
            }
        } finally {
            counter.fill((byte) 0);
            blocks.fill((byte) 0);
            scratch.fill((byte) 0);
        }
    }
}
