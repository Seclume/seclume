package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * AES-128/192/256 in CBC and CFB, off-heap.
 *
 * <p>Needed for Oracle's O5LOGON: there the session key arrives AES-encrypted
 * from the server and the password answer goes back AES-encrypted.
 * {@link javax.crypto.Cipher} is ruled out because key and plaintext go into it
 * as {@code byte[]}.
 *
 * <p>The state of a block operation lives in a 16 byte off-heap segment; the
 * round variables are local {@code int}s. There is no padding logic: what a
 * protocol pads is the protocol's decision. The length therefore has to be a
 * multiple of 16 - except for CFB, which as a stream cipher takes any
 * length.
 */
public final class Aes {

    /** Block size in bytes. */
    public static final int BLOCK = 16;

    private Aes() {
    }

    /**
     * CBC encryption. {@code length} has to be a multiple of 16. {@code iv}
     * stays unchanged; input and output may be the same segment.
     */
    public static void cbcEncrypt(AesKey key, MemorySegment iv,
                                  MemorySegment in, long inOffset,
                                  MemorySegment out, long outOffset, long length) {
        requireBlocks(length);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment state = arena.allocate(BLOCK);
            MemorySegment scratch = arena.allocate(BLOCK);
            MemorySegment feedback = arena.allocate(BLOCK);
            try {
                MemorySegment.copy(iv, 0, feedback, 0, BLOCK);
                for (long offset = 0; offset < length; offset += BLOCK) {
                    for (int i = 0; i < BLOCK; i++) {
                        set(state, i, (byte) (get(in, inOffset + offset + i) ^ get(feedback, i)));
                    }
                    encryptBlock(key, state, scratch);
                    MemorySegment.copy(state, 0, out, outOffset + offset, BLOCK);
                    MemorySegment.copy(state, 0, feedback, 0, BLOCK);
                }
            } finally {
                state.fill((byte) 0);
                scratch.fill((byte) 0);
                feedback.fill((byte) 0);
            }
        }
    }

    /** CBC decryption, otherwise as {@link #cbcEncrypt}. */
    public static void cbcDecrypt(AesKey key, MemorySegment iv,
                                  MemorySegment in, long inOffset,
                                  MemorySegment out, long outOffset, long length) {
        requireBlocks(length);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment state = arena.allocate(BLOCK);
            MemorySegment scratch = arena.allocate(BLOCK);
            MemorySegment feedback = arena.allocate(BLOCK);
            MemorySegment nextFeedback = arena.allocate(BLOCK);
            try {
                MemorySegment.copy(iv, 0, feedback, 0, BLOCK);
                for (long offset = 0; offset < length; offset += BLOCK) {
                    // The ciphertext of this block is the feedback for the
                    // next one - save it first, then out and in may be the
                    // same segment.
                    MemorySegment.copy(in, inOffset + offset, nextFeedback, 0, BLOCK);
                    MemorySegment.copy(in, inOffset + offset, state, 0, BLOCK);
                    decryptBlock(key, state, scratch);
                    for (int i = 0; i < BLOCK; i++) {
                        set(out, outOffset + offset + i, (byte) (get(state, i) ^ get(feedback, i)));
                    }
                    MemorySegment.copy(nextFeedback, 0, feedback, 0, BLOCK);
                }
            } finally {
                state.fill((byte) 0);
                scratch.fill((byte) 0);
                feedback.fill((byte) 0);
                nextFeedback.fill((byte) 0);
            }
        }
    }

    /**
     * CFB-128 encrypting. Any length; the last block is only used as far as
     * there is data.
     */
    public static void cfbEncrypt(AesKey key, MemorySegment iv,
                                  MemorySegment in, long inOffset,
                                  MemorySegment out, long outOffset, long length) {
        cfb(key, iv, in, inOffset, out, outOffset, length, true);
    }

    /** CFB-128 decrypting. */
    public static void cfbDecrypt(AesKey key, MemorySegment iv,
                                  MemorySegment in, long inOffset,
                                  MemorySegment out, long outOffset, long length) {
        cfb(key, iv, in, inOffset, out, outOffset, length, false);
    }

    private static void cfb(AesKey key, MemorySegment iv,
                            MemorySegment in, long inOffset,
                            MemorySegment out, long outOffset, long length,
                            boolean encrypting) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment state = arena.allocate(BLOCK);
            MemorySegment scratch = arena.allocate(BLOCK);
            MemorySegment feedback = arena.allocate(BLOCK);
            try {
                MemorySegment.copy(iv, 0, feedback, 0, BLOCK);
                for (long offset = 0; offset < length; offset += BLOCK) {
                    MemorySegment.copy(feedback, 0, state, 0, BLOCK);
                    encryptBlock(key, state, scratch);
                    int take = (int) Math.min(BLOCK, length - offset);
                    for (int i = 0; i < take; i++) {
                        byte input = get(in, inOffset + offset + i);
                        byte result = (byte) (input ^ get(state, i));
                        set(out, outOffset + offset + i, result);
                        // What is fed back is always the ciphertext.
                        set(feedback, i, encrypting ? result : input);
                    }
                }
            } finally {
                state.fill((byte) 0);
                scratch.fill((byte) 0);
                feedback.fill((byte) 0);
            }
        }
    }

    /**
     * A single block, encrypted in place. For protocols that use AES as a
     * building block (Oracle computes the session key with it).
     */
    public static void encryptBlock(AesKey key, MemorySegment state) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment scratch = arena.allocate(BLOCK);
            try {
                encryptBlock(key, state, scratch);
            } finally {
                scratch.fill((byte) 0);
            }
        }
    }

    /** A single block, decrypted in place. */
    public static void decryptBlock(AesKey key, MemorySegment state) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment scratch = arena.allocate(BLOCK);
            try {
                decryptBlock(key, state, scratch);
            } finally {
                scratch.fill((byte) 0);
            }
        }
    }

    private static void encryptBlock(AesKey key, MemorySegment state, MemorySegment scratch) {
        MemorySegment roundKeys = key.roundKeys();
        int rounds = key.rounds();
        addRoundKey(state, roundKeys, 0);
        for (int round = 1; round < rounds; round++) {
            subBytes(state, AesTables.SBOX);
            shiftRows(state, scratch, false);
            mixColumns(state);
            addRoundKey(state, roundKeys, round);
        }
        subBytes(state, AesTables.SBOX);
        shiftRows(state, scratch, false);
        addRoundKey(state, roundKeys, rounds);
    }

    private static void decryptBlock(AesKey key, MemorySegment state, MemorySegment scratch) {
        MemorySegment roundKeys = key.roundKeys();
        int rounds = key.rounds();
        addRoundKey(state, roundKeys, rounds);
        for (int round = rounds - 1; round >= 1; round--) {
            shiftRows(state, scratch, true);
            subBytes(state, AesTables.INV_SBOX);
            addRoundKey(state, roundKeys, round);
            invMixColumns(state);
        }
        shiftRows(state, scratch, true);
        subBytes(state, AesTables.INV_SBOX);
        addRoundKey(state, roundKeys, 0);
    }

    private static void addRoundKey(MemorySegment state, MemorySegment roundKeys, int round) {
        for (int column = 0; column < 4; column++) {
            int word = roundKeys.get(BlockDigest.BE_INT, (round * 4L + column) * 4L);
            for (int row = 0; row < 4; row++) {
                int index = row + 4 * column;
                int keyByte = (word >>> (24 - 8 * row)) & 0xff;
                set(state, index, (byte) (get(state, index) ^ keyByte));
            }
        }
    }

    private static void subBytes(MemorySegment state, byte[] box) {
        for (int i = 0; i < BLOCK; i++) {
            set(state, i, box[get(state, i) & 0xff]);
        }
    }

    /**
     * ShiftRows, or its inverse. The state is laid out in input order, that is
     * {@code state[row + 4 * column]}.
     */
    private static void shiftRows(MemorySegment state, MemorySegment scratch, boolean inverse) {
        MemorySegment.copy(state, 0, scratch, 0, BLOCK);
        for (int row = 1; row < 4; row++) {
            for (int column = 0; column < 4; column++) {
                int from = inverse ? Math.floorMod(column - row, 4) : (column + row) % 4;
                set(state, row + 4 * column, get(scratch, row + 4 * from));
            }
        }
    }

    private static void mixColumns(MemorySegment state) {
        for (int column = 0; column < 4; column++) {
            int base = 4 * column;
            int a0 = get(state, base) & 0xff;
            int a1 = get(state, base + 1) & 0xff;
            int a2 = get(state, base + 2) & 0xff;
            int a3 = get(state, base + 3) & 0xff;
            set(state, base, (byte) (AesTables.xtime(a0) ^ AesTables.xtime(a1) ^ a1 ^ a2 ^ a3));
            set(state, base + 1, (byte) (a0 ^ AesTables.xtime(a1) ^ AesTables.xtime(a2) ^ a2 ^ a3));
            set(state, base + 2, (byte) (a0 ^ a1 ^ AesTables.xtime(a2) ^ AesTables.xtime(a3) ^ a3));
            set(state, base + 3, (byte) (AesTables.xtime(a0) ^ a0 ^ a1 ^ a2 ^ AesTables.xtime(a3)));
        }
    }

    private static void invMixColumns(MemorySegment state) {
        for (int column = 0; column < 4; column++) {
            int base = 4 * column;
            int a0 = get(state, base) & 0xff;
            int a1 = get(state, base + 1) & 0xff;
            int a2 = get(state, base + 2) & 0xff;
            int a3 = get(state, base + 3) & 0xff;
            set(state, base, (byte) (AesTables.multiply(a0, 14) ^ AesTables.multiply(a1, 11)
                    ^ AesTables.multiply(a2, 13) ^ AesTables.multiply(a3, 9)));
            set(state, base + 1, (byte) (AesTables.multiply(a0, 9) ^ AesTables.multiply(a1, 14)
                    ^ AesTables.multiply(a2, 11) ^ AesTables.multiply(a3, 13)));
            set(state, base + 2, (byte) (AesTables.multiply(a0, 13) ^ AesTables.multiply(a1, 9)
                    ^ AesTables.multiply(a2, 14) ^ AesTables.multiply(a3, 11)));
            set(state, base + 3, (byte) (AesTables.multiply(a0, 11) ^ AesTables.multiply(a1, 13)
                    ^ AesTables.multiply(a2, 9) ^ AesTables.multiply(a3, 14)));
        }
    }

    private static void requireBlocks(long length) {
        if (length % BLOCK != 0) {
            throw new IllegalArgumentException("CBC needs a multiple of 16 bytes, got " + length);
        }
    }

    private static byte get(MemorySegment segment, long offset) {
        return segment.get(ValueLayout.JAVA_BYTE, offset);
    }

    private static void set(MemorySegment segment, long offset, byte value) {
        segment.set(ValueLayout.JAVA_BYTE, offset, value);
    }
}
