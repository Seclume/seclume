package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.internal.Entropy;

/**
 * RSA encryption with a public key, off-heap.
 *
 * <p>Exactly one use case, but an unavoidable one: MySQL's
 * {@code caching_sha2_password} and {@code sha256_password} send the password
 * RSA-encrypted to the server over an unencrypted connection. Without it you
 * cannot log in to a MySQL without TLS.
 *
 * <p>There is no decryption here - a client does not need it, and unused crypto
 * code is just one more place where something can be wrong.
 */
public final class Rsa {

    private Rsa() {
    }

    /**
     * RSAES-PKCS1-v1_5 (RFC 8017, 7.2.1).
     *
     * <p>The MySQL login does not need it - there it is OAEP, for
     * {@code sha256_password} just as for {@code caching_sha2_password}. This
     * padding stands ready for servers that do ask for it, and because its
     * vectors exercise the arithmetic core as well.
     *
     * @return the ciphertext length, always {@link RsaPublicKey#modulusBytes()}
     */
    public static int encryptPkcs1(RsaPublicKey key,
                                   MemorySegment message, long messageOffset, int messageLength,
                                   MemorySegment out, long outOffset) {
        int k = key.modulusBytes();
        if (messageLength > k - 11) {
            throw new IllegalArgumentException(
                    "message of " + messageLength + " bytes is too long for a "
                    + (k * 8) + " bit key");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment block = arena.allocate(k);
            try {
                int paddingLength = k - messageLength - 3;
                block.set(ValueLayout.JAVA_BYTE, 0, (byte) 0x00);
                block.set(ValueLayout.JAVA_BYTE, 1, (byte) 0x02);
                Entropy.fillNonZero(block, 2, paddingLength);
                block.set(ValueLayout.JAVA_BYTE, 2 + paddingLength, (byte) 0x00);
                MemorySegment.copy(message, messageOffset, block,
                        3L + paddingLength, messageLength);
                return raw(key, block, out, outOffset, arena);
            } finally {
                block.fill((byte) 0);
            }
        }
    }

    /**
     * RSAES-OAEP (RFC 8017, 7.1.1) with an empty label.
     *
     * <p>MySQL uses OAEP-SHA1 for {@code caching_sha2_password} and
     * {@code sha256_password}; newer servers can do SHA-256 as well, which is
     * why the hash is a parameter.
     */
    public static int encryptOaep(RsaPublicKey key, HashAlgorithm hash,
                                  MemorySegment message, long messageOffset, int messageLength,
                                  MemorySegment out, long outOffset) {
        int k = key.modulusBytes();
        int hLen = hash.digestLength();
        if (messageLength > k - 2 * hLen - 2) {
            throw new IllegalArgumentException(
                    "message of " + messageLength + " bytes is too long for OAEP with "
                    + hash + " and a " + (k * 8) + " bit key");
        }
        int dbLength = k - hLen - 1;

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment block = arena.allocate(k);
            MemorySegment seed = arena.allocate(hLen);
            MemorySegment mask = arena.allocate(Math.max(dbLength, hLen));
            try {
                // EM = 0x00 || maskedSeed || maskedDB, with DB built right
                // where it belongs - one fewer copy holding the password.
                MemorySegment db = block.asSlice(1L + hLen, dbLength);
                hash.hash(block.asSlice(0, 0), 0, 0, db, 0);   // lHash over the empty label
                db.asSlice(hLen, dbLength - hLen - messageLength - 1).fill((byte) 0);
                db.set(ValueLayout.JAVA_BYTE, dbLength - messageLength - 1, (byte) 0x01);
                MemorySegment.copy(message, messageOffset, db,
                        dbLength - messageLength, messageLength);

                Entropy.fill(seed);
                mgf1(hash, seed, 0, hLen, mask, dbLength);
                xor(db, mask, dbLength);

                mgf1(hash, db, 0, dbLength, mask, hLen);
                xor(seed, mask, hLen);

                block.set(ValueLayout.JAVA_BYTE, 0, (byte) 0x00);
                MemorySegment.copy(seed, 0, block, 1, hLen);

                return raw(key, block, out, outOffset, arena);
            } finally {
                block.fill((byte) 0);
                seed.fill((byte) 0);
                mask.fill((byte) 0);
            }
        }
    }

    /** MGF1 from RFC 8017, appendix B.2.1. */
    static void mgf1(HashAlgorithm hash, MemorySegment seed, long seedOffset, int seedLength,
                     MemorySegment out, int outLength) {
        int hLen = hash.digestLength();
        try (Arena arena = Arena.ofConfined();
             Digest digest = hash.newDigest()) {
            MemorySegment counter = arena.allocate(4);
            MemorySegment chunk = arena.allocate(hLen);
            try {
                int produced = 0;
                for (int block = 0; produced < outLength; block++) {
                    counter.set(BlockDigest.BE_INT, 0, block);
                    digest.update(seed, seedOffset, seedLength);
                    digest.update(counter, 0, 4);
                    digest.digest(chunk, 0);
                    int take = Math.min(hLen, outLength - produced);
                    MemorySegment.copy(chunk, 0, out, produced, take);
                    produced += take;
                }
            } finally {
                counter.fill((byte) 0);
                chunk.fill((byte) 0);
            }
        }
    }

    /** {@code target ^= source} over {@code length} bytes. */
    private static void xor(MemorySegment target, MemorySegment source, int length) {
        for (int i = 0; i < length; i++) {
            byte value = (byte) (target.get(ValueLayout.JAVA_BYTE, i)
                    ^ source.get(ValueLayout.JAVA_BYTE, i));
            target.set(ValueLayout.JAVA_BYTE, i, value);
        }
    }

    /** m^e mod n on the fully padded block. */
    private static int raw(RsaPublicKey key, MemorySegment block,
                           MemorySegment out, long outOffset, Arena arena) {
        return raw(key, block, 0, out, outOffset, arena);
    }

    private static int raw(RsaPublicKey key, MemorySegment block, long blockOffset,
                           MemorySegment out, long outOffset, Arena arena) {
        int k = key.modulusBytes();
        int words = key.words();
        MemorySegment base = arena.allocate(words * 4L);
        MemorySegment result = arena.allocate(words * 4L);
        try {
            BigWords.fromBytes(block, blockOffset, k, base, words);
            BigWords.modPow(base, key.exponentBytes(), 0, key.exponentLength(),
                    key.modulusWords(), words, result, arena);
            BigWords.toBytes(result, words, out, outOffset, k);
            return k;
        } finally {
            base.fill((byte) 0);
            result.fill((byte) 0);
        }
    }

    /**
     * The raw RSA public-key operation, {@code m = s^e mod n} (RFC 8017,
     * section 5.2.2, RSAVP1) - on an already {@code modulusBytes()}-long
     * block, with no padding applied or removed.
     *
     * <p>{@link #encryptPkcs1} and {@link #encryptOaep} build a padded block
     * and never let the caller see it recovered. Signature schemes need the
     * opposite: recover {@code m} from a signature and check its own padding
     * by hand (see {@code RsaPss}), which is a different operation from
     * either encryption padding even though the arithmetic underneath is the
     * one this class already has.
     */
    public static void publicOperation(RsaPublicKey key, MemorySegment block, long blockOffset,
                                       MemorySegment out, long outOffset) {
        try (Arena arena = Arena.ofConfined()) {
            raw(key, block, blockOffset, out, outOffset, arena);
        }
    }
}
