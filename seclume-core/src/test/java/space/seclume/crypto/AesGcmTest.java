package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.SecureRandom;
import java.util.HexFormat;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Our AES-GCM against the JDK's, byte for byte.
 *
 * <p>SunJCE is the oracle here, and it is a fair one: a different
 * implementation by different people, shipped with the platform. This is the
 * same move as checking the AWS signature against a few lines of Python -
 * comparing an implementation with itself proves only that it is
 * deterministic, and a cipher that is deterministically wrong produces
 * ciphertext no server will ever open.
 *
 * <p>The JDK may not be used for this in production - {@code AeadKeyTest} shows
 * why, the traffic key ends up in a heap dump and cannot be wiped - but nothing
 * stops a test from using it as a measuring stick.
 *
 * <p>The sizes are chosen where GCM goes wrong: zero, one byte, one byte short
 * of a block, exactly a block, one byte past it. Every one of those exercises
 * the zero padding of GHASH or the partial last block of CTR, and an
 * implementation that only ever sees round numbers passes while being wrong.
 */
class AesGcmTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final SecureRandom RANDOM = new SecureRandom();

    @ParameterizedTest
    @CsvSource({
        "0, 0", "0, 16", "1, 0", "1, 1", "15, 0", "16, 0", "17, 0",
        "15, 15", "16, 16", "17, 13", "64, 20", "1000, 333", "4096, 0",
    })
    void matchesTheJdkExactly(int dataLength, int aadLength) throws Exception {
        byte[] key = random(32);
        byte[] nonce = random(12);
        byte[] aad = random(aadLength);
        byte[] plain = random(dataLength);

        byte[] theirs = jdkEncrypt(key, nonce, aad, plain);
        byte[] ours = encrypt(key, nonce, aad, plain);

        assertArrayEquals(theirs, ours,
                "ciphertext and tag differ for " + dataLength + " bytes and "
                        + aadLength + " of additional data\n  jdk: " + HEX.formatHex(theirs)
                        + "\n  ours: " + HEX.formatHex(ours));
    }

    /** And the other direction: what the JDK produced, we open. */
    @ParameterizedTest
    @CsvSource({"0, 0", "1, 3", "16, 16", "17, 13", "1000, 333"})
    void opensWhatTheJdkSealed(int dataLength, int aadLength) throws Exception {
        byte[] key = random(32);
        byte[] nonce = random(12);
        byte[] aad = random(aadLength);
        byte[] plain = random(dataLength);
        byte[] sealed = jdkEncrypt(key, nonce, aad, plain);

        byte[] opened = new byte[dataLength];
        assertTrue(decrypt(key, nonce, aad, sealed, opened), "the tag was rejected");
        assertArrayEquals(plain, opened);
    }

    /** AES-128 as well, since the key schedule differs. */
    @Test
    void worksWithAes128() throws Exception {
        byte[] key = random(16);
        byte[] nonce = random(12);
        byte[] aad = random(7);
        byte[] plain = random(40);
        assertArrayEquals(jdkEncrypt(key, nonce, aad, plain), encrypt(key, nonce, aad, plain));
    }

    /**
     * A changed byte anywhere is refused, and nothing is written.
     *
     * <p>The second half matters as much as the first. A decryption that hands
     * back plaintext and reports the failure afterwards is how a padding oracle
     * is built; the caller looks at what it was given.
     */
    @ParameterizedTest
    @CsvSource({"0", "5", "31", "32", "40", "47"})
    void aChangedByteIsRefused(int position) throws Exception {
        byte[] key = random(32);
        byte[] nonce = random(12);
        byte[] aad = random(8);
        byte[] plain = random(32);
        byte[] sealed = jdkEncrypt(key, nonce, aad, plain);
        sealed[position] = (byte) (sealed[position] ^ 0x01);

        byte[] opened = new byte[32];
        assertFalse(decrypt(key, nonce, aad, sealed, opened),
                "a flipped bit at " + position + " was accepted");
        assertArrayEquals(new byte[32], opened, "plaintext was written despite a bad tag");
    }

    /** Changing the additional data is a forgery too. */
    @Test
    void changedAdditionalDataIsRefused() throws Exception {
        byte[] key = random(32);
        byte[] nonce = random(12);
        byte[] aad = random(16);
        byte[] sealed = jdkEncrypt(key, nonce, aad, random(24));
        aad[0] = (byte) (aad[0] ^ 0x80);
        assertFalse(decrypt(key, nonce, aad, sealed, new byte[24]));
    }

    /** GHASH on its own, against a value the JDK produced for an empty message. */
    @Test
    void theTagOfAnEmptyMessageMatches() throws Exception {
        byte[] key = random(32);
        byte[] nonce = random(12);
        byte[] theirs = jdkEncrypt(key, nonce, new byte[0], new byte[0]);
        assertEquals(16, theirs.length, "an empty message is just the tag");
        assertArrayEquals(theirs, encrypt(key, nonce, new byte[0], new byte[0]));
    }

    // ---- the small machinery ---------------------------------------------

    private static byte[] jdkEncrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plain)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, nonce));
        if (aad.length > 0) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(plain);
    }

    private static byte[] encrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plain) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keySegment = of(arena, key);
            try (AesKey expanded = new AesKey(keySegment, 0, key.length)) {
                MemorySegment out = arena.allocate(plain.length + AesGcm.TAG);
                AesGcm.encrypt(expanded, of(arena, nonce), 0, of(arena, aad), 0, aad.length,
                        of(arena, plain), 0, plain.length, out, 0);
                return bytes(out, plain.length + AesGcm.TAG);
            }
        }
    }

    private static boolean decrypt(byte[] key, byte[] nonce, byte[] aad, byte[] sealed,
            byte[] into) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keySegment = of(arena, key);
            try (AesKey expanded = new AesKey(keySegment, 0, key.length)) {
                int length = sealed.length - AesGcm.TAG;
                MemorySegment out = arena.allocate(Math.max(length, 1));
                boolean ok = AesGcm.decrypt(expanded, of(arena, nonce), 0, of(arena, aad), 0,
                        aad.length, of(arena, sealed), 0, length, out, 0);
                if (ok && length > 0) {
                    MemorySegment.copy(out, ValueLayout.JAVA_BYTE, 0, into, 0, length);
                }
                return ok;
            }
        }
    }

    private static MemorySegment of(Arena arena, byte[] bytes) {
        MemorySegment segment = arena.allocate(Math.max(bytes.length, 1));
        if (bytes.length > 0) {
            MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        }
        return segment;
    }

    private static byte[] bytes(MemorySegment segment, int length) {
        byte[] out = new byte[length];
        MemorySegment.copy(segment, ValueLayout.JAVA_BYTE, 0, out, 0, length);
        return out;
    }

    private static byte[] random(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}
