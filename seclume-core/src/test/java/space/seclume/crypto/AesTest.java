package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.HexFormat;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.Segments;

/** FIPS-197 examples and NIST CAVP CBC vectors, plus a cross-check against the JCA. */
class AesTest {

    /** Appendix B and C of FIPS 197 - one block, all three key lengths. */
    @ParameterizedTest
    @CsvSource({
        "000102030405060708090a0b0c0d0e0f,"
            + "00112233445566778899aabbccddeeff,69c4e0d86a7b0430d8cdb78070b4c55a",
        "000102030405060708090a0b0c0d0e0f1011121314151617,"
            + "00112233445566778899aabbccddeeff,dda97ca4864cdfe06eaf70a0ec0d7191",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f,"
            + "00112233445566778899aabbccddeeff,8ea2b7ca516745bfeafc49904b496089",
    })
    void fips197Blocks(String keyHex, String plainHex, String cipherHex) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment state = Segments.hex(arena, plainHex);
            try (AesKey key = new AesKey(Segments.hex(arena, keyHex))) {
                Aes.encryptBlock(key, state);
                assertEquals(cipherHex, Segments.toHex(state));
                Aes.decryptBlock(key, state);
                assertEquals(plainHex, Segments.toHex(state));
            }
        }
    }

    /** NIST SP 800-38A, F.2.1: AES-128-CBC. */
    @Test
    void nistCbcVector() {
        String keyHex = "2b7e151628aed2a6abf7158809cf4f3c";
        String ivHex = "000102030405060708090a0b0c0d0e0f";
        String plainHex = "6bc1bee22e409f96e93d7e117393172a"
                + "ae2d8a571e03ac9c9eb76fac45af8e51";
        String cipherHex = "7649abac8119b246cee98e9b12e9197d"
                + "5086cb9b507219ee95db113a917678b2";

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment plain = Segments.hex(arena, plainHex);
            MemorySegment out = arena.allocate(plain.byteSize());
            try (AesKey key = new AesKey(Segments.hex(arena, keyHex))) {
                Aes.cbcEncrypt(key, Segments.hex(arena, ivHex), plain, 0, out, 0, plain.byteSize());
                assertEquals(cipherHex, Segments.toHex(out));
                Aes.cbcDecrypt(key, Segments.hex(arena, ivHex), out, 0, out, 0, out.byteSize());
                assertEquals(plainHex, Segments.toHex(out));
            }
        }
    }

    /** NIST SP 800-38A, F.3.13: AES-128-CFB128. */
    @Test
    void nistCfbVector() {
        String keyHex = "2b7e151628aed2a6abf7158809cf4f3c";
        String ivHex = "000102030405060708090a0b0c0d0e0f";
        String plainHex = "6bc1bee22e409f96e93d7e117393172a"
                + "ae2d8a571e03ac9c9eb76fac45af8e51";
        String cipherHex = "3b3fd92eb72dad20333449f8e83cfb4a"
                + "c8a64537a0b3a93fcde3cdad9f1ce58b";

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment plain = Segments.hex(arena, plainHex);
            MemorySegment out = arena.allocate(plain.byteSize());
            try (AesKey key = new AesKey(Segments.hex(arena, keyHex))) {
                Aes.cfbEncrypt(key, Segments.hex(arena, ivHex), plain, 0, out, 0, plain.byteSize());
                assertEquals(cipherHex, Segments.toHex(out));
                Aes.cfbDecrypt(key, Segments.hex(arena, ivHex), out, 0, out, 0, out.byteSize());
                assertEquals(plainHex, Segments.toHex(out));
            }
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {16, 24, 32})
    void cbcMatchesJca(int keyLength) throws Exception {
        Random random = new Random(20260905L + keyLength);
        for (int blocks : new int[] {1, 2, 5, 64}) {
            byte[] keyBytes = new byte[keyLength];
            byte[] ivBytes = new byte[16];
            byte[] plainBytes = new byte[blocks * 16];
            random.nextBytes(keyBytes);
            random.nextBytes(ivBytes);
            random.nextBytes(plainBytes);

            Cipher reference = Cipher.getInstance("AES/CBC/NoPadding");
            reference.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                    new IvParameterSpec(ivBytes));
            String expected = HexFormat.of().formatHex(reference.doFinal(plainBytes));

            try (Arena arena = Arena.ofConfined()) {
                MemorySegment plain = Segments.bytes(arena, plainBytes);
                MemorySegment out = arena.allocate(plain.byteSize());
                try (AesKey key = new AesKey(Segments.bytes(arena, keyBytes))) {
                    Aes.cbcEncrypt(key, Segments.bytes(arena, ivBytes), plain, 0, out, 0,
                            plain.byteSize());
                    assertEquals(expected, Segments.toHex(out),
                            "keyLength=" + keyLength + " blocks=" + blocks);
                    Aes.cbcDecrypt(key, Segments.bytes(arena, ivBytes), out, 0, out, 0,
                            out.byteSize());
                    assertEquals(HexFormat.of().formatHex(plainBytes), Segments.toHex(out));
                }
            }
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {16, 24, 32})
    void cfbMatchesJca(int keyLength) throws Exception {
        Random random = new Random(99L + keyLength);
        // Odd lengths too: CFB is a stream cipher.
        for (int length : new int[] {1, 15, 16, 17, 100}) {
            byte[] keyBytes = new byte[keyLength];
            byte[] ivBytes = new byte[16];
            byte[] plainBytes = new byte[length];
            random.nextBytes(keyBytes);
            random.nextBytes(ivBytes);
            random.nextBytes(plainBytes);

            Cipher reference = Cipher.getInstance("AES/CFB128/NoPadding");
            reference.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                    new IvParameterSpec(ivBytes));
            String expected = HexFormat.of().formatHex(reference.doFinal(plainBytes));

            try (Arena arena = Arena.ofConfined()) {
                MemorySegment plain = Segments.bytes(arena, plainBytes);
                MemorySegment out = arena.allocate(length);
                try (AesKey key = new AesKey(Segments.bytes(arena, keyBytes))) {
                    Aes.cfbEncrypt(key, Segments.bytes(arena, ivBytes), plain, 0, out, 0, length);
                    assertEquals(expected, Segments.toHex(out),
                            "keyLength=" + keyLength + " length=" + length);
                    Aes.cfbDecrypt(key, Segments.bytes(arena, ivBytes), out, 0, out, 0, length);
                    assertEquals(HexFormat.of().formatHex(plainBytes), Segments.toHex(out));
                }
            }
        }
    }

    /** After closing, the round keys are gone. */
    @Test
    void closedKeyRefusesWork() {
        try (Arena arena = Arena.ofConfined()) {
            AesKey key = new AesKey(Segments.repeated(arena, 0x11, 16));
            key.close();
            key.close();
            MemorySegment state = Segments.repeated(arena, 0, 16);
            try {
                Aes.encryptBlock(key, state);
                throw new AssertionError("expected IllegalStateException");
            } catch (IllegalStateException expected) {
                // The wording may change; that it says the key is closed and
                // what to do next is what the test is about.
                assertTrue(expected.getMessage().contains("closed"), expected.getMessage());
                assertTrue(expected.getMessage().contains("new one"), expected.getMessage());
            }
        }
    }
}
