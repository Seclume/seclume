package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.HexFormat;
import java.util.Random;

import org.junit.jupiter.api.Test;

import space.seclume.internal.Platform;

/**
 * The AES-GCM behind the TLS records: the platform's library where there is
 * one, agreeing byte for byte with the constant-time Java version on every
 * shape of input, and with NIST's test vector.
 */
class AesGcmCipherTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void theNativeLibraryIsUsedWhereThePlatformHasOne() {
        try (Arena arena = Arena.ofConfined(); AesGcmCipher cipher =
                AesGcmCipher.of(arena.allocate(16), 0, 16)) {
            String expected = Platform.isWindows() ? "cng"
                    : Platform.isLinux() ? "openssl" : "java";
            System.out.println("  AES-GCM implementation here: " + cipher.implementation());
            if (!Platform.isLinux() || hasLibcrypto()) {
                assertEquals(expected, cipher.implementation());
            }
        }
    }

    private static boolean hasLibcrypto() {
        try {
            java.lang.foreign.SymbolLookup.libraryLookup("libcrypto.so.3", Arena.global());
            return true;
        } catch (IllegalArgumentException absent) {
            return false;
        }
    }

    /** NIST GCM test case 4 (AES-128, 60 bytes, 20 bytes of additional data). */
    @Test
    void nistTestCaseFour() {
        byte[] key = HEX.parseHex("feffe9928665731c6d6a8f9467308308");
        byte[] nonce = HEX.parseHex("cafebabefacedbaddecaf888");
        byte[] plain = HEX.parseHex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                + "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        byte[] aad = HEX.parseHex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        String expected = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                + "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
                + "5bc94fbc3221a5db94fae95ae7121a47";
        try (Arena arena = Arena.ofConfined();
             AesGcmCipher cipher = AesGcmCipher.of(segment(arena, key), 0, 16)) {
            MemorySegment out = arena.allocate(plain.length + AesGcm.TAG);
            cipher.encrypt(segment(arena, nonce), 0, segment(arena, aad), 0, aad.length,
                    segment(arena, plain), 0, plain.length, out, 0);
            assertEquals(expected, HEX.formatHex(out.toArray(ValueLayout.JAVA_BYTE)));
            MemorySegment back = arena.allocate(plain.length);
            assertTrue(cipher.decrypt(segment(arena, nonce), 0, segment(arena, aad), 0,
                    aad.length, out, 0, plain.length, back, 0));
            assertEquals(HEX.formatHex(plain), HEX.formatHex(back.toArray(ValueLayout.JAVA_BYTE)));
        }
    }

    @Test
    void nativeAndJavaAgreeOnEveryShape() {
        Random random = new Random(42);
        for (int keyLength : new int[] {16, 32}) {
            for (int length : new int[] {0, 1, 15, 16, 17, 255, 16385}) {
                for (int aadLength : new int[] {0, 5, 13}) {
                    agree(random, keyLength, length, aadLength);
                }
            }
        }
    }

    private static void agree(Random random, int keyLength, int length, int aadLength) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = random(arena, random, keyLength);
            MemorySegment nonce = random(arena, random, AesGcm.NONCE);
            MemorySegment aad = random(arena, random, Math.max(aadLength, 1));
            MemorySegment plain = random(arena, random, Math.max(length, 1));
            MemorySegment platform = arena.allocate(length + AesGcm.TAG);
            MemorySegment java = arena.allocate(length + AesGcm.TAG);
            try (AesGcmCipher nativeCipher = AesGcmCipher.of(key, 0, keyLength);
                 AesGcmCipher javaCipher = new JavaAesGcm(key, 0, keyLength)) {
                nativeCipher.encrypt(nonce, 0, aad, 0, aadLength, plain, 0, length, platform, 0);
                javaCipher.encrypt(nonce, 0, aad, 0, aadLength, plain, 0, length, java, 0);
                String what = nativeCipher.implementation() + ", key " + keyLength + ", "
                        + length + " bytes, aad " + aadLength;
                assertEquals(HEX.formatHex(java.toArray(ValueLayout.JAVA_BYTE)),
                        HEX.formatHex(platform.toArray(ValueLayout.JAVA_BYTE)), what);

                MemorySegment back = arena.allocate(Math.max(length, 1));
                assertTrue(nativeCipher.decrypt(nonce, 0, aad, 0, aadLength, java, 0, length,
                        back, 0), what);
                assertEquals(-1, back.asSlice(0, length).mismatch(plain.asSlice(0, length)), what);

                // One flipped bit in the tag: refused, and nothing decrypted left behind.
                int last = length + AesGcm.TAG - 1;
                java.set(ValueLayout.JAVA_BYTE, last,
                        (byte) (java.get(ValueLayout.JAVA_BYTE, last) ^ 1));
                back.fill((byte) 0x55);
                assertFalse(nativeCipher.decrypt(nonce, 0, aad, 0, aadLength, java, 0, length,
                        back, 0), what);
                for (int i = 0; i < length; i++) {
                    assertEquals(0, back.get(ValueLayout.JAVA_BYTE, i), what + ": byte " + i);
                }
            }
        }
    }

    /** Not a benchmark - a figure for the log, so a slow path does not go unnoticed. */
    @Test
    void throughputOfSixteenKilobyteRecords() {
        try (Arena arena = Arena.ofConfined();
             AesGcmCipher cipher = AesGcmCipher.of(arena.allocate(16), 0, 16)) {
            MemorySegment nonce = arena.allocate(AesGcm.NONCE);
            MemorySegment aad = arena.allocate(5);
            MemorySegment in = arena.allocate(16384);
            MemorySegment out = arena.allocate(16384 + AesGcm.TAG);
            long start = System.nanoTime();
            int records = 0;
            while (System.nanoTime() - start < 300_000_000L) {
                cipher.encrypt(nonce, 0, aad, 0, 5, in, 0, 16384, out, 0);
                records++;
            }
            double seconds = (System.nanoTime() - start) / 1e9;
            System.out.printf("  AES-GCM (%s): %.0f MB/s%n", cipher.implementation(),
                    records * 16384 / seconds / 1e6);
        }
    }

    private static MemorySegment segment(Arena arena, byte[] bytes) {
        MemorySegment segment = arena.allocate(Math.max(bytes.length, 1));
        MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return segment;
    }

    private static MemorySegment random(Arena arena, Random random, int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return segment(arena, bytes);
    }
}
