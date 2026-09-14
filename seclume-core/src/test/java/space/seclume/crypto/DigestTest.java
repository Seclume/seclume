package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Random;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

import space.seclume.Segments;

/**
 * The published vectors, plus a cross-check against the JCA over many random
 * lengths. The vectors show that the algorithm is right; the cross-check finds
 * the errors in buffer boundaries and padding that a
 * einzelner Vektor nie trifft.
 */
class DigestTest {

    @ParameterizedTest
    @CsvSource({
        // RFC 1321 (MD5)
        "MD5,,d41d8cd98f00b204e9800998ecf8427e",
        "MD5,abc,900150983cd24fb0d6963f7d28e17f72",
        "MD5,message digest,f96b697d7cb7938d525a2f31aaf161d0",
        "MD5,abcdefghijklmnopqrstuvwxyz,c3fcd3d76192e4007dfb496cca67e13b",
        // FIPS 180-4 (SHA-1)
        "SHA_1,,da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "SHA_1,abc,a9993e364706816aba3e25717850c26c9cd0d89d",
        "SHA_1,abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq,"
            + "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        // FIPS 180-4 (SHA-256)
        "SHA_256,,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "SHA_256,abc,ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "SHA_256,abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq,"
            + "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        // FIPS 180-4 (SHA-512)
        "SHA_512,abc,ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "SHA_512,abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
            + "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu,"
            + "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
            + "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
    })
    void officialVectors(String algorithm, String message, String expected) {
        HashAlgorithm hash = HashAlgorithm.valueOf(algorithm);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment input = Segments.ascii(arena, message == null ? "" : message);
            MemorySegment out = arena.allocate(hash.digestLength());
            hash.hash(input, 0, input.byteSize(), out, 0);
            assertEquals(expected, Segments.toHex(out));
        }
    }

    /** The million-'a' vectors from FIPS 180-4 - the test for the block chain. */
    @Test
    void oneMillionLetters() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment chunk = Segments.ascii(arena, "a".repeat(1000));
            MemorySegment out = arena.allocate(32);
            try (Digest digest = HashAlgorithm.SHA_256.newDigest()) {
                for (int i = 0; i < 1000; i++) {
                    digest.update(chunk);
                }
                digest.digest(out, 0);
            }
            assertEquals("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
                    Segments.toHex(out));
        }
    }

    @ParameterizedTest
    @EnumSource(HashAlgorithm.class)
    void matchesJcaForRandomLengths(HashAlgorithm algorithm) throws Exception {
        MessageDigest reference = MessageDigest.getInstance(jcaName(algorithm));
        Random random = new Random(20260905L);
        try (Arena arena = Arena.ofConfined()) {
            // Lengths around every block boundary - that is where padding bugs sit.
            for (int length : lengths(algorithm)) {
                byte[] data = new byte[length];
                random.nextBytes(data);
                MemorySegment input = Segments.bytes(arena, data);
                MemorySegment out = arena.allocate(algorithm.digestLength());
                algorithm.hash(input, 0, input.byteSize(), out, 0);
                assertEquals(HexFormat.of().formatHex(reference.digest(data)),
                        Segments.toHex(out),
                        algorithm + " with " + length + " bytes");
            }
        }
    }

    /** Fed in pieces, the same result has to come out. */
    @ParameterizedTest
    @EnumSource(HashAlgorithm.class)
    void chunkedUpdatesMatchSingleUpdate(HashAlgorithm algorithm) throws Exception {
        MessageDigest reference = MessageDigest.getInstance(jcaName(algorithm));
        Random random = new Random(4711L);
        byte[] data = new byte[5000];
        random.nextBytes(data);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment input = Segments.bytes(arena, data);
            MemorySegment out = arena.allocate(algorithm.digestLength());
            try (Digest digest = algorithm.newDigest()) {
                long offset = 0;
                while (offset < data.length) {
                    long take = Math.min(1 + random.nextInt(300), data.length - offset);
                    digest.update(input, offset, take);
                    offset += take;
                }
                digest.digest(out, 0);
            }
            assertEquals(HexFormat.of().formatHex(reference.digest(data)), Segments.toHex(out));
        }
    }

    /** After {@code digest()} the next hash really does start from zero. */
    @ParameterizedTest
    @EnumSource(HashAlgorithm.class)
    void reusableAfterDigest(HashAlgorithm algorithm) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment input = Segments.ascii(arena, "abc");
            MemorySegment first = arena.allocate(algorithm.digestLength());
            MemorySegment second = arena.allocate(algorithm.digestLength());
            try (Digest digest = algorithm.newDigest()) {
                digest.update(input);
                digest.digest(first, 0);
                digest.update(input);
                digest.digest(second, 0);
            }
            assertEquals(Segments.toHex(first), Segments.toHex(second));
        }
    }

    @Test
    void closedDigestRefusesWork() {
        Digest digest = HashAlgorithm.SHA_256.newDigest();
        digest.close();
        digest.close(); // closing more than once is allowed
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment input = Segments.ascii(arena, "abc");
            assertTrue(assertThrowsIllegalState(() -> digest.update(input)));
        }
    }

    private static boolean assertThrowsIllegalState(Runnable runnable) {
        try {
            runnable.run();
            return false;
        } catch (IllegalStateException expected) {
            return true;
        }
    }

    private static int[] lengths(HashAlgorithm algorithm) {
        int block = algorithm.blockLength();
        return new int[] {
            0, 1, 2, 3, 55, 56, 57, 63, 64, 65,
            block - 17, block - 9, block - 8, block - 1, block, block + 1,
            2 * block - 1, 2 * block, 2 * block + 1, 1000, 4096, 4097,
        };
    }

    private static String jcaName(HashAlgorithm algorithm) {
        return switch (algorithm) {
            case MD5 -> "MD5";
            case SHA_1 -> "SHA-1";
            case SHA_256 -> "SHA-256";
            case SHA_512 -> "SHA-512";
        };
    }
}
