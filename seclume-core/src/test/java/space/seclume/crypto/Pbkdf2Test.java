package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.HexFormat;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import space.seclume.Segments;

/** RFC 6070 (PBKDF2-HMAC-SHA-1) and a JCA cross-check for SHA-256/512. */
class Pbkdf2Test {

    @ParameterizedTest
    @CsvSource({
        "1,20,0c60c80f961f0e71f3a9b524af6012062fe037a6",
        "2,20,ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
        "4096,20,4b007901b765489abead49d926f721d065a429c1",
    })
    void rfc6070(int iterations, int length, String expected) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment password = Segments.ascii(arena, "password");
            MemorySegment salt = Segments.ascii(arena, "salt");
            MemorySegment out = arena.allocate(length);
            Pbkdf2.derive(HashAlgorithm.SHA_1, password, salt, iterations, out);
            assertEquals(expected, Segments.toHex(out));
        }
    }

    /** The case with several output blocks and a long salt. */
    @Test
    void rfc6070LongCase() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment password = Segments.ascii(arena, "passwordPASSWORDpassword");
            MemorySegment salt = Segments.ascii(arena, "saltSALTsaltSALTsaltSALTsaltSALTsalt");
            MemorySegment out = arena.allocate(25);
            Pbkdf2.derive(HashAlgorithm.SHA_1, password, salt, 4096, out);
            assertEquals("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038", Segments.toHex(out));
        }
    }

    @ParameterizedTest
    @CsvSource({
        "SHA_1,PBKDF2WithHmacSHA1",
        "SHA_256,PBKDF2WithHmacSHA256",
        "SHA_512,PBKDF2WithHmacSHA512",
    })
    void matchesJca(String algorithm, String jcaName) throws Exception {
        HashAlgorithm hash = HashAlgorithm.valueOf(algorithm);
        char[] password = "correct horse battery staple".toCharArray();
        byte[] salt = "seclume-cross-check".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

        for (int length : new int[] {16, 20, 32, 40, 64, 100}) {
            for (int iterations : new int[] {1, 2, 1000}) {
                PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, length * 8);
                String expected = HexFormat.of().formatHex(
                        SecretKeyFactory.getInstance(jcaName).generateSecret(spec).getEncoded());

                try (Arena arena = Arena.ofConfined()) {
                    MemorySegment out = arena.allocate(length);
                    Pbkdf2.derive(hash,
                            Segments.ascii(arena, new String(password)),
                            Segments.bytes(arena, salt),
                            iterations, out);
                    assertEquals(expected, Segments.toHex(out),
                            algorithm + " len=" + length + " iterations=" + iterations);
                }
            }
        }
    }
}
