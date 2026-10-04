package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.ByteArrayOutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import space.seclume.crypto.HashAlgorithm;

/**
 * The TLS 1.2 PRF against a second, independent implementation - the JDK's
 * {@code Mac}, written out here the way RFC 5246 section 5 states it. Lengths
 * below, at and across the digest length, because the last partial block is
 * where a P_hash goes wrong.
 */
class Tls12PrfTest {

    @ParameterizedTest(name = "{0}, {1} bytes")
    @CsvSource({"SHA_256, 1", "SHA_256, 12", "SHA_256, 32", "SHA_256, 33", "SHA_256, 48",
            "SHA_256, 104", "SHA_384, 12", "SHA_384, 48", "SHA_384, 49", "SHA_384, 136"})
    void matchesTheRfcConstruction(HashAlgorithm hash, int length) throws Exception {
        Random random = new Random(length * 31L + hash.ordinal());
        byte[] secret = new byte[48];
        byte[] first = new byte[32];
        byte[] second = new byte[32];
        random.nextBytes(secret);
        random.nextBytes(first);
        random.nextBytes(second);

        byte[] expected = reference(hash == HashAlgorithm.SHA_256 ? "HmacSHA256" : "HmacSHA384",
                secret, "key expansion", concat(first, second), length);

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(length);
            Tls12Prf.derive(hash, MemorySegment.ofArray(secret), "key expansion",
                    new MemorySegment[] {MemorySegment.ofArray(first), MemorySegment.ofArray(second)},
                    out, 0, length);
            assertArrayEquals(expected, out.toArray(ValueLayout.JAVA_BYTE));
        }
    }

    private static byte[] reference(String algorithm, byte[] secret, String label, byte[] seed,
            int length) throws Exception {
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(secret, algorithm));
        byte[] labelAndSeed = concat(label.getBytes(StandardCharsets.US_ASCII), seed);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] a = mac.doFinal(labelAndSeed);
        while (out.size() < length) {
            mac.update(a);
            mac.update(labelAndSeed);
            out.write(mac.doFinal());
            a = mac.doFinal(a);
        }
        byte[] all = out.toByteArray();
        byte[] result = new byte[length];
        System.arraycopy(all, 0, result, 0, length);
        return result;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
