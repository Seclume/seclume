package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;

import org.junit.jupiter.api.Test;

import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * What a key management service answers, as {@link KmsSigningKey} and its
 * services turn it into what TLS takes: an ECDSA signature as r and s (Azure
 * Key Vault) re-encoded as DER, a public key as PEM (Vault transit). Any answer
 * ends in a value or an {@link IOException}; a signature that is r and s comes
 * out as the one DER encoding of it, which a verifier would otherwise refuse.
 */
class KmsAnswerFuzzTest {

    private static final int ROUNDS = Integer.getInteger("seclume.kms.fuzz.rounds", 20_000);

    @FuzzTest(maxDuration = "60s")
    void aRawSignatureBecomesDerOrAnIoException(byte[] raw) {
        try {
            check(raw, KmsSigningKey.derFromRaw(raw));
        } catch (IOException expected) {
            // not r and s of one length
        }
    }

    @FuzzTest(maxDuration = "60s")
    void aPublicKeyPemBecomesDerOrAnIoException(byte[] text) {
        try {
            VaultTransitKey.der(new String(text, StandardCharsets.ISO_8859_1));
        } catch (IOException expected) {
            // not a PUBLIC KEY PEM
        }
    }

    @Test
    void everyRawSignatureOfOneLengthBecomesTheDerOfItsTwoNumbers() throws IOException {
        Random random = new Random(20261030L);
        for (int round = 0; round < ROUNDS; round++) {
            int half = 1 + random.nextInt(66);
            byte[] raw = new byte[2 * half];
            random.nextBytes(raw);
            // Leading zeros and high bits are where DER encodings go wrong.
            switch (round % 4) {
                case 0 -> Arrays.fill(raw, 0, random.nextInt(half + 1), (byte) 0);
                case 1 -> raw[0] = (byte) 0x80;
                case 2 -> Arrays.fill(raw, half, half + random.nextInt(half + 1), (byte) 0);
                default -> raw[half] = (byte) 0xff;
            }
            check(raw, KmsSigningKey.derFromRaw(raw));
        }
    }

    @Test
    void whatIsNotRAndSIsRefused() {
        for (byte[] raw : new byte[][] {{}, {1}, {1, 2, 3}, new byte[134], new byte[1000]}) {
            assertThrows(IOException.class, () -> KmsSigningKey.derFromRaw(raw));
        }
    }

    @Test
    void mutatedPemsEndInDerOrAnIoException() {
        String pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n"
                + "-----END PUBLIC KEY-----\n";
        Random random = new Random(7);
        for (int round = 0; round < ROUNDS; round++) {
            char[] text = pem.toCharArray();
            for (int i = 0; i < 1 + random.nextInt(3); i++) {
                text[random.nextInt(text.length)] = (char) random.nextInt(128);
            }
            try {
                VaultTransitKey.der(String.valueOf(text, 0, random.nextInt(text.length + 1)));
            } catch (IOException expected) {
                // broken, said as such
            } catch (RuntimeException e) {
                throw new AssertionError("round " + round + ": " + e, e);
            }
        }
    }

    /** {@code der} is SEQUENCE { INTEGER r, INTEGER s }, minimal, with r and s from {@code raw}. */
    private static void check(byte[] raw, byte[] der) {
        int half = raw.length / 2;
        int[] at = {0};
        assertEquals(0x30, der[at[0]++] & 0xff, "not a SEQUENCE");
        int length = length(der, at);
        assertEquals(der.length, at[0] + length, "the SEQUENCE's length is not the rest");
        BigInteger r = integer(der, at);
        BigInteger s = integer(der, at);
        assertEquals(der.length, at[0], "something after s");
        assertEquals(new BigInteger(1, Arrays.copyOfRange(raw, 0, half)), r);
        assertEquals(new BigInteger(1, Arrays.copyOfRange(raw, half, raw.length)), s);
    }

    private static int length(byte[] der, int[] at) {
        int first = der[at[0]++] & 0xff;
        if (first < 0x80) {
            return first;
        }
        assertEquals(0x81, first, "a length of more than one byte for at most 255");
        int length = der[at[0]++] & 0xff;
        assertTrue(length >= 0x80, "a long form for a short length is not DER");
        return length;
    }

    private static BigInteger integer(byte[] der, int[] at) {
        assertEquals(0x02, der[at[0]++] & 0xff, "not an INTEGER");
        int length = length(der, at);
        byte[] value = Arrays.copyOfRange(der, at[0], at[0] + length);
        at[0] += length;
        assertTrue(length > 0, "an empty INTEGER");
        assertTrue(value[0] >= 0, "a negative INTEGER: r and s are positive");
        if (length > 1) {
            assertTrue(value[0] != 0 || value[1] < 0, "a leading zero DER does not allow");
        }
        BigInteger number = new BigInteger(value);
        assertArrayEquals(value, number.toByteArray(), "not the minimal encoding");
        return number;
    }
}
