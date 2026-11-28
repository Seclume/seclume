package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import org.junit.jupiter.api.Test;

/**
 * The decoder stopped at the first '=' and dropped the rest - a key file with
 * two keys in it was read as the first - and took a last unit the JDK refuses:
 * one character, wrong padding, bits set beyond the last byte. About a quarter
 * of random inputs came out differently from java.util.Base64. It agrees now.
 */
class Base64OffStrictTest {

    private static byte[] decode(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[bytes.length];
        int n = Base64Off.decode(MemorySegment.ofArray(bytes), 0, bytes.length,
                MemorySegment.ofArray(out), 0);
        return Arrays.copyOf(out, n);
    }

    @Test
    void whatTheJdkRefusesIsRefused() {
        for (String bad : new String[] {"QUJD=QUJD", "QUJDRA==QUJD", "QQ", "QR==", "QUI=",
            "Q===", "QUJDR", "QUJ===", "QUJDRA=", "Q"}) {
            boolean jdkRefuses;
            try {
                Base64.getDecoder().decode(bad);
                jdkRefuses = false;
            } catch (IllegalArgumentException refused) {
                jdkRefuses = true;
            }
            if (jdkRefuses) {
                assertThrows(IllegalArgumentException.class, () -> decode(bad), bad);
            }
        }
        assertThrows(IllegalArgumentException.class, () -> decode("QUJD=QUJD"),
                "text after the padding");
    }

    /** Whether {@code text} is how its bytes encode - padded or not. */
    private static boolean canonical(String text, byte[] bytes) {
        return text.equals(Base64.getEncoder().encodeToString(bytes))
                || text.equals(Base64.getEncoder().withoutPadding().encodeToString(bytes));
    }

    @Test
    void bitsBeyondTheLastByteAreRefused() {
        assertThrows(IllegalArgumentException.class, () -> decode("Vr2"));
        assertThrows(IllegalArgumentException.class, () -> decode("QR=="));
        assertArrayEquals(new byte[] {'A'}, decode("QQ=="));
    }

    @Test
    void randomInputsAgreeWithTheJdk() {
        Random random = new Random(0x64);
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        for (int round = 0; round < 20_000; round++) {
            StringBuilder text = new StringBuilder();
            int length = random.nextInt(13);
            for (int i = 0; i < length; i++) {
                text.append(alphabet.charAt(random.nextInt(alphabet.length())));
            }
            byte[] expected;
            try {
                expected = Base64.getDecoder().decode(text.toString());
            } catch (IllegalArgumentException refused) {
                expected = null;
            }
            byte[] actual;
            try {
                actual = decode(text.toString());
            } catch (IllegalArgumentException refused) {
                actual = null;
            }
            if (expected != null && actual == null && !canonical(text.toString(), expected)) {
                continue;               // stricter on purpose: bits set beyond the last byte
            }
            if (expected == null || actual == null) {
                if (expected != actual) {
                    fail("'" + text + "': JDK " + (expected == null ? "refuses" : "accepts")
                            + ", Base64Off " + (actual == null ? "refuses" : "accepts"));
                }
            } else {
                assertArrayEquals(expected, actual, text.toString());
            }
        }
    }
}
