package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import org.junit.jupiter.api.Test;

/**
 * A secret a server sends back is overwritten before the line is read: whole,
 * cut at either end, more than once - and text that only shares a few
 * characters with it stays as it is. The values here are test data.
 */
class EchoMaskTest {

    private static String masked(String text, String secret) {
        try (Arena arena = Arena.ofConfined()) {
            byte[] t = text.getBytes(StandardCharsets.ISO_8859_1);
            byte[] s = secret.getBytes(StandardCharsets.ISO_8859_1);
            MemorySegment line = arena.allocate(Math.max(1, t.length));
            MemorySegment key = arena.allocate(Math.max(1, s.length));
            MemorySegment.copy(t, 0, line, ValueLayout.JAVA_BYTE, 0, t.length);
            MemorySegment.copy(s, 0, key, ValueLayout.JAVA_BYTE, 0, s.length);
            int count = EchoMask.mask(line, t.length, key, s.length);
            String out = new String(line.asSlice(0, t.length).toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.ISO_8859_1);
            assertEquals(count, out.chars().filter(c -> c == '*').count()
                    - text.chars().filter(c -> c == '*').count());
            return out;
        }
    }

    @Test
    void theWholeSecretIsOverwritten() {
        assertEquals("-ERR unknown command: PASS *************",
                masked("-ERR unknown command: PASS correct horse", "correct horse"));
        assertEquals("*************", masked("correct horse", "correct horse"));
    }

    @Test
    void everyTimeItStandsThere() {
        assertEquals("**** and **** and ****", masked("s3cr and s3cr and s3cr", "s3cr"));
    }

    @Test
    void aPartOfItCutAtEitherEnd() {
        assertEquals("bad argument '*******...'", masked("bad argument 'correct...'",
                "correct horse"));
        assertEquals("bad argument '...*****'", masked("bad argument '...horse'",
                "correct horse"));
        assertEquals("near '*****'", masked("near 'ect h'", "correct horse"));
    }

    @Test
    void fewerThanFourBytesOfALongerSecretAreNotTakenForIt() {
        assertEquals("535 5.7.8 authentication credentials invalid",
                masked("535 5.7.8 authentication credentials invalid", "xcrex7.8y"));
        assertEquals("-ERR:hor", masked("-ERR:hor", "correct horse"));
    }

    @Test
    void aShortSecretIsLookedForWhole() {
        assertEquals("pin ** refused, 1 try left", masked("pin 42 refused, 1 try left", "42"));
        assertEquals("pin 4 refused", masked("pin 4 refused", "42"));
    }

    @Test
    void anEmptySecretOrAnEmptyLineChangesNothing() {
        assertEquals("anything", masked("anything", ""));
        assertEquals("", masked("", "secret"));
        assertEquals("abc", masked("abc", "abcd"));
    }

    @Test
    void theLongestPartCounts() {
        // "abcd" stands at the secret's start, "abcdefgh" further in: all eight go.
        assertEquals("got ********!", masked("got abcdefgh!", "abcd-abcdefgh"));
    }

    @Test
    void whateverSurroundsItNoFourBytesOfTheSecretAreLeft() {
        Random random = new Random(20261112);
        String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=";
        for (int round = 0; round < 2000; round++) {
            StringBuilder secret = new StringBuilder();
            int length = 4 + random.nextInt(40);
            for (int i = 0; i < length; i++) {
                secret.append(alphabet.charAt(random.nextInt(alphabet.length())));
            }
            int from = random.nextInt(length - 3);
            int to = from + 4 + random.nextInt(length - from - 3);
            String part = secret.substring(from, to);
            String line = "500 5.5.1 not understood: \"" + part + "\" (" + round + ")";
            String out = masked(line, secret.toString());
            for (int i = 0; i + 4 <= secret.length(); i++) {
                assertFalse(out.contains(secret.substring(i, i + 4)), line + " -> " + out);
            }
            assertEquals(line.length(), out.length());
        }
    }
}
