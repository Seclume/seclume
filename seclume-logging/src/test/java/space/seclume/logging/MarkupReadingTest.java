package space.seclume.logging;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Random;

import org.junit.jupiter.api.Test;

/**
 * Reading XML's and HTML's character references looked from each {@code &}
 * up to 32 characters on for its {@code ;}: a long line of {@code &} cost 32
 * reads a character. It finds the next {@code ;} once now. What it reads is
 * held to the old reading, character for character, on random text made of
 * what references are made of.
 */
class MarkupReadingTest {

    /** The reading as it was: from each {@code &}, the first {@code ;} 2 to 32 characters on. */
    private static String reference(String text, int[] from, int[] to) {
        StringBuilder out = new StringBuilder();
        int i = 0;
        while (i < text.length()) {
            int end = -1;
            if (text.charAt(i) == '&') {
                int last = Math.min(text.length() - 1, i + 32);
                for (int k = i + 2; k <= last; k++) {
                    if (text.charAt(k) == ';') {
                        end = k;
                        break;
                    }
                }
            }
            int point = end > 0 ? SecretMasker.entity(text, i + 1, end) : -1;
            if (point < 0) {
                from[out.length()] = i;
                to[out.length()] = i + 1;
                out.append(text.charAt(i));
                i++;
                continue;
            }
            for (char c : Character.toChars(point)) {
                from[out.length()] = i;
                to[out.length()] = end + 1;
                out.append(c);
            }
            i = end + 1;
        }
        return out.toString();
    }

    @Test
    void readsAsBeforeOnRandomText() {
        String alphabet = "&;#x0123456789abcdefltgampquos ";
        Random random = new Random(20261126L);
        try (Arena arena = Arena.ofConfined()) {
            for (int round = 0; round < 20_000; round++) {
                StringBuilder line = new StringBuilder();
                int length = random.nextInt(80);
                for (int i = 0; i < length; i++) {
                    line.append(alphabet.charAt(random.nextInt(alphabet.length())));
                }
                if (random.nextInt(4) == 0) {
                    line.insert(random.nextInt(line.length() + 1), "&#" + "0".repeat(
                            random.nextInt(35)) + "65;");
                }
                String text = line.toString();
                int[] from = new int[text.length() + 1];
                int[] to = new int[text.length() + 1];
                int[] wantFrom = new int[text.length() + 1];
                int[] wantTo = new int[text.length() + 1];
                String want = reference(text, wantFrom, wantTo);
                MemorySegment out = arena.allocate(Math.max(2, 2L * text.length()));
                int got = SecretMasker.entitiesRead(text, out, from, to);
                if (got < 0) {
                    assertEquals(text, want, "said nothing was read in: " + text);
                    continue;
                }
                char[] chars = new char[got];
                for (int i = 0; i < got; i++) {
                    chars[i] = out.get(ValueLayout.JAVA_CHAR_UNALIGNED, 2L * i);
                }
                assertEquals(want, new String(chars), text);
                assertArrayEquals(java.util.Arrays.copyOf(wantFrom, got),
                        java.util.Arrays.copyOf(from, got), text);
                assertArrayEquals(java.util.Arrays.copyOf(wantTo, got),
                        java.util.Arrays.copyOf(to, got), text);
            }
        }
    }
}
