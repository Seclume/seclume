package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;

/**
 * A dollar-quoted session value read back the way PostgreSQL's lexer reads
 * one: after the opening tag, the string runs to the first occurrence of the
 * same tag - wherever that comes from.
 *
 * <p>Review round 4: the tag was chosen only so that it did not occur in the
 * value. A value ending in {@code $seclume} makes one together with the
 * closing tag's first {@code $}: {@code x$seclume} was read as {@code x}, and
 * {@code seclume$} after it was left in the statement.
 */
class ContextValuesTest {

    /** The value a dollar-quoted string stands for, and what follows it. */
    private record Read(String value, String rest) {
    }

    private static Read read(String quoted) {
        assertTrue(quoted.startsWith("$"), quoted);
        int close = quoted.indexOf('$', 1);
        String tag = quoted.substring(0, close + 1);
        int end = quoted.indexOf(tag, tag.length());
        assertTrue(end >= 0, "never ends: " + quoted);
        return new Read(quoted.substring(tag.length(), end), quoted.substring(end + tag.length()));
    }

    private static void assertReadsAsItself(String value) {
        String quoted = ContextValues.dollarQuoted(value);
        Read read = read(quoted);
        assertEquals(value, read.value(), quoted);
        assertEquals("", read.rest(), quoted + " ends where it was made to end");
    }

    @Test
    void aValueEndingLikeTheTagIsStillOneString() {
        for (String value : List.of("x$seclume", "$seclume", "$seclume$", "x$seclume$",
                "x$seclume$y$seclume", "$seclume1", "x$seclume1", "$seclume$x$seclume1",
                "", "$", "$$", "seclume$", "$seclume$seclume$", "tenant-42")) {
            assertReadsAsItself(value);
        }
    }

    @Test
    void randomValuesOfTagLikeTextAreReadAsThemselves() {
        Random random = new Random(0x5ec1L);
        String alphabet = "$seclum12x";
        for (int round = 0; round < 20_000; round++) {
            StringBuilder value = new StringBuilder();
            int length = random.nextInt(24);
            for (int i = 0; i < length; i++) {
                value.append(random.nextInt(3) == 0 ? "$seclume" : String.valueOf(
                        alphabet.charAt(random.nextInt(alphabet.length()))));
            }
            assertReadsAsItself(value.toString());
        }
    }

    @Test
    void theOldTagChoiceEndedTheStringEarly() {
        // The negative control: the model sees what the old choice did.
        List<String> broken = new ArrayList<>();
        for (String value : List.of("x$seclume", "a$seclume$b$seclume1")) {
            String tag = "$seclume$";
            int n = 0;
            while (value.contains(tag)) {
                tag = "$seclume" + (++n) + "$";
            }
            Read read = read(tag + value + tag);
            if (!read.rest().isEmpty()) {
                broken.add(value + " -> " + read.value() + " + " + read.rest());
            }
        }
        assertEquals(2, broken.size(), broken.toString());
    }
}
