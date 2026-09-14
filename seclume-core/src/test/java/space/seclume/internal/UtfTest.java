package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.Segments;

/**
 * The conversion has to produce the same as the JDK charsets - otherwise a
 * login with an umlaut in the password fails, and with a message that looks
 * like a wrong password.
 */
class UtfTest {

    @ParameterizedTest
    @ValueSource(strings = {
        "",
        "plain-ascii",
        "Grüße aus Wien",
        "Ünïcödé-Pässwörd",
        "日本語のパスワード",
        "emoji 😀 and 𝄞 clef",
        "mixed ascii äöü 😀 end",
    })
    void utf8ToUtf16AndBack(String text) {
        byte[] utf8 = text.getBytes(StandardCharsets.UTF_8);
        byte[] utf16 = text.getBytes(StandardCharsets.UTF_16LE);

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment source = Segments.bytes(arena, utf8);
            MemorySegment wide = arena.allocate(Utf.utf16LeUpperBound(utf8.length) + 2);
            int wideLength = Utf.utf8ToUtf16Le(source, 0, utf8.length, wide, 0);
            assertEquals(utf16.length, wideLength, "UTF-16LE length for " + text);
            assertArrayEquals(utf16, Segments.toBytes(wide.asSlice(0, wideLength)));

            MemorySegment back = arena.allocate(Utf.utf8UpperBound(wideLength) + 4);
            int backLength = Utf.utf16LeToUtf8(wide, 0, wideLength, back, 0);
            assertEquals(utf8.length, backLength);
            assertArrayEquals(utf8, Segments.toBytes(back.asSlice(0, backLength)));
        }
    }

    /** The upper bounds have to hold, or someone writes past their target. */
    @ParameterizedTest
    @ValueSource(strings = {"a", "ä", "€", "😀", "aä€😀"})
    void upperBoundsHold(String text) {
        byte[] utf8 = text.getBytes(StandardCharsets.UTF_8);
        byte[] utf16 = text.getBytes(StandardCharsets.UTF_16LE);
        org.junit.jupiter.api.Assertions.assertTrue(
                Utf.utf16LeUpperBound(utf8.length) >= utf16.length,
                "UTF-16 upper bound too small for " + text);
        org.junit.jupiter.api.Assertions.assertTrue(
                Utf.utf8UpperBound(utf16.length) >= utf8.length,
                "UTF-8 upper bound too small for " + text);
    }
}
