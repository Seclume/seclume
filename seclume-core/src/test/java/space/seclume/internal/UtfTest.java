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

    /**
     * What is not UTF-8 is refused, not read as something else: a lone
     * continuation byte, a byte UTF-8 never uses, a sequence cut short by a
     * start byte, an overlong NUL, a surrogate written as UTF-8 and a code
     * point beyond Unicode. Taken leniently, a mistyped secret became a
     * different one.
     */
    @ParameterizedTest
    @ValueSource(strings = {"80", "41BF42", "F8888080", "FF", "C341", "C080", "E0808F",
        "EDA080", "F4908080"})
    void whatIsNotUtf8IsRefused(String hex) {
        byte[] bytes = java.util.HexFormat.of().parseHex(hex);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment source = Segments.bytes(arena, bytes);
            MemorySegment wide = arena.allocate(Utf.utf16LeUpperBound(bytes.length) + 4);
            org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                    () -> Utf.utf8ToUtf16Le(source, 0, bytes.length, wide, 0), hex);
        }
    }

    /** Half a surrogate pair is refused rather than written as CESU-8. */
    @ParameterizedTest
    @ValueSource(strings = {"00D8", "4100", "00DC4100"})
    void anUnpairedSurrogateIsRefused(String hex) {
        byte[] bytes = java.util.HexFormat.of().parseHex(hex);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment source = Segments.bytes(arena, bytes);
            MemorySegment narrow = arena.allocate(Utf.utf8UpperBound(bytes.length) + 4);
            if (hex.equals("4100")) {
                assertEquals(1, Utf.utf16LeToUtf8(source, 0, bytes.length, narrow, 0),
                        "a plain 'A' is not a surrogate");
                return;
            }
            org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                    () -> Utf.utf16LeToUtf8(source, 0, bytes.length, narrow, 0), hex);
        }
    }
}
