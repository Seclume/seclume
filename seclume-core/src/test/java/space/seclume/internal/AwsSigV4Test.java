package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * UTF-8 encoding in native memory for AWS SigV4, checked against the platform's
 * {@link StandardCharsets#UTF_8} implementation.
 */
class AwsSigV4Test {

    @ParameterizedTest
    @ValueSource(strings = {
        "",
        "hello-world",
        "GET\n/v1/resource\nkey=value",
        "München-Grüße",
        "こんにちは世界",
        "🚀",
        "hello 🌍 world 🎉!",
        "/path/with/emoji/🔥/and/text/✨",
        "complex 👩‍💻 emoji sequence with ZWJ and modifiers 🧑🏿‍🚀"
    })
    void encodesUtf8IdenticalToStandardCharsets(String input) {
        byte[] expected = input.getBytes(StandardCharsets.UTF_8);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(input.length() * 3L + 1);
            int written = AwsSigV4.writeAscii(target, input);
            assertEquals(expected.length, written);
            byte[] actual = target.asSlice(0, written).toArray(ValueLayout.JAVA_BYTE);
            assertArrayEquals(expected, actual);
        }
    }

    @Test
    void rejectsUnpairedHighSurrogateAtEnd() {
        String input = "test" + Character.MIN_HIGH_SURROGATE;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(32);
            assertThrows(IllegalArgumentException.class, () -> AwsSigV4.writeAscii(target, input));
        }
    }

    @Test
    void rejectsUnpairedHighSurrogateFollowedByNonSurrogate() {
        String input = "test" + Character.MIN_HIGH_SURROGATE + "abc";
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(32);
            assertThrows(IllegalArgumentException.class, () -> AwsSigV4.writeAscii(target, input));
        }
    }

    @Test
    void rejectsUnpairedLowSurrogate() {
        String input = "test" + Character.MIN_LOW_SURROGATE + "abc";
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(32);
            assertThrows(IllegalArgumentException.class, () -> AwsSigV4.writeAscii(target, input));
        }
    }

    @Test
    void rejectsReversedSurrogates() {
        String input = "" + Character.MIN_LOW_SURROGATE + Character.MIN_HIGH_SURROGATE;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(32);
            assertThrows(IllegalArgumentException.class, () -> AwsSigV4.writeAscii(target, input));
        }
    }

    @Test
    void sha256HexHandlesSupplementaryCharactersWithoutOverflow() {
        String text = "GET\n/api/v1/items/🔥/details\n\nhost:example.amazonaws.com\n";
        String hex = AwsSigV4.sha256Hex(text);
        assertEquals(64, hex.length());
    }
}
