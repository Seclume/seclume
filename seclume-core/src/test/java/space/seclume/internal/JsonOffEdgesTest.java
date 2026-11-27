package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * The edges of the JSON reader that reads secrets off the heap: what a
 * hostile or broken server could answer. Each is refused - never read as
 * something else, never past the length given.
 */
class JsonOffEdgesTest {

    private static MemorySegment json(Arena arena, byte[] bytes) {
        MemorySegment segment = arena.allocate(Math.max(1, bytes.length));
        MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return segment;
    }

    private static MemorySegment json(Arena arena, String text) {
        return json(arena, text.getBytes(StandardCharsets.UTF_8));
    }

    /** A raw 0x00 inside a string is a control character, refused like the others. */
    @Test
    void aRawNulInAStringIsRefused() {
        try (Arena arena = Arena.ofConfined()) {
            byte[] bytes = "{\"a\":\"x?y\"}".getBytes(StandardCharsets.US_ASCII);
            bytes[7] = 0;
            MemorySegment in = json(arena, bytes);
            MemorySegment out = arena.allocate(16);
            assertThrows(RuntimeException.class,
                    () -> JsonOff.string(in, bytes.length, out, "a"));
        }
    }

    /** A lone surrogate, low or high, at either end of the range: no such character. */
    @Test
    void loneSurrogatesAreRefused() {
        try (Arena arena = Arena.ofConfined()) {
            for (String escape : new String[] {"\\udfff", "\\udc00", "\\ud800", "\\udbff"}) {
                String text = "{\"a\":\"" + escape + "\"}";
                MemorySegment in = json(arena, text);
                MemorySegment out = arena.allocate(16);
                assertThrows(RuntimeException.class,
                        () -> JsonOff.string(in, text.length(), out, "a"), escape);
            }
        }
    }

    /** number() of something that is not a number - an array, a cut document. */
    @Test
    void numberOfAnArrayOrACutDocumentIsRefused() {
        try (Arena arena = Arena.ofConfined()) {
            for (String text : new String[] {"[", "[1]", "{\"n\":[1]}", "{\"n\":", "{\"n\":1"}) {
                MemorySegment in = json(arena, text);
                String[] path = text.startsWith("{") ? new String[] {"n"} : new String[0];
                if (text.equals("{\"n\":1")) {
                    // The value itself is whole; the document around it is cut
                    // - read or refused, never read past the end.
                    try {
                        assertEquals(1, JsonOff.number(in, text.length(), path));
                    } catch (RuntimeException refused) {
                        // refused is fine too
                    }
                    continue;
                }
                assertThrows(RuntimeException.class,
                        () -> JsonOff.number(in, text.length(), path), text);
            }
        }
    }

    /** has() on a cut object and on an unquoted key: no field found, no read past the end. */
    @Test
    void hasOnACutObjectOrAnUnquotedKey() {
        try (Arena arena = Arena.ofConfined()) {
            String cut = "{\"b\":1";
            MemorySegment in = json(arena, cut);
            try {
                assertFalse(JsonOff.has(in, cut.length(), "a"));
            } catch (RuntimeException refused) {
                // refused is fine
            }
            String unquoted = "{a:1}";
            MemorySegment bad = json(arena, unquoted);
            try {
                assertFalse(JsonOff.has(bad, unquoted.length(), "a"),
                        "an unquoted key was taken for the field");
            } catch (RuntimeException refused) {
                // refused is fine
            }
        }
    }

    /** A length that cuts a string value: the string is not read past it. */
    @Test
    void aLengthThatCutsTheStringIsRefused() {
        try (Arena arena = Arena.ofConfined()) {
            String text = "{\"a\":\"xy\"}";
            MemorySegment in = json(arena, text);
            for (int length = 6; length < text.length() - 1; length++) {
                MemorySegment out = arena.allocate(16).fill((byte) 0x5a);
                int cutAt = length;
                assertThrows(RuntimeException.class,
                        () -> JsonOff.string(in, cutAt, out, "a"), "length " + cutAt);
            }
        }
    }
}
