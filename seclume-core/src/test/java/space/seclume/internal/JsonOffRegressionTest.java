package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * JsonOff against the inputs the audit of 27.09.2026 found it too lenient
 * with (N4, N8): numbers that overflow, raw control characters, brackets that
 * do not match, nesting without end. Each must be refused - and refused as
 * {@link JsonOff.NotFound}, the one failure its callers expect.
 *
 * <p>The documents here are public test data; none contains a secret.
 */
@Timeout(30)
class JsonOffRegressionTest {

    private static long number(String json, String... path) {
        try (Arena arena = Arena.ofConfined()) {
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            MemorySegment document = arena.allocate(Math.max(bytes.length, 1));
            MemorySegment.copy(bytes, 0, document, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return JsonOff.number(document, bytes.length, path);
        }
    }

    private static int string(String json, String... path) {
        try (Arena arena = Arena.ofConfined()) {
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            MemorySegment document = arena.allocate(Math.max(bytes.length, 1));
            MemorySegment.copy(bytes, 0, document, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return JsonOff.string(document, bytes.length, arena.allocate(256), path);
        }
    }

    // ---- N4: numbers --------------------------------------------------------

    @Test
    void theLargestLongIsRead() {
        assertEquals(Long.MAX_VALUE, number("{\"lease_duration\": 9223372036854775807}",
                "lease_duration"));
    }

    @Test
    void theSmallestLongIsRead() {
        assertEquals(Long.MIN_VALUE, number("{\"n\": -9223372036854775808}", "n"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "9223372036854775808",                 // one past Long.MAX_VALUE
        "-9223372036854775809",                // one past Long.MIN_VALUE
        "18446744073709551616",                // 2^64, which used to wrap to 0
        "99999999999999999999999999999999",
    })
    void aNumberThatDoesNotFitIsRefusedNotWrapped(String value) {
        assertThrows(JsonOff.NotFound.class, () -> number("{\"n\": " + value + "}", "n"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"012", "-01", "12abc", "1.5", "1e3", "-", "+1", "0x10"})
    void somethingThatIsNotAJsonIntegerIsRefused(String value) {
        assertThrows(JsonOff.NotFound.class, () -> number("{\"n\": " + value + "}", "n"));
    }

    @Test
    void zeroAndNegativeZeroAreNumbers() {
        assertEquals(0, number("{\"n\": 0}", "n"));
        assertEquals(0, number("{\"n\": -0 }", "n"));
    }

    @Test
    void aNegativeLeaseIsReadAsWritten() {
        assertEquals(-5, number("{\"n\":-5,\"m\":1}", "n"));
    }

    // ---- N8: strings and structure -----------------------------------------

    @Test
    void aRawControlCharacterInAValueIsRefused() {
        assertThrows(JsonOff.NotFound.class, () -> string("{\"p\": \"a\u0001b\"}", "p"));
        assertThrows(JsonOff.NotFound.class, () -> string("{\"p\": \"a\nb\"}", "p"));
    }

    private static byte[] decoded(String json, String... path) {
        try (Arena arena = Arena.ofConfined()) {
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            MemorySegment document = arena.allocate(Math.max(bytes.length, 1));
            MemorySegment.copy(bytes, 0, document, ValueLayout.JAVA_BYTE, 0, bytes.length);
            MemorySegment out = arena.allocate(64);
            int length = JsonOff.string(document, bytes.length, out, path);
            return out.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE);
        }
    }

    /** An escape is written as the UTF-8 it stands for, on both sides of the two-byte limit. */
    @Test
    void escapesAtTheUtf8LengthBoundariesAreWrittenRight() {
        org.junit.jupiter.api.Assertions.assertArrayEquals(new byte[] {(byte) 0xdf, (byte) 0xbf},
                decoded("{\"p\": \"\\u07ff\"}", "p"), "U+07FF is two bytes");
        org.junit.jupiter.api.Assertions.assertArrayEquals(
                new byte[] {(byte) 0xe0, (byte) 0xa0, (byte) 0x80},
                decoded("{\"p\": \"\\u0800\"}", "p"), "U+0800 is three bytes");
        org.junit.jupiter.api.Assertions.assertArrayEquals(new byte[] {0x7f},
                decoded("{\"p\": \"\\u007f\"}", "p"), "U+007F is one byte");
    }

    /** DEL is no control character in JSON: a field named by it is a field like any other. */
    @Test
    void aFieldNamedByDelIsFound() {
        try (Arena arena = Arena.ofConfined()) {
            byte[] bytes = "{\"\u007f\": 1}".getBytes(StandardCharsets.UTF_8);
            MemorySegment document = arena.allocate(bytes.length);
            MemorySegment.copy(bytes, 0, document, ValueLayout.JAVA_BYTE, 0, bytes.length);
            org.junit.jupiter.api.Assertions.assertTrue(JsonOff.has(document, bytes.length, "\u007f"));
            assertFalse(JsonOff.has(document, bytes.length, "\u007e"));
        }
    }

    /** The edges of RFC 8259's range: NUL and U+001F refused, a space read. */
    @Test
    void aRawNulInAStringIsRefused() {
        assertThrows(JsonOff.NotFound.class, () -> string("{\"p\": \"a\u0000b\"}", "p"));
        assertThrows(JsonOff.NotFound.class, () -> string("{\"p\": \"a\u001fb\"}", "p"));
        assertEquals(3, string("{\"p\": \"a b\"}", "p"));
    }

    @Test
    void aRawControlCharacterInASkippedValueIsRefused() {
        assertThrows(JsonOff.NotFound.class,
                () -> string("{\"other\": \"x\ty\", \"p\": \"v\"}", "p"));
    }

    @Test
    void anEscapedControlCharacterIsFine() {
        assertEquals(3, string("{\"p\": \"a\\nb\"}", "p"));
    }

    @Test
    void mismatchedBracketsInASkippedValueAreRefused() {
        assertThrows(JsonOff.NotFound.class,
                () -> string("{\"a\": {\"b\": [1}], \"p\": \"v\"}", "p"));
        assertThrows(JsonOff.NotFound.class,
                () -> string("{\"a\": [{\"b\": 1]}, \"p\": \"v\"}", "p"));
    }

    @Test
    void wellNestedStructuresBeforeTheFieldAreSkipped() {
        assertEquals(1, string("{\"a\": {\"b\": [1, {\"c\": []}, \"]\"]}, \"p\": \"v\"}", "p"));
    }

    @Test
    void nestingBeyondTheLimitIsRefusedWithoutAStackOverflow() {
        int depth = JsonOff.MAX_DEPTH + 1;
        String json = "{\"a\": " + "[".repeat(depth) + "]".repeat(depth) + ", \"p\": \"v\"}";
        assertThrows(JsonOff.NotFound.class, () -> string(json, "p"));
    }

    @Test
    void nestingUpToTheLimitIsFine() {
        int depth = JsonOff.MAX_DEPTH;
        String json = "{\"a\": " + "[".repeat(depth) + "]".repeat(depth) + ", \"p\": \"v\"}";
        assertEquals(1, string(json, "p"));
    }

    @Test
    void aTruncatedDocumentIsRefusedAtEveryLength() {
        String json = "{\"a\": [1, {\"b\": \"x\"}], \"p\": \"value\", \"n\": 12}";
        for (int cut = 0; cut < json.length() - 1; cut++) {
            String part = json.substring(0, cut);
            try {
                string(part, "p");
            } catch (JsonOff.NotFound expected) {
                // the only acceptable failure
            }
        }
    }

    @Test
    void aLoneSurrogateEscapeIsRefused() {
        assertThrows(JsonOff.NotFound.class, () -> string("{\"p\": \"\\ud83d\"}", "p"));
    }

    @Test
    void aMalformedEscapeIsRefused() {
        assertThrows(JsonOff.NotFound.class, () -> string("{\"p\": \"\\x41\"}", "p"));
        assertThrows(JsonOff.NotFound.class, () -> string("{\"p\": \"\\u12G4\"}", "p"));
    }

    @Test
    void aValueLongerThanItsSpaceIsRefused() {
        assertThrows(JsonOff.NotFound.class,
                () -> string("{\"p\": \"" + "y".repeat(300) + "\"}", "p"));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 2, Integer.MAX_VALUE})
    void documentLengthMustFitTheSourceSegment(int length) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment document = arena.allocate(1);
            document.set(ValueLayout.JAVA_BYTE, 0, (byte) '"');
            assertThrows(JsonOff.NotFound.class,
                    () -> JsonOff.string(document, length, arena.allocate(8)));
            assertThrows(JsonOff.NotFound.class, () -> JsonOff.number(document, length));
            assertFalse(JsonOff.has(document, length));
        }
    }
}
