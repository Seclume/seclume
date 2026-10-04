package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import com.code_intelligence.jazzer.junit.FuzzTest;

/** Only synthetic test data crosses the heap in these independent oracles. */
class JsonOffFuzzTest {

    private static final int MAX_INPUT = 8192;
    private static final byte GUARD = 0x5a;
    private static final String[][] PATHS = {{}, {"p"}, {"data", "data", "password"}};

    @FuzzTest(maxDuration = "60s")
    void arbitraryDocumentsStayWithinBounds(byte[] bytes) {
        if (bytes.length > MAX_INPUT) {
            return;
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment document = arena.allocate(Math.max(1, bytes.length))
                    .asSlice(0, bytes.length);
            MemorySegment.copy(bytes, 0, document, ValueLayout.JAVA_BYTE, 0, bytes.length);
            MemorySegment input = document.asReadOnly();
            MemorySegment storage = arena.allocate(bytes.length + 2L);
            int prefix = bytes.length == 0 ? 0 : (bytes[bytes.length - 1] & 0xff) % bytes.length;
            int small = bytes.length == 0 ? 0 : (bytes[0] & 0xff) % (bytes.length + 1);
            for (int length : new int[] {bytes.length, prefix}) {
                // An exact input slice exposes reads beyond the declared length.
                MemorySegment slice = input.asSlice(0, length);
                for (String[] path : PATHS) {
                    for (int capacity : new int[] {bytes.length, small}) {
                        storage.fill(GUARD);
                        MemorySegment output = storage.asSlice(1, capacity);
                        try {
                            int written = JsonOff.string(slice, length, output, path);
                            assertTrue(written >= 0 && written <= capacity);
                            assertTrue(JsonOff.has(slice, length, path));
                        } catch (JsonOff.NotFound refused) {
                            // The sole documented parse/path/space failure.
                        }
                        assertEquals(GUARD, storage.get(ValueLayout.JAVA_BYTE, 0));
                        assertEquals(GUARD, storage.get(ValueLayout.JAVA_BYTE, capacity + 1L));
                    }
                    try {
                        JsonOff.number(slice, length, path);
                    } catch (JsonOff.NotFound refused) {
                        // A non-integral or missing value is allowed to fail.
                    }
                    JsonOff.has(slice, length, path);
                }
            }
            for (int invalid : new int[] {-1, bytes.length + 1, Integer.MAX_VALUE}) {
                assertThrows(JsonOff.NotFound.class,
                        () -> JsonOff.string(input, invalid, storage, "p"));
                assertThrows(JsonOff.NotFound.class,
                        () -> JsonOff.number(input, invalid, "p"));
                assertFalse(JsonOff.has(input, invalid));
            }
            assertArrayEquals(bytes, document.toArray(ValueLayout.JAVA_BYTE));
        }
    }

    @FuzzTest(maxDuration = "60s")
    void generatedValuesRoundTrip(byte[] bytes) {
        if (bytes.length > MAX_INPUT) {
            return;
        }
        // The JDK supplies the expected UTF-8; the JSON quoting below is a
        // test-only encoder, independent of JsonOff's decoder.
        String value = new String(bytes, StandardCharsets.UTF_8);
        byte[] expected = value.getBytes(StandardCharsets.UTF_8);
        long number = 0;
        for (int i = 0; i < Math.min(Long.BYTES, bytes.length); i++) {
            number = (number << 8) | (bytes[i] & 0xffL);
        }
        String[] path = {"data", "data", "password"};
        for (boolean escapeBmp : new boolean[] {false, true}) {
            String quoted = quote(value, escapeBmp);
            String json = "{\"metadata\":[null,true,false,1.5,{\"password\":\"wrong\"}],"
                    + "\"p\":\"wrong\",\"data\":{\"data\":{\"password\":" + quoted
                    + "}},\"n\":" + number + "}";
            byte[] encoded = json.getBytes(StandardCharsets.UTF_8);
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment document = arena.allocate(encoded.length);
                MemorySegment.copy(encoded, 0, document, ValueLayout.JAVA_BYTE, 0, encoded.length);
                MemorySegment storage = arena.allocate(expected.length + 2L).fill(GUARD);
                MemorySegment output = storage.asSlice(1, expected.length);
                int written = JsonOff.string(document.asReadOnly(), encoded.length, output, path);
                assertEquals(expected.length, written);
                assertArrayEquals(expected, output.toArray(ValueLayout.JAVA_BYTE));
                assertEquals(GUARD, storage.get(ValueLayout.JAVA_BYTE, 0));
                assertEquals(GUARD, storage.get(ValueLayout.JAVA_BYTE, expected.length + 1L));
                assertEquals(number, JsonOff.number(document, encoded.length, "n"));
                assertTrue(JsonOff.has(document, encoded.length, path));
                assertFalse(JsonOff.has(document, encoded.length, "data", "missing"));
                assertArrayEquals(encoded, document.toArray(ValueLayout.JAVA_BYTE));
                if (expected.length > 0) {
                    assertThrows(JsonOff.NotFound.class, () -> JsonOff.string(document,
                            encoded.length, output.asSlice(0, expected.length - 1), path));
                }
            }
        }
    }

    private static String quote(String value, boolean escapeBmp) {
        StringBuilder json = new StringBuilder("\"");
        String hex = "0123456789abcdef";
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\\') {
                json.append('\\').append(c);
            } else if (c < 0x20 || (escapeBmp && !Character.isSurrogate(c))) {
                json.append("\\u");
                for (int shift = 12; shift >= 0; shift -= 4) {
                    json.append(hex.charAt((c >>> shift) & 15));
                }
            } else {
                // Supplementary characters stay raw UTF-8: surrogate escapes
                // are explicitly outside JsonOff's supported subset.
                json.append(c);
            }
        }
        return json.append('"').toString();
    }
}
