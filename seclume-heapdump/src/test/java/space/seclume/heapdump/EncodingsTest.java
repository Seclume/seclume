package space.seclume.heapdump;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import space.seclume.tck.SecretEncodings;

/**
 * The redaction looks for the same patterns as the test kit's check after it:
 * this module keeps its own copy of the list, and a pattern one of them gains
 * must not be missing from the other.
 */
class EncodingsTest {

    private static final List<String> TEXTS = List.of(
            "abc12", "a-longer-secret", "sk_live_DECOY_0123456789", "p@ss word/+=?&",
            "Grüße-DECOY", "quote\"back\slash\nline\ttab", "日本語-DECOY-token", "~*_.-");

    @Test
    void textPatternsMatchTheTestKit() {
        for (String text : TEXTS) {
            same(SecretEncodings.ofText(text), Encodings.ofText(text), text);
        }
    }

    @Test
    void bytePatternsMatchTheTestKit() {
        for (int length : new int[] {1, 5, 6, 7, 16, 32, 33}) {
            byte[] key = new byte[length];
            for (int i = 0; i < length; i++) {
                key[i] = (byte) (i * 37 + 11);
            }
            same(SecretEncodings.ofBytes(key), Encodings.ofBytes(key), length + " bytes");
        }
    }

    private static void same(Map<String, byte[]> kit, Map<String, byte[]> own, String what) {
        assertEquals(List.copyOf(kit.keySet()), List.copyOf(own.keySet()), what);
        for (Map.Entry<String, byte[]> entry : kit.entrySet()) {
            assertArrayEquals(entry.getValue(), own.get(entry.getKey()), what + " / " + entry.getKey());
        }
    }
}
