package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * JsonOff.has answered false for "not there" and for "could not read that
 * far" alike. A check that applies a claim only when it is there - exp, nbf,
 * crit - skipped it for a document broken in front of the claim. present
 * says false only where the object ends without the field.
 */
class JsonOffPresentTest {

    private static boolean present(String json, String... path) {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        return JsonOff.present(MemorySegment.ofArray(bytes), bytes.length, path);
    }

    @Test
    void absentOnlyWhereTheObjectReadsThrough() {
        assertTrue(present("{\"sub\":\"a\",\"exp\":1}", "exp"));
        assertFalse(present("{\"sub\":\"a\"}", "exp"), "read through, and not there");
        assertFalse(present("{\"a\":{\"b\":1}}", "a", "c"));
    }

    @Test
    void aDocumentBrokenBeforeTheFieldIsNoAbsence() {
        for (String broken : new String[] {
            "{\"sub\":\"a\" \"exp\":1}",                    // a comma missing
            "[{\"exp\":1}]",                              // an array, not an object
            "{\"sub\":\"a\u0001\",\"exp\":1}",            // a control character
            "{\"sub\":" + "[".repeat(600) + "]".repeat(600) + ",\"exp\":1}"}) {
            assertThrows(JsonOff.NotFound.class, () -> present(broken, "exp"), broken);
        }
    }
}
