package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import space.seclume.internal.JsonOff;

/**
 * Mutants the mutation test found alive: ConstantTime.equals with its length
 * check removed, and JsonOff fed an empty or cut-off document. Nothing used
 * them that way yet; these pin what they must do when something does.
 */
class MutationGapsTest {

    @Test
    void segmentsOfDifferentLengthsAreNeverEqual() {
        MemorySegment sixteen = MemorySegment.ofArray(new byte[16]);
        MemorySegment seventeen = MemorySegment.ofArray(new byte[17]);
        MemorySegment empty = MemorySegment.ofArray(new byte[0]);
        assertFalse(ConstantTime.equals(sixteen, seventeen));
        assertFalse(ConstantTime.equals(seventeen, sixteen));
        assertFalse(ConstantTime.equals(empty, sixteen));
        assertTrue(ConstantTime.equals(sixteen, MemorySegment.ofArray(new byte[16])));
        assertTrue(ConstantTime.equals(empty, MemorySegment.ofArray(new byte[0])));
    }

    private static MemorySegment json(String text) {
        return MemorySegment.ofArray(text.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void anEmptyOrCutOffDocumentHasNoFields() {
        assertThrows(JsonOff.NotFound.class, () -> JsonOff.number(json(""), 0, "exp"));
        assertThrows(JsonOff.NotFound.class,
                () -> JsonOff.number(json("{\"exp\":1}"), 0, "exp"), "a length of zero");
        assertThrows(JsonOff.NotFound.class,
                () -> JsonOff.number(json("{\"exp\":"), 7, "exp"), "cut off after the colon");
        assertThrows(JsonOff.NotFound.class,
                () -> JsonOff.present(json("{\"a\":1,"), 7, "exp"), "cut off before the field");
    }
}
