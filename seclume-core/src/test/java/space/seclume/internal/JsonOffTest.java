package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * The JSON reader, including the cases a search-for-the-key would get wrong.
 *
 * <p>Worth more tests than its size suggests. It sits on the path a password
 * takes out of a secret manager, and the tempting shortcut - find
 * {@code "password":} and take what follows - is wrong in at least three
 * ways that all look like working code until the day they do not. Each of
 * those is a test here.
 */
class JsonOffTest {

    private static String read(String json, String... path) {
        try (Arena arena = Arena.ofConfined()) {
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            MemorySegment document = arena.allocate(bytes.length);
            MemorySegment.copy(bytes, 0, document, ValueLayout.JAVA_BYTE, 0, bytes.length);
            MemorySegment out = arena.allocate(4096);
            int length = JsonOff.string(document, bytes.length, out, path);
            byte[] value = new byte[length];
            MemorySegment.copy(out, ValueLayout.JAVA_BYTE, 0, value, 0, length);
            return new String(value, StandardCharsets.UTF_8);
        }
    }

    private static long readNumber(String json, String... path) {
        try (Arena arena = Arena.ofConfined()) {
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            MemorySegment document = arena.allocate(bytes.length);
            MemorySegment.copy(bytes, 0, document, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return JsonOff.number(document, bytes.length, path);
        }
    }

    @Test
    void aNestedFieldIsFound() {
        assertEquals("hunter2", read(
                "{\"data\":{\"data\":{\"password\":\"hunter2\"}}}", "data", "data", "password"));
    }

    /** Vault KV v2 as it really looks, metadata and all. */
    @Test
    void aRealVaultAnswer() {
        String answer = """
                {"request_id":"7c1f...","lease_id":"","renewable":false,
                 "lease_duration":0,
                 "data":{"data":{"username":"app","password":"s3cr3t"},
                         "metadata":{"created_time":"2026-09-20T10:00:00Z","version":3}},
                 "warnings":null}""";

        assertEquals("s3cr3t", read(answer, "data", "data", "password"));
        assertEquals("app", read(answer, "data", "data", "username"));
    }

    /** The database secrets engine: the credential is one level up, with a lease. */
    @Test
    void aDynamicDatabaseCredential() {
        String answer = """
                {"lease_id":"database/creds/app/abc","renewable":true,
                 "lease_duration":3600,
                 "data":{"username":"v-token-app-x","password":"A1a-generated"}}""";

        assertEquals("A1a-generated", read(answer, "data", "password"));
        assertEquals(3600, readNumber(answer, "lease_duration"));
    }

    // ---------------------------------- what a naive search would get wrong --

    /** The word appears inside another value first. */
    @Test
    void aValueThatContainsTheFieldNameIsNotMistakenForIt() {
        assertEquals("right", read(
                "{\"note\":\"the \\\"password\\\":\\\"wrong\\\" is in here\","
                + "\"password\":\"right\"}", "password"));
    }

    /** A longer key that ends with the same letters. */
    @Test
    void aFieldWhoseNameMerelyEndsTheSameIsNotTaken() {
        assertEquals("right", read(
                "{\"old_password\":\"wrong\",\"password\":\"right\"}", "password"));
    }

    /** The same name in a nested object that is not the one asked for. */
    @Test
    void aFieldOfTheSameNameInAnotherObjectIsNotTaken() {
        assertEquals("right", read(
                "{\"metadata\":{\"password\":\"wrong\"},\"data\":{\"password\":\"right\"}}",
                "data", "password"));
    }

    /** An array in the way has to be stepped over, not walked into. */
    @Test
    void anArrayBeforeTheFieldIsSkipped() {
        assertEquals("right", read(
                "{\"policies\":[\"a\",\"b\",{\"password\":\"wrong\"}],\"password\":\"right\"}",
                "password"));
    }

    /** A brace inside a string must not be counted as nesting. */
    @Test
    void bracesInsideStringsDoNotConfuseTheSkip() {
        assertEquals("right", read(
                "{\"note\":\"a } and a { in text\",\"password\":\"right\"}", "password"));
    }

    // --------------------------------------------------------------- escapes --

    @Test
    void escapesAreUnescaped() {
        assertEquals("a\"b\\c/d\ne\tf", read(
                "{\"p\":\"a\\\"b\\\\c\\/d\\ne\\tf\"}", "p"));
    }

    @Test
    void unicodeEscapesBecomeUtf8() {
        assertEquals("gr\u00fc\u00df", read("{\"p\":\"gr\\u00fc\\u00df\"}", "p"));
        assertEquals("\u20ac", read("{\"p\":\"\\u20ac\"}", "p"));
    }

    /** Raw UTF-8 in the document passes through unchanged. */
    @Test
    void rawUtf8IsCopiedThrough() {
        assertEquals("Pa\u00dfwort-\u20ac", read("{\"p\":\"Pa\u00dfwort-\u20ac\"}", "p"));
    }

    // -------------------------------------------------------------- refusals --

    @Test
    void aMissingFieldSaysWhichOne() {
        JsonOff.NotFound missing = assertThrows(JsonOff.NotFound.class,
                () -> read("{\"data\":{}}", "data", "password"));
        assertTrue(missing.getMessage().contains("password"), missing.getMessage());
    }

    @Test
    void aTruncatedDocumentIsRefused() {
        assertThrows(JsonOff.NotFound.class, () -> read("{\"p\":\"unfinis", "p"));
    }

    @Test
    void aValueThatIsNotAStringIsRefused() {
        assertThrows(JsonOff.NotFound.class, () -> read("{\"p\":42}", "p"));
    }

    @Test
    void aValueLongerThanTheBufferIsRefused() {
        try (Arena arena = Arena.ofConfined()) {
            String json = "{\"p\":\"" + "x".repeat(100) + "\"}";
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            MemorySegment document = arena.allocate(bytes.length);
            MemorySegment.copy(bytes, 0, document, ValueLayout.JAVA_BYTE, 0, bytes.length);
            MemorySegment small = arena.allocate(16);

            assertThrows(JsonOff.NotFound.class,
                    () -> JsonOff.string(document, bytes.length, small, "p"));
        }
    }

    /** Surrogate pairs are refused rather than written out as broken UTF-8. */
    @Test
    void aSurrogateEscapeIsRefused() {
        assertThrows(JsonOff.NotFound.class, () -> read("{\"p\":\"\\ud83d\\ude00\"}", "p"));
    }

    @Test
    void hasAnswersWithoutThrowing() {
        String answer = "{\"lease_duration\":60,\"data\":{\"password\":\"x\"}}";
        try (Arena arena = Arena.ofConfined()) {
            byte[] bytes = answer.getBytes(StandardCharsets.UTF_8);
            MemorySegment document = arena.allocate(bytes.length);
            MemorySegment.copy(bytes, 0, document, ValueLayout.JAVA_BYTE, 0, bytes.length);

            assertTrue(JsonOff.has(document, bytes.length, "lease_duration"));
            assertTrue(JsonOff.has(document, bytes.length, "data", "password"));
            assertFalse(JsonOff.has(document, bytes.length, "renewable"));
            assertFalse(JsonOff.has(document, bytes.length, "data", "username"));
        }
    }

    @Test
    void whitespaceEverywhereIsFine() {
        assertEquals("x", read("  {  \"a\" : {  \"b\" :  \"x\"  }  }  ", "a", "b"));
    }

    @Test
    void anEmptyStringIsAValue() {
        assertEquals("", read("{\"p\":\"\"}", "p"));
    }
}
