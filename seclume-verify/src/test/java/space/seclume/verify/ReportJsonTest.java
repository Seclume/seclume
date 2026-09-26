package space.seclume.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import space.seclume.internal.JsonOff;

/**
 * The machine-readable half of the report.
 *
 * <p>The text report is read by a person, who forgives a stray quote. This one
 * is read by a pipeline, which does not: a document that does not parse is the
 * same as no check at all, and it fails in the build rather than here.
 *
 * <p>So every assertion below goes through a reader rather than through
 * {@code contains}. The reader is {@link JsonOff}, the project's own - which
 * makes this test the one place where the two halves meet.
 */
class ReportJsonTest {

    /** The shape a probe depends on: the flag, the code, the sections. */
    @Test
    void theDocumentSaysWhetherItStandsAndWhy() {
        Report report = new Report();
        report.title("seclume-verify");
        report.line("driver", "space.seclume.postgresql.PgDriver 0.9");
        report.title("what this driver can do against this server");
        report.line("round trips counted", "true");

        String json = report.json(0);
        read(json, document -> {
            assertEquals(0, JsonOff.number(document.segment(), document.length(), "status"),
                    json);
            assertEquals("space.seclume.postgresql.PgDriver 0.9",
                    string(document, "sections", "seclume_verify", "driver"), json);
            assertEquals("true", string(document, "sections",
                    "what_this_driver_can_do_against_this_server", "round_trips_counted"),
                    json);
        });
        assertTrue(ok(json), json);
    }

    /**
     * A failure has to be a failure in the document too.
     *
     * <p>This is the assertion the whole flag exists for. A probe that reads
     * {@code ok} out of a report of a connection that never opened, and finds
     * it true because the writer used "are there problems" instead of "what is
     * the exit code", would pass a build over a database that is not there.
     */
    @Test
    void aConnectionThatFailedIsNotOk() {
        Report report = new Report();
        assertEquals(1, Verify.run("jdbc:something:else://host/db", report));
        String json = report.json(1);
        read(json, document -> {
            assertEquals(1, JsonOff.number(document.segment(), document.length(), "status"),
                    json);
        });
        assertFalse(ok(json), json);
        assertTrue(json.contains("problems"), json);
        assertTrue(json.contains("jdbc:seclume:postgresql"), json);
    }

    /**
     * Notes are not a failure.
     *
     * <p>A connection that stands but has something worth mentioning exits 0,
     * and the document says so with the notes beside it. Reporting a note as
     * {@code ok: false} would teach people to stop writing notes.
     */
    @Test
    void aNoteDoesNotTurnTheDocumentRed() {
        Report report = new Report();
        report.title("verdict");
        report.line("result", "reachable, with the notes above");
        report.problem("The server does not read in blocks; a large result comes at once.");

        String json = report.json(0);
        read(json, document ->
                assertEquals(0, JsonOff.number(document.segment(), document.length(), "status"),
                        json));
        assertTrue(ok(json), json);
    }

    /**
     * A server's own sentence arrives here verbatim, quotes and all.
     *
     * <p>Nothing in the code below controls what a strange server says when it
     * refuses a login. A quote or a newline in it would end the document early
     * and take the {@code ok} field with it.
     */
    @Test
    void whatTheServerSaidCannotBreakTheDocument() {
        String awkward = "he said \"no\"\nand a tab\there, plus a backslash \\ and a null \u0001";
        Report report = new Report();
        report.title("connect");
        report.line("said", awkward);

        String json = report.json(1);
        read(json, document ->
                assertEquals(awkward, string(document, "sections", "connect", "said"), json));
    }

    /**
     * And the rule the whole library exists for, restated in JSON.
     *
     * <p>The text report takes the password out of the URL. The document is
     * built from the same lines, so it does too - but "so it does too" is an
     * inference, and this is the project where inferences about secrets get
     * tested.
     */
    @Test
    void noPasswordReachesTheDocument() {
        Report report = new Report();
        Verify.run("jdbc:seclume:postgresql://127.0.0.1:1/db?user=app&password=hunter2", report);
        String json = report.json(1);
        assertFalse(json.contains("hunter2"), json);
    }

    /** Keys a consumer can index without quoting them. */
    @Test
    void keysBecomeSlugs() {
        assertEquals("round_trips_counted", Report.slug("round trips counted"));
        assertEquals("two_phase_commit", Report.slug("two-phase commit"));
        assertEquals("seclume_verify", Report.slug("seclume-verify"));
        assertEquals("result", Report.slug("  result  "));
        assertEquals("_", Report.slug("---"));
    }

    // ---- reading it back -------------------------------------------------

    private record Document(MemorySegment segment, int length) {
    }

    private interface Check {
        void run(Document document);
    }

    private static void read(String json, Check check) {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment segment = arena.allocate(bytes.length);
            MemorySegment.copy(bytes, 0, segment, java.lang.foreign.ValueLayout.JAVA_BYTE, 0,
                    bytes.length);
            check.run(new Document(segment, bytes.length));
        }
    }

    /**
     * The {@code ok} flag, read as text and not through {@link JsonOff}.
     *
     * <p>{@code JsonOff} is a credential reader: it walks to a value and
     * copies a string or a number, and it has no need of booleans. Rather than
     * grow it for a test, the flag is read here and {@code status} - which is
     * the same answer as a number - is read through the parser in every test
     * that checks it. If the two ever disagreed, one of these assertions
     * would fail.
     */
    private static boolean ok(String json) {
        assertTrue(json.contains("\"ok\": true") || json.contains("\"ok\": false"),
                "the document has no ok flag at all: " + json);
        return json.contains("\"ok\": true");
    }

    private static String string(Document document, String... path) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(4096);
            int written = JsonOff.string(document.segment(), document.length(), out, path);
            byte[] copy = new byte[written];
            MemorySegment.copy(out, java.lang.foreign.ValueLayout.JAVA_BYTE, 0, copy, 0, written);
            return new String(copy, StandardCharsets.UTF_8);
        }
    }
}
