package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * {@code putText} writes what {@code String.getBytes(UTF_8)} would have.
 *
 * <p>There was no test for this at all, and then it grew a second path: ASCII
 * goes straight into native memory one byte at a time and allocates nothing,
 * anything else falls back to the general encoder. Every message of all four
 * drivers goes through here, so the two paths have to agree byte for byte.
 *
 * <p>The case that earns the test is the one in the middle: text that starts
 * ASCII and turns into something else. The fast path has already written bytes
 * by then and gives up; the fallback has to land on top of them, not after
 * them. Get that wrong and the wire carries a few characters twice - which the
 * server answers with a parse error somewhere entirely unrelated.
 */
class WireBufferTextTest {

    @ParameterizedTest
    @ValueSource(strings = {
        "",                                   // the commonest of all: portal names
        "select 1",
        "S_1",
        "insert into zl_bench_insert (n, t) values ($1, $2)",
        "Grüße",                              // non-ASCII from the first character
        "select 'Grüße'",                     // ASCII first, then not - the bail-out
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaß",    // bail-out on the very last character
        "ß",
        "€",                                  // three bytes in UTF-8
        "a€b",
        "𝄞",                                  // four bytes, a surrogate pair
        "table_ÄÖÜ_name",
    })
    void writesWhatTheEncoderWouldHave(String text) {
        byte[] expected = text.getBytes(StandardCharsets.UTF_8);
        try (WireBuffer buffer = new WireBuffer(8)) {   // small on purpose: it has to grow
            buffer.putText(text);
            assertEquals(expected.length, buffer.position(),
                    "wrong number of bytes written for \"" + text + "\"");
            byte[] written = new byte[buffer.position()];
            for (int i = 0; i < written.length; i++) {
                written[i] = buffer.getByte(i);
            }
            assertArrayEquals(expected, written, "bytes differ for \"" + text + "\"");
        }
    }

    /** The same, with the trailing zero the protocol wants everywhere. */
    @ParameterizedTest
    @ValueSource(strings = {"", "select 1", "Grüße", "select 'Grüße'"})
    void putCStringAppendsTheZero(String text) {
        byte[] body = text.getBytes(StandardCharsets.UTF_8);
        try (WireBuffer buffer = new WireBuffer(8)) {
            buffer.putCString(text);
            assertEquals(body.length + 1, buffer.position());
            for (int i = 0; i < body.length; i++) {
                assertEquals(body[i], buffer.getByte(i), "byte " + i + " of \"" + text + "\"");
            }
            assertEquals(0, buffer.getByte(body.length), "the terminator is missing");
        }
    }

    /**
     * Two writes in a row, the first ASCII and the second not.
     *
     * <p>Nothing here is exotic - it is what a statement with a bind value
     * looks like - and it is the arrangement in which a fast path that leaves
     * the position in the wrong place shows up.
     */
    @ParameterizedTest
    @ValueSource(strings = {"Grüße", "ß", "€"})
    void aFallbackDoesNotDisturbWhatCameBefore(String tail) {
        String head = "select ";
        byte[] expected = (head + tail).getBytes(StandardCharsets.UTF_8);
        try (WireBuffer buffer = new WireBuffer(4)) {
            buffer.putText(head);
            buffer.putText(tail);
            assertEquals(expected.length, buffer.position());
            byte[] written = new byte[buffer.position()];
            for (int i = 0; i < written.length; i++) {
                written[i] = buffer.getByte(i);
            }
            assertArrayEquals(expected, written);
        }
    }
}
