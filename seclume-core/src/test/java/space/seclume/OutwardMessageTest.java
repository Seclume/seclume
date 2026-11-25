package space.seclume;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

/**
 * An exception's message is the server's words, a host name, a user name,
 * the application's input - none of it for an HTTP answer, which a health
 * endpoint or an admission webhook gives to whoever asks. The pool's health
 * indicator and the seclume endpoint handed it out; ErrorMessageTest, which
 * reads what is thrown, did not look at what is answered. This does: no
 * getMessage() in a statement that writes a health detail, an error response
 * or a response body.
 */
class OutwardMessageTest {

    /** What writes into an answer someone outside reads. */
    static final List<String> SINKS = List.of("withDetail(", "sendError(", ".put(\"error\"",
            "ResponseEntity", "getWriter().write", "getWriter().print", "setStatusMessage(");

    @Test
    void noExceptionMessageReachesAnHttpAnswer() throws IOException {
        List<String> findings = new ArrayList<>();
        for (Path sources : ForbiddenApiTest.productionSources()) {
            try (Stream<Path> files = Files.walk(sources)) {
                for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                    findings.addAll(findings(file.toString(),
                            Files.readString(file, StandardCharsets.UTF_8)));
                }
            }
        }
        assertTrue(findings.isEmpty(), "an exception's message in an HTTP answer:\n"
                + String.join("\n", findings));
    }

    /** The statements of {@code source} that put a getMessage() into an answer. */
    static List<String> findings(String file, String source) {
        List<String> found = new ArrayList<>();
        String[] statements = source.split(";");
        long line = 1;
        for (String statement : statements) {
            boolean sink = SINKS.stream().anyMatch(statement::contains);
            if (sink && statement.contains(".getMessage()")
                    && !statement.contains("seclume-allow")) {
                found.add(file + ":" + line + " " + statement.strip().replaceAll("\\s+", " "));
            }
            line += statement.chars().filter(c -> c == '\n').count();
        }
        return found;
    }

    @Test
    void theScanFindsWhatItLooksFor() {
        assertEquals(1, findings("A", "return down(health).withDetail(\"error\", e.getMessage());")
                .size());
        assertEquals(1, findings("B", "response.sendError(500,\n        failure.getMessage());")
                .size());
        assertEquals(1, findings("C", "source.put(\"error\", e.getMessage());").size());
        assertEquals(0, findings("D", "throw new IOException(\"x: \" + e.getMessage());").size(),
                "a thrown message is ErrorMessageTest's");
        assertEquals(0, findings("E", "detail.withDetail(\"state\", e.getSQLState());").size());
    }
}
