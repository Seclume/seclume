package space.seclume.heapdump;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.tck.HeapDumpScanner;

/**
 * A secret as an application leaves it, not only as itself: in an
 * {@code Authorization: Basic} header, whose Base64 has the password at
 * whatever offset the user name leaves it - nothing like the password's own
 * Base64 - URL-safe, percent-encoded, JSON-escaped. The redaction overwrote
 * none of those, its check after it passed, and heapcheck said NOT FOUND for a
 * process that held the secret in a header only.
 */
class RedactorEncodingsTest {

    private static final String SECRET = "Qz-decoy+pw/\"with\\needs?3";

    private static String basic(String user) {
        return "Basic " + Base64.getEncoder().encodeToString(
                (user + ":" + SECRET).getBytes(StandardCharsets.UTF_8));
    }

    private static List<String> forms() {
        return List.of(basic("svc"), basic("abcd"), basic("admin"), basic("orders"),
                Base64.getUrlEncoder().withoutPadding().encodeToString(SECRET.getBytes(StandardCharsets.UTF_8)),
                "jdbc:x://db/app?password=" + URLEncoder.encode(SECRET, StandardCharsets.UTF_8),
                "{\"password\":\"" + SECRET.replace("\\", "\\\\").replace("\"", "\\\"") + "\"}");
    }

    private static Path dump(Path directory) throws Exception {
        TestHprof h = new TestHprof(4);
        long[] at = new long[1];
        int id = 0x400;
        for (String form : forms()) {
            h.byteArray(id++, form.getBytes(StandardCharsets.UTF_8), at);
        }
        h.finish();
        return Files.write(directory.resolve("app.hprof"), h.file.toByteArray());
    }

    /** Whether any Basic header in {@code data} decodes to something that holds the secret. */
    private static boolean decodable(byte[] data) {
        String text = new String(data, StandardCharsets.ISO_8859_1);
        java.util.regex.Matcher basic = java.util.regex.Pattern.compile("Basic ([A-Za-z0-9+/=]{8,})")
                .matcher(text);
        while (basic.find()) {
            try {
                if (new String(Base64.getDecoder().decode(basic.group(1)), StandardCharsets.UTF_8)
                        .contains(SECRET)) {
                    return true;
                }
            } catch (IllegalArgumentException redacted) {
                // overwritten: no longer Base64
            }
        }
        return false;
    }

    @Test
    void everyFormIsOverwrittenAndEachPlaceCountedOnce(@TempDir Path directory) throws Exception {
        Path dump = dump(directory);
        assertTrue(decodable(Files.readAllBytes(dump)), "the fixture holds the secret in headers");
        Path out = directory.resolve("redacted.hprof");
        Redactor.Report report = Redactor.redact(dump, out,
                List.of(Redactor.Needle.text("db-password", SECRET)), false, Set.of());
        byte[] after = Files.readAllBytes(out);
        assertFalse(decodable(after), "a Basic header still decodes to the password");
        String text = new String(after, StandardCharsets.ISO_8859_1);
        assertFalse(text.contains(URLEncoder.encode(SECRET, StandardCharsets.UTF_8)));
        assertFalse(text.contains(SECRET.replace("\\", "\\\\").replace("\"", "\\\"")));
        assertFalse(text.contains(Base64.getUrlEncoder().withoutPadding()
                .encodeToString(SECRET.getBytes(StandardCharsets.UTF_8))));
        assertEquals((long) forms().size(), (long) report.named().get("db-password"),
                "one place per form, whichever encodings matched it");
    }

    @Test
    void theScannerFindsASecretThatIsOnlyInAHeader(@TempDir Path directory) throws Exception {
        TestHprof h = new TestHprof(4);
        h.byteArray(0x400, basic("svc").getBytes(StandardCharsets.US_ASCII), new long[1]);
        h.finish();
        Path dump = Files.write(directory.resolve("header.hprof"), h.file.toByteArray());
        assertFalse(HeapDumpScanner.scan(dump, SECRET).isEmpty(),
                "heapcheck said NOT FOUND for a password in an Authorization header");
    }

    @Test
    void aShortSecretIsNotLookedForInsideBase64() {
        // Four characters of Base64 are found anywhere; a secret this short is looked for whole only.
        assertTrue(space.seclume.tck.SecretEncodings.ofText("abc12").keySet().stream()
                .noneMatch(name -> name.startsWith("Base64 inside")));
        assertTrue(space.seclume.tck.SecretEncodings.ofText("a-longer-secret").keySet().stream()
                .anyMatch(name -> name.startsWith("Base64 inside")));
    }
}
