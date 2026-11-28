package space.seclume.heapdump;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A credential discovery found is looked for in every encoding a named secret
 * is: the password of a URL also lies in an Authorization header as
 * base64("app:" + password), at whatever offset "app:" leaves it, and as
 * URL-safe Base64. Only aligned, padded Base64 was looked for; those copies
 * stayed in the redacted dump, and the dump passed its own check.
 */
class DiscoveredEncodingsTest {

    private static final Random RANDOM = new Random(81);

    private static String alnum(int length) {
        String letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < length; i++) {
            out.append(letters.charAt(RANDOM.nextInt(letters.length())));
        }
        return out.toString();
    }

    private static boolean contains(byte[] data, String needle) {
        byte[] n = needle.getBytes(StandardCharsets.US_ASCII);
        outer:
        for (int i = 0; i + n.length <= data.length; i++) {
            for (int j = 0; j < n.length; j++) {
                if (data[i + j] != n[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    /** Whether a Basic value in {@code data} still decodes to something holding {@code secret}. */
    private static boolean decodable(byte[] data, String secret) {
        String text = new String(data, StandardCharsets.ISO_8859_1);
        java.util.regex.Matcher basic = java.util.regex.Pattern.compile("[A-Za-z0-9+/=]{16,}")
                .matcher(text);
        while (basic.find()) {
            for (int skip = 0; skip < 4; skip++) {
                String candidate = basic.group().substring(skip);
                candidate = candidate.substring(0, candidate.length() - candidate.length() % 4);
                try {
                    if (new String(Base64.getDecoder().decode(candidate), StandardCharsets.ISO_8859_1)
                            .contains(secret)) {
                        return true;
                    }
                } catch (IllegalArgumentException notBase64) {
                    // overwritten, or not Base64 from here
                }
            }
        }
        return false;
    }

    @Test
    void aDiscoveredPasswordGoesInItsHeaderAndItsUrlSafeForm(@TempDir Path directory)
            throws Exception {
        String password = alnum(20);
        String url = "postgresql://app:" + password + "@db.internal:5432/app";
        String header = "Authorization: Basic " + Base64.getEncoder().encodeToString(
                ("app:" + password).getBytes(StandardCharsets.US_ASCII));
        String urlSafe = Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("x" + password).getBytes(StandardCharsets.US_ASCII));
        TestHprof h = new TestHprof(4);
        long[] at = new long[1];
        h.byteArray(0x700, url.getBytes(StandardCharsets.US_ASCII), at);
        h.byteArray(0x701, header.getBytes(StandardCharsets.US_ASCII), at);
        h.byteArray(0x702, urlSafe.getBytes(StandardCharsets.US_ASCII), at);
        h.finish();
        Path dump = Files.write(directory.resolve("app.hprof"), h.file.toByteArray());
        byte[] before = Files.readAllBytes(dump);
        assertTrue(decodable(before, password), "the fixture holds the password in its header");

        Path out = directory.resolve("redacted.hprof");
        Redactor.redact(dump, out, List.of(), true, Set.of());

        byte[] after = Files.readAllBytes(out);
        assertFalse(contains(after, password), "the password itself");
        assertFalse(decodable(after, password), "the Authorization header still decodes to it");
        assertTrue(contains(after, "@db.internal:5432/app"), "what is not the credential stays");
    }
}
