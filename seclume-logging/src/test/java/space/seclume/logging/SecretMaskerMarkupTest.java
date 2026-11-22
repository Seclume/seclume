package space.seclume.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.StreamHandler;
import java.util.logging.XMLFormatter;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.logging.jul.RedactingFormatter;
import space.seclume.tck.StaticSecretProvider;

/**
 * A secret with {@code & < > " '} as XML and HTML writers put it in a line:
 * as character references, named or numeric. java.util.logging's XMLFormatter
 * wrote such a secret to the log unmasked; the line is read with its
 * references resolved now as well. Isolated: the JUL test installs the
 * masker for the whole JVM.
 */
@Isolated
class SecretMaskerMarkupTest {

    private static final String SECRET = "Qz&decoy<log>\"secret'4711/";

    private static String escaped(String text, boolean quotes, String apostrophe, boolean slash) {
        StringBuilder out = new StringBuilder();
        for (char c : text.toCharArray()) {
            switch (c) {
                case '&' -> out.append("&amp;");
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '"' -> out.append(quotes ? "&quot;" : "\"");
                case '\'' -> out.append(quotes ? apostrophe : "'");
                case '/' -> out.append(slash ? "&#x2F;" : "/");
                default -> out.append(c);
            }
        }
        return out.toString();
    }

    private static String numeric(String text, boolean hex) {
        StringBuilder out = new StringBuilder();
        text.codePoints().forEach(c -> out.append(hex ? "&#x" + Integer.toHexString(c) + ";" : "&#" + c + ";"));
        return out.toString();
    }

    @Test
    void theReferencesWritersUse() {
        try (SecretMasker masker = new SecretMasker(Map.of("db", new StaticSecretProvider(SECRET)))) {
            String[] lines = {
                escaped(SECRET, false, "'", false),            // XMLFormatter: & < > only
                escaped(SECRET, true, "&apos;", false),        // XML writers, Log4j 2's %enc{}{XML}
                escaped(SECRET, true, "&#39;", false),         // HTML escapers
                escaped(SECRET, true, "&#x27;", true),         // Log4j 2's %enc{}{HTML}
                numeric(SECRET, false),
                numeric(SECRET, true).toUpperCase(java.util.Locale.ROOT).replace("&#X", "&#x"),
                numeric(SECRET, false).replace("&#", "&#0000000"),   // leading zeros are allowed
            };
            for (String encoded : lines) {
                assertEquals("<message>login with [redacted:db] failed</message>",
                        masker.mask("<message>login with " + encoded + " failed</message>"), encoded);
            }
            // A reference outside the secret stays as it was, and so does an ampersand that starts none.
            assertEquals("a &amp; b &unknown; &#xZZ; & [redacted:db] &#1114112;",
                    masker.mask("a &amp; b &unknown; &#xZZ; & " + escaped(SECRET, false, "'", false)
                            + " &#1114112;"));
            // Non-ASCII digits are no digits in a reference.
            assertEquals("&#\u0663\u0669;", masker.mask("&#\u0663\u0669;"));
            try (SecretMasker astral = new SecretMasker(Map.of("db",
                    new StaticSecretProvider("key\uD83D\uDD11decoy-4711")))) {
                assertEquals("k=[redacted:db]", astral.mask("k=key&#128273;decoy-4711"));
                assertEquals("k=[redacted:db]", astral.mask("k=key&#x1F511;decoy-4711"));
            }
            String ordinary = "fish &amp; chips &lt;3";
            assertTrue(ordinary == masker.mask(ordinary), "a line without a secret is the line itself");
        }
    }

    @Test
    void randomSecretsThroughXmlFormatter() {
        Random random = new Random(84);
        String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789&<>\"'!#%;=";
        for (int n = 0; n < 200; n++) {
            StringBuilder secret = new StringBuilder();
            int length = 10 + random.nextInt(20);
            for (int i = 0; i < length; i++) {
                secret.append(alphabet.charAt(random.nextInt(alphabet.length())));
            }
            String key = secret.toString();
            try (SecretMasker masker = new SecretMasker(Map.of("api", new StaticSecretProvider(key)))) {
                SecretMasker.install(masker);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                StreamHandler handler = new StreamHandler(out, new RedactingFormatter(new XMLFormatter()));
                LogRecord record = new LogRecord(Level.WARNING, "calling with key {0}");
                record.setParameters(new Object[] {key});
                record.setThrown(new IllegalStateException("key " + key + " refused"));
                handler.publish(record);
                handler.flush();
                String written = out.toString(StandardCharsets.UTF_8);
                String xml = key.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
                assertFalse(written.contains(key) || written.contains(xml), key + "\n" + written);
                assertTrue(written.contains("calling with key [redacted:api]"), key + "\n" + written);
                assertTrue(written.contains("key [redacted:api] refused"), key + "\n" + written);
            } finally {
                SecretMasker.install(null);
            }
        }
    }
}
