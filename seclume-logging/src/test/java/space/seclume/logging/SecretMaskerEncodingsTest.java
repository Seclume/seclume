package space.seclume.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Random;

import org.junit.jupiter.api.Test;

import space.seclume.secret.SecretProvider;

/**
 * The secret as encoders actually write it, not only in the forms the masker
 * makes of it: most URL builders percent-encode only what their part of a URL
 * does not allow (java.net.URI, Spring, OkHttp - {@code p@ss%20word}), and
 * Gson escapes {@code = ' < > &} as backslash-u sequences by default. Those
 * lines went to the log unmasked; they are read decoded now as well.
 */
class SecretMaskerEncodingsTest {

    private static SecretMasker masker(String secret) {
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        return new SecretMasker(Map.of("db", new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
                return bytes.length;
            }

            @Override
            public int maxSecretLength() {
                return 128;
            }
        }));
    }

    private static String gson(String text) {
        StringBuilder out = new StringBuilder();
        for (char c : text.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '<', '>', '&', '=', '\'' -> out.append(String.format("\\u%04x", (int) c));
                default -> out.append(c);
            }
        }
        return out.toString();
    }

    private static void masked(SecretMasker masker, String encoded) {
        assertEquals("login with [redacted:db] failed", masker.mask("login with " + encoded + " failed"),
                encoded);
    }

    @Test
    void theEncodingsThatWentThrough() throws Exception {
        String secret = "Qz p@ss=w'rd&more";
        try (SecretMasker masker = masker(secret)) {
            masked(masker, new URI("https", "h", "/p", "password=" + secret, null).getRawQuery()
                    .substring("password=".length()));
            masked(masker, "Qz%20p@ss=w'rd&more");                        // Spring's query value
            masked(masker, "qz%20p%40ss%3dw%27rd%26more".replace("qz", "Qz")); // lower-case hex
            masked(masker, gson(secret));
            masked(masker, "Qz p@ss\\u003dw\\u0027rd\\u0026more");
        }
    }

    @Test
    void aRunOfPercentEncodedUtf8IsOneCharacterEach() throws Exception {
        String secret = "Qzäöü€-secret";
        try (SecretMasker masker = masker(secret)) {
            masked(masker, new URI("https", "h", "/" + secret, null).toASCIIString()
                    .substring("https://h/".length()));
        }
    }

    @Test
    void randomSecretsAreMaskedWholeInEveryEncoding() throws Exception {
        Random random = new Random(20261122L);
        String specials = "@!$'()*+,;=:/ ~&<>\"";
        for (int n = 0; n < 500; n++) {
            StringBuilder secret = new StringBuilder("Qz");
            for (int i = 0; i < 10; i++) {
                secret.append(random.nextInt(3) == 0 ? specials.charAt(random.nextInt(specials.length()))
                        : (char) ('a' + random.nextInt(26)));
            }
            String text = secret.toString();
            try (SecretMasker masker = masker(text)) {
                masked(masker, text);
                masked(masker, java.net.URLEncoder.encode(text, StandardCharsets.UTF_8));
                masked(masker, new URI("https", "h", "/p", "q=" + text, null).getRawQuery().substring(2));
                masked(masker, new URI("https", "h", "/" + text, null).getRawPath().substring(1));
                masked(masker, gson(text));
            }
        }
    }
}
