package space.seclume.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.secret.FileSecretProvider;
import space.seclume.secret.SecretScope;

/**
 * A placeholder becomes the secret only in a credential header. It used to be
 * replaced in every header line: typed by a user into a query, a cookie or
 * X-Opaque-Id - anything the application fills from what it is given - it
 * went out as the secret, to wherever the request went.
 */
class HttpFramingCredentialHeaderTest {

    private static final String SERVER = "api.example.com:443";
    private static final String SECRET = "sk_live_DECOY_credential_header";

    @TempDir
    Path dir;

    private String placeholder() throws IOException {
        Path file = dir.resolve("token");
        Files.writeString(file, SECRET);
        return CredentialPlaceholders.register(new FileSecretProvider(file, 1 << 12));
    }

    private static String rewritten(String head) throws IOException {
        try (SecretScope out = HttpFraming.rewrite(head.getBytes(StandardCharsets.ISO_8859_1), SERVER)) {
            return new String(out.segment().asSlice(0, out.length()).toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.ISO_8859_1);
        }
    }

    @Test
    void aPlaceholderInXOpaqueIdStaysAPlaceholder() throws IOException {
        String p = placeholder();
        String out = rewritten("GET /x HTTP/1.1\r\nHost: api.example.com\r\nX-Opaque-Id: " + p
                + "\r\nAuthorization-Extra: " + p + "\r\n\r\n");
        assertFalse(out.contains(SECRET), out);
        assertTrue(out.contains("X-Opaque-Id: " + p));
    }

    @Test
    void aPlaceholderInTheQueryOrACookieStaysAPlaceholder() throws IOException {
        String p = placeholder();
        String out = rewritten("GET /search?q=" + p + " HTTP/1.1\r\nHost: api.example.com\r\n"
                + "Cookie: session=" + p + "\r\n\r\n");
        assertFalse(out.contains(SECRET), out);
    }

    @Test
    void credentialHeadersGetTheSecretInAnyCase() throws IOException {
        String p = placeholder();
        for (String name : new String[] {"Authorization", "authorization", "PROXY-AUTHORIZATION",
                "X-Api-Key", "api-key", "X-Auth-Token"}) {
            String out = rewritten("GET /x HTTP/1.1\r\nHost: api.example.com\r\n" + name
                    + ": Bearer " + p + "\r\n\r\n");
            assertEquals("GET /x HTTP/1.1\r\nHost: api.example.com\r\n" + name + ": Bearer "
                    + SECRET + "\r\n\r\n", out, name);
        }
    }

    @Test
    void aHeaderNameThatOnlyBeginsLikeOneIsNotOne() throws IOException {
        String p = placeholder();
        String out = rewritten("GET /x HTTP/1.1\r\nHost: api.example.com\r\nAuthorizationNote: "
                + p + "\r\nX-Api-Key-Hint: " + p + "\r\n\r\n");
        assertFalse(out.contains(SECRET), out);
    }
}
