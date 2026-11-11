package space.seclume.http;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.secret.FileSecretProvider;
import space.seclume.secret.SecretScope;

/**
 * A head whose secrets are longer than the room the rewrite had: twice the
 * head and 64 KB. A JWT with its claims, a SAML assertion in a header, a few
 * of them in one request - an {@code IndexOutOfBoundsException} came out of
 * the socket's {@code write}, found in the third review round, 11.11.2026.
 * The room is now what the head and its providers' longest secrets need.
 */
class LongSecretsTest {

    private static final String SERVER = "api.example.com:443";

    @TempDir
    Path dir;

    private String placeholder(String name, String secret) throws IOException {
        Path file = dir.resolve(name);
        Files.writeString(file, secret);
        return CredentialPlaceholders.register(new FileSecretProvider(file, 1 << 17));
    }

    private static String rewritten(String head) throws IOException {
        try (SecretScope out = HttpFraming.rewrite(head.getBytes(StandardCharsets.ISO_8859_1), SERVER)) {
            return new String(out.segment().asSlice(0, out.length()).toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.ISO_8859_1);
        }
    }

    @Test
    void secretsLongerThanTheHeadAndSixtyFourKilobytesAreWrittenWhole() throws IOException {
        String token = "t".repeat(40_000);
        String key = "k".repeat(30_000);
        String first = placeholder("token", token);
        String second = placeholder("key", key);
        String head = "GET /x HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer " + first
                + "\r\nX-Api-Key: " + second + "\r\nX-Again: " + second + "\r\n\r\n";
        assertEquals("GET /x HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer " + token
                + "\r\nX-Api-Key: " + key + "\r\nX-Again: " + key + "\r\n\r\n", rewritten(head));
    }

    @Test
    void aLongBasicPasswordIsWrittenWhole() throws IOException {
        String password = "p".repeat(70_000);
        String basic = Base64.getEncoder().encodeToString(("user:" + placeholder("password", password))
                .getBytes(StandardCharsets.US_ASCII));
        String head = "GET /x HTTP/1.1\r\nAuthorization: Basic " + basic + "\r\n\r\n";
        assertEquals("GET /x HTTP/1.1\r\nAuthorization: Basic " + Base64.getEncoder().encodeToString(
                ("user:" + password).getBytes(StandardCharsets.US_ASCII)) + "\r\n\r\n", rewritten(head));
    }
}
