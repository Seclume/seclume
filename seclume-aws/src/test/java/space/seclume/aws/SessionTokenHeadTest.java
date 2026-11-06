package space.seclume.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import space.seclume.secret.SecretScope;

/**
 * The session token goes into the X-Amz-Security-Token header and nowhere
 * else. The SDK holds the token's placeholder on the heap; a heap dump gives
 * it away, and an application that puts a string from its user into a header
 * - S3 object metadata, say - or into the request target could otherwise have
 * had the token written there: signed as the placeholder, refused by AWS, and
 * the token in the canonical request the error sends back.
 */
class SessionTokenHeadTest {

    private static final String PLACEHOLDER = TemporaryCredentials.TOKEN_PREFIX + "0123abcd-7";
    private static final String TOKEN = "IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJH";

    private SecretScope token;
    private Function<String, SecretScope> tokens;

    @BeforeEach
    void aToken() {
        token = SecretScope.allocate(TOKEN.length());
        token.segment().copyFrom(java.lang.foreign.MemorySegment.ofArray(
                TOKEN.getBytes(StandardCharsets.US_ASCII)));
        token.length(TOKEN.length());
        tokens = Map.of(PLACEHOLDER, token)::get;
    }

    @AfterEach
    void wipe() {
        token.close();
    }

    private String sent(String head) throws IOException {
        byte[] bytes = head.getBytes(StandardCharsets.ISO_8859_1);
        String text = head.toLowerCase(Locale.ROOT);
        try (SecretScope rewritten = SessionTokenSocket.withToken(bytes, text, tokens)) {
            if (rewritten == null) {
                return null;
            }
            byte[] out = rewritten.segment().asSlice(0, rewritten.length())
                    .toArray(ValueLayout.JAVA_BYTE);
            return new String(out, StandardCharsets.ISO_8859_1);
        }
    }

    private static String head(String... headers) {
        return "PUT /bucket/key HTTP/1.1\r\nHost: s3.eu-central-1.amazonaws.com\r\n"
                + String.join("\r\n", headers) + "\r\n\r\n";
    }

    @Test
    void theTokenHeaderGetsTheToken() throws IOException {
        assertEquals(head("X-Amz-Security-Token: " + TOKEN, "Content-Length: 0"),
                sent(head("X-Amz-Security-Token: " + PLACEHOLDER, "Content-Length: 0")));
    }

    @Test
    void anyCaseAndWhitespaceAroundTheValue() throws IOException {
        assertEquals(head("x-amz-security-token:\t " + TOKEN + "  "),
                sent(head("x-amz-security-token:\t " + PLACEHOLDER + "  ")));
        assertEquals(head("X-AMZ-SECURITY-TOKEN:" + TOKEN),
                sent(head("X-AMZ-SECURITY-TOKEN:" + PLACEHOLDER)));
    }

    @Test
    void thePlaceholderInAnotherHeaderStaysThePlaceholder() throws IOException {
        // Metadata first, as alphabetical order puts it: the old search took
        // the first occurrence of the prefix, wherever it was.
        String head = head("x-amz-meta-note: " + PLACEHOLDER,
                "X-Amz-Security-Token: " + PLACEHOLDER);
        String sent = sent(head);
        assertEquals(head("x-amz-meta-note: " + PLACEHOLDER, "X-Amz-Security-Token: " + TOKEN),
                sent);
        assertEquals(sent.indexOf(TOKEN), sent.lastIndexOf(TOKEN));
    }

    @Test
    void thePlaceholderInTheRequestTargetStaysThePlaceholder() throws IOException {
        String head = "GET /bucket/" + PLACEHOLDER + "?prefix=" + PLACEHOLDER + " HTTP/1.1\r\n"
                + "Host: s3.amazonaws.com\r\nX-Amz-Security-Token: " + PLACEHOLDER + "\r\n\r\n";
        String sent = sent(head);
        assertEquals(head.replace("X-Amz-Security-Token: " + PLACEHOLDER,
                "X-Amz-Security-Token: " + TOKEN), sent);
    }

    @Test
    void withoutATokenHeaderNothingIsWritten() throws IOException {
        assertNull(sent(head("x-amz-meta-note: " + PLACEHOLDER)));
        assertNull(sent(head("Content-Length: 0")));
        // A header whose name only ends like it is another header.
        assertNull(sent(head("X-Not-Amz-Security-Token: " + PLACEHOLDER)));
    }

    @Test
    void aTokenHeaderWithoutOurPlaceholderIsLeftAlone() throws IOException {
        assertNull(sent(head("X-Amz-Security-Token: someone-elses-real-token")));
        assertNull(sent(head("X-Amz-Security-Token: x" + PLACEHOLDER)));
        assertNull(sent(head("X-Amz-Security-Token: " + TemporaryCredentials.TOKEN_PREFIX)));
    }

    @Test
    void twoTokenHeadersAreRefusedBeforeAnythingIsWritten() {
        IOException refused = assertThrows(IOException.class, () -> sent(head(
                "X-Amz-Security-Token: " + PLACEHOLDER, "x-amz-security-token: " + PLACEHOLDER)));
        assertTrue(refused.getMessage().contains("two X-Amz-Security-Token headers"),
                refused.getMessage());
    }

    @Test
    void aPlaceholderWhoseCredentialsAreGoneIsRefused() {
        String gone = TemporaryCredentials.TOKEN_PREFIX + "ffff-1";
        IOException refused = assertThrows(IOException.class,
                () -> sent(head("X-Amz-Security-Token: " + gone)));
        assertTrue(refused.getMessage().contains("whose credentials are gone"),
                refused.getMessage());
    }
}
