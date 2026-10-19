package space.seclume.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.internal.SeclumeSslEngine;
import space.seclume.secret.SecretScope;

/**
 * The engine's rewriting, step by step as the engine asks for it: what would
 * be encrypted, in order - and the written pieces as the client chose them,
 * down to a byte at a time.
 */
class HttpCredentialRewriterTest {

    private static final String SECRET = "es-api-key-VnVXaGxvbFRScE1nQWJVZ2Q6dWk1";

    /** What the engine would encrypt, and how many records it took. */
    private record Sent(String text, int records, int heldSteps) {
    }

    private static Sent run(byte[] written, int[] pieces) throws IOException {
        HttpCredentialRewriter rewriter = new HttpCredentialRewriter("es:9200");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int records = 0;
        int held = 0;
        int at = 0;
        int piece = 0;
        while (at < written.length) {
            int size = Math.min(pieces[piece++ % pieces.length], written.length - at);
            ByteBuffer src = ByteBuffer.wrap(written, at, size).slice();
            while (src.hasRemaining()) {
                SeclumeSslEngine.Outgoing.Step step = rewriter.next(src);
                if (step.replacement() != null) {
                    try (SecretScope bytes = step.replacement()) {
                        if (bytes.length() == 0) {
                            held++;
                        } else {
                            out.writeBytes(bytes.segment().asSlice(0, bytes.length())
                                    .toArray(ValueLayout.JAVA_BYTE));
                            records++;
                        }
                    }
                    src.position(src.position() + step.replaced());
                } else {
                    byte[] plain = new byte[step.unchanged()];
                    src.get(plain);
                    out.writeBytes(plain);
                    records++;
                }
            }
            at += size;
        }
        return new Sent(out.toString(StandardCharsets.ISO_8859_1), records, held);
    }

    private static String placeholder(Path dir) throws IOException {
        Path file = dir.resolve("es.key");
        Files.writeString(file, SECRET);
        return SeclumeSslSocketFactory.placeholder("provider=file&path="
                + file.toString().replace('\\', '/'));
    }

    private static String request(String authorization, String body) {
        return "POST /orders/_doc HTTP/1.1\r\nHost: es:9200\r\nAuthorization: " + authorization
                + "\r\nContent-Type: application/json\r\nContent-Length: " + body.length()
                + "\r\n\r\n" + body;
    }

    @Test
    void theKeyIsWrittenInAndTheBodyLeftAlone(@TempDir Path dir) throws IOException {
        String placeholder = placeholder(dir);
        String body = "{\"note\":\"" + placeholder + "\"}";
        String written = request("ApiKey " + placeholder, body)
                + request("ApiKey " + placeholder, "{}");
        String expected = request("ApiKey " + SECRET, body) + request("ApiKey " + SECRET, "{}");
        Random random = new Random(7);
        for (int[] pieces : List.of(new int[] {1 << 20}, new int[] {1}, new int[] {2, 3, 5},
                new int[] {17}, new int[] {random.nextInt(40) + 1, random.nextInt(40) + 1})) {
            Sent sent = run(written.getBytes(StandardCharsets.ISO_8859_1), pieces);
            assertEquals(expected, sent.text(), "pieces " + java.util.Arrays.toString(pieces));
            assertTrue(sent.text().contains("{\"note\":\"" + placeholder + "\"}"),
                    "a body was rewritten: the secret would be indexed");
        }
    }

    /** Never a head in parts: a placeholder split across writes cannot go out unreplaced. */
    @Test
    void aHeadSplitAcrossWritesGoesOutWholeAndOnce(@TempDir Path dir) throws IOException {
        String placeholder = placeholder(dir);
        String written = request("Bearer " + placeholder, "");
        Sent sent = run(written.getBytes(StandardCharsets.ISO_8859_1), new int[] {1});
        assertEquals(1, sent.records(), "the head went out in more than one record");
        assertEquals(written.length() - 1, sent.heldSteps());
        assertFalse(sent.text().contains(placeholder));
        assertTrue(sent.text().contains("Authorization: Bearer " + SECRET + "\r\n"));
    }

    @Test
    void basicIsDecodedAndEncodedAgain(@TempDir Path dir) throws IOException {
        String placeholder = placeholder(dir);
        String encoded = Base64.getEncoder().encodeToString(("elastic:" + placeholder)
                .getBytes(StandardCharsets.US_ASCII));
        Sent sent = run(request("Basic " + encoded, "").getBytes(StandardCharsets.ISO_8859_1),
                new int[] {3});
        String expected = Base64.getEncoder().encodeToString(("elastic:" + SECRET)
                .getBytes(StandardCharsets.US_ASCII));
        assertTrue(sent.text().contains("Authorization: Basic " + expected + "\r\n"),
                sent.text());
    }

    @Test
    void chunkedBodiesAreFollowedNotRewritten(@TempDir Path dir) throws IOException {
        String placeholder = placeholder(dir);
        String chunk = "{\"k\":\"" + placeholder + "\"}";
        String written = "POST /_bulk HTTP/1.1\r\nAuthorization: Bearer " + placeholder
                + "\r\nTransfer-Encoding: chunked\r\n\r\n" + Integer.toHexString(chunk.length())
                + "\r\n" + chunk + "\r\n0\r\n\r\n"
                + "GET / HTTP/1.1\r\nAuthorization: Bearer " + placeholder + "\r\n\r\n";
        Sent sent = run(written.getBytes(StandardCharsets.ISO_8859_1), new int[] {4, 1, 9});
        assertEquals(written.replace("Bearer " + placeholder, "Bearer " + SECRET), sent.text());
    }

    @Test
    void aPlaceholderThisProcessDidNotHandOutIsRefused() {
        String forged = CredentialPlaceholders.PREFIX + "000000000000000000000000-1";
        assertThrows(IOException.class, () -> run(request("Bearer " + forged, "")
                .getBytes(StandardCharsets.ISO_8859_1), new int[] {64}));
    }

    @Test
    void aHeadTooLargeForOneRecordIsRefused() {
        StringBuilder big = new StringBuilder("GET / HTTP/1.1\r\n");
        List<String> lines = new ArrayList<>();
        for (int i = 0; i < 400; i++) {
            lines.add("X-Filler-" + i + ": " + "x".repeat(60));
        }
        big.append(String.join("\r\n", lines)).append("\r\n\r\n");
        assertThrows(IOException.class, () -> run(big.toString()
                .getBytes(StandardCharsets.ISO_8859_1), new int[] {1 << 20}));
    }
}
