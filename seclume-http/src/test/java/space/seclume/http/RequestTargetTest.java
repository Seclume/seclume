package space.seclume.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.secret.SecretScope;

/**
 * A credential goes into a header, never into the request target. The client
 * holds the placeholder - on the heap, so a heap dump gives it away - and an
 * application puts what its users typed into paths and queries: a search, an
 * id. Written there, the secret would have gone to the server's access log
 * and back in every response that echoes the request ("no index named ...").
 * HTTP/1.1's request line and HTTP/2's pseudo-headers stay as they are.
 */
class RequestTargetTest {

    private static final String SECRET = "sk-live-0123456789abcdef";

    @TempDir
    Path dir;

    private String placeholder;

    @BeforeEach
    void aPlaceholder() throws IOException {
        Path file = dir.resolve("token");
        Files.writeString(file, SECRET);
        placeholder = SeclumeSslSocketFactory.placeholder("provider=file&path=" + file);
    }

    private static String rewritten(String head) throws IOException {
        try (SecretScope out = HttpFraming.rewrite(head.getBytes(StandardCharsets.ISO_8859_1),
                "api.example.com:443")) {
            return new String(out.segment().asSlice(0, out.length()).toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.ISO_8859_1);
        }
    }

    private static int count(String text, String part) {
        int count = 0;
        for (int at = text.indexOf(part); at >= 0; at = text.indexOf(part, at + 1)) {
            count++;
        }
        return count;
    }

    // ---- HTTP/1.1 -------------------------------------------------------------------

    @Test
    void theHeaderGetsTheSecretAndThePathKeepsThePlaceholder() throws IOException {
        String head = "GET /search?q=" + placeholder + " HTTP/1.1\r\nHost: api.example.com\r\n"
                + "Authorization: Bearer " + placeholder + "\r\n\r\n";
        String sent = rewritten(head);
        assertEquals("GET /search?q=" + placeholder + " HTTP/1.1\r\nHost: api.example.com\r\n"
                + "Authorization: Bearer " + SECRET + "\r\n\r\n", sent);
        assertEquals(1, count(sent, SECRET));
    }

    @Test
    void aPlaceholderOnlyInThePathIsLeftThere() throws IOException {
        String head = "GET /orders/" + placeholder + " HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        assertEquals(head, rewritten(head));
    }

    @Test
    void anApiKeyHeaderOfItsOwnStillGetsIt() throws IOException {
        String head = "POST /v1/charges HTTP/1.1\r\nX-Api-Key: " + placeholder
                + "\r\nContent-Length: 0\r\n\r\n";
        assertEquals("POST /v1/charges HTTP/1.1\r\nX-Api-Key: " + SECRET
                + "\r\nContent-Length: 0\r\n\r\n", rewritten(head));
    }

    @Test
    void aHeadOfOnlyARequestLineIsWhole() throws IOException {
        String head = "GET /" + placeholder + " HTTP/1.1\r\n";
        assertEquals(head, rewritten(head));
        assertEquals("GET / HTTP/1.1", rewritten("GET / HTTP/1.1"));
    }

    // ---- HTTP/2 -----------------------------------------------------------------------

    private static final byte[] PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            .getBytes(StandardCharsets.US_ASCII);

    /** A literal field without indexing, new name, no Huffman (RFC 7541 6.2.2). */
    private static void literal(ByteArrayOutputStream out, String name, String value) {
        out.write(0x00);
        out.write(name.length());
        out.writeBytes(name.getBytes(StandardCharsets.US_ASCII));
        out.write(value.length());
        out.writeBytes(value.getBytes(StandardCharsets.US_ASCII));
    }

    private String sentOverHttp2(String path, String authorization) throws IOException {
        ByteArrayOutputStream block = new ByteArrayOutputStream();
        literal(block, ":method", "GET");
        literal(block, ":scheme", "https");
        literal(block, ":authority", "api.example.com");
        literal(block, ":path", path);
        literal(block, "authorization", authorization);
        byte[] fields = block.toByteArray();
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        wire.writeBytes(PREFACE);
        wire.write(fields.length >>> 16);
        wire.write(fields.length >>> 8);
        wire.write(fields.length);
        wire.write(0x1);                                  // HEADERS
        wire.write(0x5);                                  // END_STREAM | END_HEADERS
        wire.writeBytes(new byte[] {0, 0, 0, 1});         // stream 1
        wire.writeBytes(fields);
        byte[] bytes = wire.toByteArray();

        ByteArrayOutputStream sent = new ByteArrayOutputStream();
        Http2Requests requests = new Http2Requests(buffer -> {
            byte[] piece = new byte[buffer.remaining()];
            buffer.get(piece);
            sent.writeBytes(piece);
        }, "api.example.com:443");
        requests.consume(bytes, 0, bytes.length);
        return sent.toString(StandardCharsets.ISO_8859_1);
    }

    @Test
    void http2PathKeepsThePlaceholderAndTheHeaderGetsTheSecret() throws IOException {
        String sent = sentOverHttp2("/search?q=" + placeholder, "Bearer " + placeholder);
        assertEquals(1, count(sent, SECRET), "the secret once, in authorization");
        assertEquals(1, count(sent, placeholder), "the placeholder once, in :path");
        assertTrue(sent.indexOf("/search?q=" + placeholder) >= 0, sent);
        assertTrue(sent.indexOf("Bearer " + SECRET) >= 0, sent);
    }

    @Test
    void http2WithThePlaceholderOnlyInThePathSendsNoSecret() throws IOException {
        String sent = sentOverHttp2("/orders/" + placeholder, "Bearer static-token");
        assertEquals(0, count(sent, SECRET));
        assertEquals(1, count(sent, placeholder));
    }
}
