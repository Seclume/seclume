package space.seclume.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.foreign.ValueLayout;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import space.seclume.internal.TlsLayer;
import space.seclume.secret.SecretScope;

/**
 * What the socket hands to TLS for what the HTTP client writes: the same
 * bytes, with the session token in each request's head and nowhere else -
 * however the client's writes fall - and in runs, not a TLS record for every
 * byte of a chunk's framing.
 */
class SessionTokenFramingTest {

    private static final String TOKEN = "IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJH";

    /** What TLS was given, and in how many writes. */
    private static final class Recorded implements TlsLayer {
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private int writes;

        @Override
        public void write(ByteBuffer plain) {
            writes++;
            while (plain.hasRemaining()) {
                bytes.write(plain.get());
            }
        }

        @Override
        public int read(ByteBuffer target) {
            return -1;
        }

        @Override
        public X509Certificate peerCertificate() {
            return null;
        }

        @Override
        public String description() {
            return "recorded";
        }

        @Override
        public boolean movable() {
            return false;
        }

        @Override
        public void replaceTransport(space.seclume.internal.Transport replacement) {
            // none under it
        }

        @Override
        public void discard() {
            // nothing open
        }

        @Override
        public void close() {
            // nothing open
        }

        String text() {
            return bytes.toString(StandardCharsets.ISO_8859_1);
        }
    }

    private SecretScope key;
    private SecretScope token;
    private String placeholder;
    private final Recorded tls = new Recorded();
    private SessionTokenSocket socket;

    @BeforeEach
    void credentials() {
        key = secret("test-secret-key");
        token = secret(TOKEN);
        TemporaryCredentials source = new TemporaryCredentials() {
            @Override
            Fetched fetch() {
                return new Fetched("ASIATEST", Instant.now().plusSeconds(3600), key, token);
            }

            @Override
            String name() {
                return "test";
            }
        };
        placeholder = source.current().placeholder;
        socket = new SessionTokenSocket(new Socket(), "s3.eu-central-1.amazonaws.com", 443, tls);
    }

    @AfterEach
    void wipe() {
        TemporaryCredentials.byPlaceholder(placeholder).close();
    }

    private static SecretScope secret(String text) {
        SecretScope scope = SecretScope.allocate(text.length());
        for (int i = 0; i < text.length(); i++) {
            scope.segment().set(ValueLayout.JAVA_BYTE, i, (byte) text.charAt(i));
        }
        scope.length(text.length());
        return scope;
    }

    private String head(String method, String... more) {
        StringBuilder head = new StringBuilder(method + " /bucket/key HTTP/1.1\r\n"
                + "Host: s3.eu-central-1.amazonaws.com\r\n"
                + "X-Amz-Security-Token: " + placeholder + "\r\n");
        for (String header : more) {
            head.append(header).append("\r\n");
        }
        return head.append("\r\n").toString();
    }

    /** A body that looks like a head of its own, placeholder and all. */
    private String lookalike() {
        return "GET / HTTP/1.1\r\nX-Amz-Security-Token: " + placeholder + "\r\n\r\n";
    }

    private void write(String text) throws IOException {
        socket.getOutputStream().write(text.getBytes(StandardCharsets.ISO_8859_1));
    }

    private String chunked() {
        return chunked("Transfer-Encoding: chunked");
    }

    /** A chunked request whose head says so with {@code codings}, its body a lookalike head. */
    private String chunked(String... codings) {
        String body = lookalike();
        return head("PUT", codings)
                + Integer.toHexString(body.length()) + "\r\n" + body + "\r\n"
                + "5;name=value\r\nhello\r\n"
                + "0\r\n"
                + "x-amz-security-token: " + placeholder + "\r\n"
                + "\r\n";
    }

    @Test
    void aBodyOfAKnownLengthGoesThroughAsItIs() throws IOException {
        String body = lookalike();
        String request = head("PUT", "Content-Length: " + body.length()) + body;
        write(request + head("GET"));
        assertEquals((request + head("GET")).replaceFirst(placeholder, TOKEN)
                .replaceAll(placeholder + "(?=\\r\\n\\r\\n$)", TOKEN), tls.text());
        assertEquals(2, count(tls.text(), TOKEN), "one token in each of the two heads");
        assertEquals(1, count(tls.text(), placeholder), "and the body's placeholder as it was");
        assertEquals(3, tls.writes, "a head, its body, the next head");
    }

    @Test
    void aChunkedBodyAndItsTrailerGoThroughAsTheyAre() throws IOException {
        String request = chunked();
        write(request + head("GET"));
        String sent = tls.text();
        assertEquals(request.length() + head("GET").length()
                + 2 * (TOKEN.length() - placeholder.length()), sent.length());
        assertEquals(2, count(sent, TOKEN), "one token in each of the two heads");
        assertEquals(2, count(sent, placeholder), "the chunk's and the trailer's stay");
        assertTrue(sent.endsWith(head("GET").replace(placeholder, TOKEN)), sent);
    }

    @Test
    void aChunksFramingIsNotARecordForEachByte() throws IOException {
        write(chunked());
        // head; size, data, CRLF; size, data, CRLF; last chunk; trailer; blank line
        assertEquals(10, tls.writes);
    }

    @Test
    void writtenAByteAtATimeItIsTheSame() throws IOException {
        String requests = chunked() + head("PUT", "Content-Length: 5") + "hello" + head("GET");
        write(requests);
        String whole = tls.text();
        Recorded second = new Recorded();
        try (SessionTokenSocket other = new SessionTokenSocket(new Socket(), "host", 443, second)) {
            OutputStream out = other.getOutputStream();
            for (byte b : requests.getBytes(StandardCharsets.ISO_8859_1)) {
                out.write(b);
            }
            assertEquals(whole, second.text());
        }
        assertEquals(3, count(whole, TOKEN));
    }

    @Test
    void aHeadSplitInsideItsBlankLineIsStillOneHead() throws IOException {
        String head = head("GET");
        write(head.substring(0, head.length() - 2));
        assertEquals(0, tls.writes, "nothing goes before the head is whole");
        write("\r\n");
        assertEquals(head.replace(placeholder, TOKEN), tls.text());
        assertEquals(1, tls.writes);
    }

    @Test
    void aLengthThatIsNoLengthIsRefused() {
        assertThrows(IOException.class,
                () -> write(head("PUT", "Transfer-Encoding: chunked") + "-5\r\nhello"));
        assertThrows(IOException.class,
                () -> write(head("PUT", "Transfer-Encoding: chunked") + "five\r\nhello"));
    }

    /**
     * Review round 4: only {@code transfer-encoding: chunked} with one space
     * was recognised. Written any other way RFC 9112 allows - no space, a
     * tab, a coding before it, two header lines - the chunked body was taken
     * for no body, its chunks for the next head, and the session token was
     * written into the lookalike head inside the body: into the object S3
     * stores. The same was fixed in seclume-http's framing in round 3 (#273).
     */
    @Test
    void aChunkedBodyIsFollowedHoweverItsCodingIsWritten() throws IOException {
        for (String[] codings : new String[][] {
                {"Transfer-Encoding:chunked"},
                {"Transfer-Encoding:\tchunked"},
                {"transfer-encoding:   chunked   "},
                {"TRANSFER-ENCODING: CHUNKED"},
                {"Transfer-Encoding: gzip, chunked"},
                {"Transfer-Encoding: gzip", "Transfer-Encoding: chunked"},
                {"Content-Length: 10", "Transfer-Encoding:chunked"}}) {
            Recorded sent = new Recorded();
            try (SessionTokenSocket other = new SessionTokenSocket(new Socket(),
                    "s3.eu-central-1.amazonaws.com", 443, sent)) {
                String request = chunked(codings);
                other.getOutputStream().write((request + head("GET"))
                        .getBytes(StandardCharsets.ISO_8859_1));
                String text = sent.text();
                String which = String.join(" | ", codings);
                assertEquals(2, count(text, TOKEN), which + ": one token in each of the two heads,"
                        + " none in the body\n" + text);
                assertEquals(2, count(text, placeholder), which + ": the chunk's and the "
                        + "trailer's placeholder stay as they were");
                assertTrue(text.endsWith(head("GET").replace(placeholder, TOKEN)), which);
            }
        }
    }

    /** What a server could read another way than this socket is refused, before a byte goes. */
    @Test
    void whatCannotBeFramedIsRefused() throws IOException {
        for (String[] headers : new String[][] {
                {"Transfer-Encoding: chunked, gzip"},
                {"Transfer-Encoding: gzip"},
                {"Transfer-Encoding: chunked", "Transfer-Encoding: chunked"},
                {"Content-Length: 5", "Content-Length: 6"},
                {"Content-Length: +5"},
                {"Content-Length: 5, 5"},
                {"Content-Length : 5"},
                {"X-Amz-Meta-Note: a", " folded"}}) {
            Recorded sent = new Recorded();
            try (SessionTokenSocket other = new SessionTokenSocket(new Socket(),
                    "s3.eu-central-1.amazonaws.com", 443, sent)) {
                byte[] request = (head("PUT", headers) + "hello")
                        .getBytes(StandardCharsets.ISO_8859_1);
                assertThrows(IOException.class, () -> other.getOutputStream().write(request),
                        String.join(" | ", headers));
                assertEquals(0, sent.writes, String.join(" | ", headers) + ": nothing sent");
            }
        }
        // Two lengths that agree are one length.
        String body = lookalike();
        String request = head("PUT", "Content-Length: " + body.length(),
                "Content-Length: " + body.length()) + body;
        write(request + head("GET"));
        assertEquals(2, count(tls.text(), TOKEN));
    }

    @Test
    void aHeadWithoutEndIsNotHeldForever() {
        byte[] line = ("X-Amz-Meta-Filler: " + "a".repeat(1000) + "\r\n")
                .getBytes(StandardCharsets.ISO_8859_1);
        assertThrows(IOException.class, () -> {
            OutputStream out = socket.getOutputStream();
            out.write(("PUT /bucket/key HTTP/1.1\r\n").getBytes(StandardCharsets.ISO_8859_1));
            for (int i = 0; i <= SessionTokenSocket.MAX_HEAD / line.length; i++) {
                out.write(line);
            }
        });
        assertEquals(0, tls.writes);
    }

    private static int count(String text, String part) {
        int count = 0;
        for (int at = text.indexOf(part); at >= 0; at = text.indexOf(part, at + 1)) {
            count++;
        }
        return count;
    }
}
