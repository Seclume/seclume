package space.seclume.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;

/**
 * The framing that decides which bytes are a request head - where a secret
 * may be written - and which are a body, which goes through untouched,
 * against a model of HTTP/1.1's message framing (RFC 9112, section 6).
 *
 * <p>Random sequences of requests on one connection, written the ways an
 * HTTP client may write them: {@code Content-Length} and
 * {@code Transfer-Encoding} in any case and with or without whitespace
 * around the value, codings before {@code chunked}, chunk extensions,
 * trailers, bodies that hold whole fake request heads with placeholders in
 * them. The framing has to find exactly the heads the model finds, in the
 * same order, whatever the sizes of the writes. One it found in a body would
 * have a secret written into the body - into a document a server stores.
 *
 * <p>And what cannot be framed - a coding after {@code chunked}, two lengths
 * that differ, a folded header line - is refused, not guessed.
 *
 * <p>Seeded: a failure names its round and replays with
 * {@code -Dseclume.framing.seed=}; {@code -Dseclume.framing.rounds=} runs longer.
 */
class HttpFramingModelTest {

    private static final int ROUNDS = Integer.getInteger("seclume.framing.rounds", 3_000);
    private static final long SEED = Long.getLong("seclume.framing.seed", 0x48717046L);
    private static final String FAKE_HEAD = "POST /x HTTP/1.1\r\nAuthorization: Bearer "
            + CredentialPlaceholders.PREFIX + "token\r\n\r\n";

    /** A request: its head, and its body as it goes on the wire. */
    private record Request(byte[] head, byte[] wire) {
    }

    @Test
    void theFramingFindsTheHeadsTheModelFinds() {
        Random random = new Random(SEED);
        for (int round = 0; round < ROUNDS; round++) {
            List<Request> requests = new ArrayList<>();
            int count = 1 + random.nextInt(4);
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            for (int i = 0; i < count; i++) {
                Request request = request(random);
                requests.add(request);
                stream.writeBytes(request.head());
                stream.writeBytes(request.wire());
            }
            byte[] bytes = stream.toByteArray();
            try {
                List<byte[]> heads = frame(bytes, random);
                assertEquals(requests.size(), heads.size(), "heads found");
                for (int i = 0; i < heads.size(); i++) {
                    assertArrayEquals(requests.get(i).head(), heads.get(i), "head " + i);
                }
            } catch (AssertionError | IOException | RuntimeException e) {
                throw new AssertionError("round " + round + " of seed " + SEED + ": " + e
                        + "\n" + printable(bytes), e);
            }
        }
    }

    @Test
    void whatCannotBeFramedIsRefused() {
        for (String head : List.of(
                // A coding after chunked: the body has no end a reader can find.
                "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
                "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\n\r\n",
                // Two lengths that differ: whichever the framing took, the server may take the other.
                "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 50\r\n\r\n",
                // A folded line: the next line belongs to the header before it.
                "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding:\r\n chunked\r\n\r\n",
                "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: x5\r\n\r\n",
                "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: +5\r\n\r\n",
                "POST / HTTP/1.1\r\nHost: h\r\nContent-Length : 5\r\n\r\n",
                "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n")) {
            assertThrows(IOException.class, () -> frame(head.getBytes(StandardCharsets.US_ASCII),
                    new Random(1)), head);
        }
    }

    /**
     * Found by the first run of the model, 08.11.2026: only
     * {@code Transfer-Encoding: chunked} with one space was read as chunked.
     * With none, a tab or {@code gzip, chunked} the body was taken for no
     * body - and the fake head in it for the next request's, with the secret
     * written into it.
     */
    @Test
    void aChunkedBodyIsNeverTakenForAHeadWhateverTheSpelling() throws IOException {
        byte[] body = chunked(FAKE_HEAD.getBytes(StandardCharsets.US_ASCII), new Random(7));
        for (String encoding : List.of("Transfer-Encoding:chunked", "Transfer-Encoding:\tchunked",
                "Transfer-Encoding: gzip, chunked", "transfer-encoding:  Chunked")) {
            byte[] head = ("POST /docs HTTP/1.1\r\nHost: h\r\n" + encoding + "\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII);
            byte[] stream = new byte[head.length + body.length];
            System.arraycopy(head, 0, stream, 0, head.length);
            System.arraycopy(body, 0, stream, head.length, body.length);
            List<byte[]> heads = frame(stream, new Random(3));
            assertEquals(1, heads.size(), encoding + ": the body was taken for a head");
            assertArrayEquals(head, heads.get(0));
        }
    }

    /** The heads {@link HttpFraming} finds in {@code bytes}, fed in writes of random sizes. */
    private static List<byte[]> frame(byte[] bytes, Random random) throws IOException {
        HttpFraming framing = new HttpFraming();
        List<byte[]> heads = new ArrayList<>();
        int at = 0;
        while (at < bytes.length) {
            int end = Math.min(bytes.length, at + 1 + random.nextInt(97));
            while (at < end) {
                if (framing.inHead()) {
                    byte[] head = framing.headByte(bytes[at++]);
                    if (head != null) {
                        heads.add(head);
                    }
                } else {
                    at += framing.passThrough(ByteBuffer.wrap(bytes, at, end - at), Integer.MAX_VALUE);
                }
            }
        }
        if (!framing.inHead() || framing.held() != 0) {
            throw new AssertionError("the stream ended inside a "
                    + (framing.inHead() ? "head" : "body"));
        }
        return heads;
    }

    private static Request request(Random random) {
        StringBuilder head = new StringBuilder(random.nextBoolean() ? "POST" : "PUT")
                .append(" /items/").append(random.nextInt(1000)).append(" HTTP/1.1\r\n")
                .append("Host: api.example\r\n");
        if (random.nextInt(3) == 0) {
            head.append("Authorization: Bearer ").append(CredentialPlaceholders.PREFIX)
                    .append("api\r\n");
        }
        byte[] body = body(random);
        byte[] wire;
        switch (random.nextInt(4)) {
            case 0 -> {
                wire = new byte[0];                      // no body, and no framing header
                if (random.nextBoolean()) {
                    head.append(name(random, "Content-Length")).append(':').append(ows(random))
                            .append('0').append(ows(random)).append("\r\n");
                }
            }
            case 1 -> {
                wire = body;
                head.append(name(random, "Content-Length")).append(':').append(ows(random))
                        .append(body.length).append(ows(random)).append("\r\n");
            }
            default -> {
                wire = chunked(body, random);
                String codings = switch (random.nextInt(4)) {
                    case 0 -> "gzip, chunked";
                    case 1 -> "gzip,chunked";
                    default -> random.nextBoolean() ? "chunked" : "Chunked";
                };
                head.append(name(random, "Transfer-Encoding")).append(':').append(ows(random))
                        .append(codings).append(ows(random)).append("\r\n");
                if (random.nextInt(4) == 0) {
                    // Both: Transfer-Encoding overrides the length (RFC 9112, 6.3).
                    head.append("Content-Length: ").append(body.length).append("\r\n");
                }
            }
        }
        head.append("Accept: */*\r\n\r\n");
        return new Request(head.toString().getBytes(StandardCharsets.ISO_8859_1), wire);
    }

    /** A header name in some case. */
    private static String name(Random random, String name) {
        return switch (random.nextInt(3)) {
            case 0 -> name.toLowerCase(java.util.Locale.ROOT);
            case 1 -> name.toUpperCase(java.util.Locale.ROOT);
            default -> name;
        };
    }

    /** Optional whitespace, as RFC 9110 allows it around a field value. */
    private static String ows(Random random) {
        return switch (random.nextInt(4)) {
            case 0 -> "";
            case 1 -> "\t";
            case 2 -> "  ";
            default -> " ";
        };
    }

    /** Random bytes with whole fake heads and blank lines in them. */
    private static byte[] body(Random random) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int parts = random.nextInt(4);
        for (int i = 0; i < parts; i++) {
            switch (random.nextInt(3)) {
                case 0 -> out.writeBytes(FAKE_HEAD.getBytes(StandardCharsets.US_ASCII));
                case 1 -> out.writeBytes("\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                default -> {
                    byte[] noise = new byte[random.nextInt(300)];
                    random.nextBytes(noise);
                    out.writeBytes(noise);
                }
            }
        }
        return out.toByteArray();
    }

    /** {@code body} in chunks, with extensions and trailers now and then. */
    private static byte[] chunked(byte[] body, Random random) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int at = 0;
        while (at < body.length) {
            int size = Math.min(body.length - at, 1 + random.nextInt(200));
            String line = Integer.toHexString(size);
            if (random.nextBoolean()) {
                line = line.toUpperCase(java.util.Locale.ROOT);
            }
            if (random.nextInt(4) == 0) {
                line += ";name=value";
            }
            out.writeBytes((line + "\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write(body, at, size);
            out.writeBytes("\r\n".getBytes(StandardCharsets.US_ASCII));
            at += size;
        }
        out.writeBytes("0\r\n".getBytes(StandardCharsets.US_ASCII));
        if (random.nextInt(3) == 0) {
            out.writeBytes("Trailer-Field: x\r\n".getBytes(StandardCharsets.US_ASCII));
        }
        out.writeBytes("\r\n".getBytes(StandardCharsets.US_ASCII));
        return out.toByteArray();
    }

    private static String printable(byte[] bytes) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, 2000); i++) {
            int b = bytes[i] & 0xff;
            out.append(b >= 0x20 && b < 0x7f ? String.valueOf((char) b)
                    : b == '\r' ? "\\r" : b == '\n' ? "\\n\n" : String.format("\\x%02x", b));
        }
        return out.toString();
    }
}
