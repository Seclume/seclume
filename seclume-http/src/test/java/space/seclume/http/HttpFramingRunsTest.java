package space.seclume.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * A request's body goes through in runs: a chunk's size line, its data, the
 * CRLF after it and a trailer line are each one piece - one TLS record on the
 * wire - and not one for each of their bytes. And a long head costs what its
 * bytes cost, not their square.
 */
class HttpFramingRunsTest {

    /** The pieces a request goes out in: each head, and each run the framing passes through. */
    private static List<String> pieces(String request, int writeSize) throws IOException {
        byte[] bytes = request.getBytes(StandardCharsets.ISO_8859_1);
        HttpFraming framing = new HttpFraming();
        List<String> pieces = new ArrayList<>();
        for (int start = 0; start < bytes.length; start += writeSize) {
            int end = Math.min(bytes.length, start + writeSize);
            int at = start;
            while (at < end) {
                if (framing.inHead()) {
                    byte[] head = framing.headByte(bytes[at++]);
                    if (head != null) {
                        pieces.add(new String(head, StandardCharsets.ISO_8859_1));
                    }
                } else {
                    int n = framing.passThrough(ByteBuffer.wrap(bytes, at, end - at),
                            Integer.MAX_VALUE);
                    assertTrue(n >= 1 && n <= end - at, "a run of " + n);
                    pieces.add(new String(bytes, at, n, StandardCharsets.ISO_8859_1));
                    at += n;
                }
            }
        }
        assertTrue(framing.inHead(), "the request is over");
        assertEquals(0, framing.held());
        return pieces;
    }

    private static final String HEAD = "PUT /upload HTTP/1.1\r\nHost: api.example\r\n"
            + "Transfer-Encoding: chunked\r\n\r\n";
    private static final String CHUNKED = HEAD
            + "1a;ext=1\r\n" + "abcdefghijklmnopqrstuvwxyz" + "\r\n"
            + "5\r\nhello\r\n"
            + "0\r\n"
            + "X-Checksum: 1234\r\n"
            + "\r\n";

    @Test
    void aChunkedBodyGoesThroughInItsParts() throws IOException {
        assertEquals(List.of(HEAD,
                "1a;ext=1\r\n", "abcdefghijklmnopqrstuvwxyz", "\r\n",
                "5\r\n", "hello", "\r\n",
                "0\r\n", "X-Checksum: 1234\r\n", "\r\n"), pieces(CHUNKED, Integer.MAX_VALUE));
    }

    @Test
    void howeverTheWritesFallTheBytesAreTheSame() throws IOException {
        String two = CHUNKED + "GET /next HTTP/1.1\r\nHost: api.example\r\n\r\n";
        for (int writeSize : new int[] {1, 2, 3, 7, 16, 61, 1000}) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (String piece : pieces(two, writeSize)) {
                out.writeBytes(piece.getBytes(StandardCharsets.ISO_8859_1));
            }
            assertArrayEquals(two.getBytes(StandardCharsets.ISO_8859_1), out.toByteArray(),
                    "written " + writeSize + " bytes at a time");
        }
    }

    @Test
    void aPassThroughTakesNoMoreThanItIsAllowed() throws IOException {
        byte[] bytes = CHUNKED.getBytes(StandardCharsets.ISO_8859_1);
        HttpFraming framing = new HttpFraming();
        int at = 0;
        while (framing.inHead()) {
            framing.headByte(bytes[at++]);
        }
        while (at < bytes.length) {
            int n = framing.passThrough(ByteBuffer.wrap(bytes, at, bytes.length - at), 3);
            assertTrue(n >= 1 && n <= 3, "a run of " + n + " where 3 were allowed");
            at += n;
        }
        assertTrue(framing.inHead());
    }

    /**
     * Sixty kilobytes of head, a thousand times: a second or two of work
     * when every byte is looked at once. With a copy of the head so far for
     * each byte it was 1.8 GB copied per head - minutes.
     */
    @Test
    void aLongHeadIsNotCopiedForEachOfItsBytes() throws IOException {
        StringBuilder head = new StringBuilder("GET /things HTTP/1.1\r\nHost: api.example\r\n");
        while (head.length() < 60_000) {
            head.append("X-Field-").append(head.length()).append(": a value of some length\r\n");
        }
        byte[] bytes = head.append("\r\n").toString().getBytes(StandardCharsets.ISO_8859_1);
        HttpFraming framing = new HttpFraming();
        long start = System.nanoTime();
        for (int round = 0; round < 1000; round++) {
            byte[] complete = null;
            for (byte b : bytes) {
                complete = framing.headByte(b);
            }
            assertEquals(bytes.length, complete.length);
        }
        long millis = (System.nanoTime() - start) / 1_000_000;
        assertTrue(millis < 30_000, "1000 heads of " + bytes.length + " bytes took " + millis
                + " ms");
    }
}
