package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.junit.jupiter.api.Test;

/**
 * What SecretFetch reads as a response, held to the letter: a chunk whose data
 * is longer or shorter than its size, a transfer coding other than chunked,
 * and a head sent a byte at a time. The bodies are public filler.
 */
class SecretFetchStrictnessTest {

    private static SecretFetch.Source pieces(byte[] answer, int piece) {
        ByteBuffer remaining = ByteBuffer.wrap(answer);
        return into -> {
            if (!remaining.hasRemaining()) {
                return -1;
            }
            int n = Math.min(Math.min(piece, into.remaining()), remaining.remaining());
            into.put(remaining.slice(remaining.position(), n));
            remaining.position(remaining.position() + n);
            return n;
        };
    }

    private static String read(String response, int piece) throws IOException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment body = arena.allocate(1024);
            SecretFetch.Response answer = SecretFetch.readResponse(
                    pieces(response.getBytes(StandardCharsets.ISO_8859_1), piece), body);
            return new String(body.asSlice(0, answer.bodyLength()).toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.ISO_8859_1);
        }
    }

    private static String refusal(String response) {
        return assertThrows(IOException.class, () -> read(response, 7)).getMessage();
    }

    private static final String CHUNKED = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";

    @Test
    void wellFormedChunksAreReadWhateverThePieces() throws IOException {
        String response = CHUNKED + "4\r\nabcd\r\n3;ext=1\r\nefg\r\n0\r\n\r\n";
        for (int piece : new int[] {1, 2, 3, 7, 64, 4096}) {
            assertEquals("abcdefg", read(response, piece), "pieces of " + piece);
        }
        assertEquals("ab", read("HTTP/1.1 200 OK\r\nTransfer-Encoding:  Chunked \r\n\r\n2\r\nab\r\n0\r\n\r\n", 5),
                "the coding's name in any case, with blanks around it");
    }

    @Test
    void aChunkLongerOrShorterThanItsSizeIsRefused() {
        assertEquals("a chunk is not as long as its size says",
                refusal(CHUNKED + "3\r\nabcd\r\n0\r\n\r\n"), "four bytes where three were said");
        assertEquals("a chunk is not as long as its size says",
                refusal(CHUNKED + "5\r\nabcd\r\n0\r\n\r\n"), "four bytes where five were said");
        assertEquals("a chunk is not as long as its size says",
                refusal(CHUNKED + "4\r\nabcdX\n0\r\n\r\n"), "no CRLF after the data");
        assertEquals("a chunk is not as long as its size says",
                refusal(CHUNKED + "4\r\nabcd"), "the data and then the end of the connection");
    }

    @Test
    void anotherTransferCodingIsRefusedNotReadAsPlain() {
        for (String coding : new String[] {"gzip", "gzip, chunked", "identity", "chunked, gzip"}) {
            String response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: " + coding + "\r\nContent-Length: 2\r\n\r\nab";
            assertEquals("the response has Transfer-Encoding " + coding + " - only chunked is read",
                    refusal(response), coding);
        }
    }

    @Test
    void aHeadSentAByteAtATimeIsReadInLinearTime() {
        // A quarter mebibyte of header bytes with no end, one byte per read:
        // refused as no response, and quickly - not after a scan of the whole
        // buffer for every byte.
        StringBuilder head = new StringBuilder("HTTP/1.1 200 OK\r\n");
        while (head.length() < SecretFetch.MAX_RESPONSE - 300) {
            head.append("X-Filler: ").append("f".repeat(80)).append("\r\n");
        }
        String endless = head.toString();
        IOException e = assertTimeoutPreemptively(Duration.ofSeconds(15),
                () -> assertThrows(IOException.class, () -> read(endless, 1)));
        assertEquals("the secret manager sent no complete HTTP response", e.getMessage());
        String complete = head + "Content-Length: 3\r\n\r\nabc";
        assertEquals("abc", assertTimeoutPreemptively(Duration.ofSeconds(15), () -> read(complete, 1)),
                "and the same head, ended, gives its body");
    }
}
