package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;

import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * The HTTP answer of a secret manager - Vault, AWS, Azure, GCP, a metadata
 * service - as the parser takes it, from bytes nobody vouches for: whatever
 * arrives, it returns a status and a body inside the caller's segment, or
 * throws an {@link IOException}. Nothing is written outside the body, and the
 * reads come in pieces of any size, as a socket hands them out.
 */
class SecretFetchFuzzTest {

    private static final int BODY = 4096;
    private static final byte GUARD = 0x5a;
    /** What lengths, chunk sizes and header lines are made of - the mutator's favourites. */
    private static final String HTTP_BYTES = "0123456789abcdefABCDEF\r\n: ;-";
    private static final int ROUNDS =Integer.getInteger("seclume.fetch.fuzz.rounds", 20_000);

    private static final List<byte[]> SEEDS = List.of(
            bytes("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 26\r\n\r\n"
                    + "{\"data\":{\"password\":\"pw\"}}"),
            bytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                    + "a\r\n{\"token\":\"\r\n7\r\nabc\"}  \r\n0\r\n\r\n"),
            bytes("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=/var/opt/azcmagent/"
                    + "tokens/x.key\r\nContent-Length: 2\r\n\r\n{}"),
            bytes("HTTP/1.0 404 Not Found\r\nConnection: close\r\n\r\nnot here"));

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.ISO_8859_1);
    }

    /** A socket that hands out the answer in pieces of {@code piece} bytes, then the end. */
    private static SecretFetch.Source pieces(byte[] answer, int piece) {
        ByteBuffer remaining = ByteBuffer.wrap(answer);
        return into -> {
            if (!remaining.hasRemaining()) {
                return -1;
            }
            int n = Math.min(Math.min(piece, into.remaining()), remaining.remaining());
            ByteBuffer slice = remaining.slice(remaining.position(), n);
            into.put(slice);
            remaining.position(remaining.position() + n);
            return n;
        };
    }

    /** One answer through the parser; the body checked to stay where it belongs. */
    private static SecretFetch.Response parse(byte[] answer, int piece) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment storage = arena.allocate(BODY + 2L);
            storage.fill(GUARD);
            MemorySegment body = storage.asSlice(1, BODY);
            SecretFetch.Response response;
            try {
                response = SecretFetch.readResponse(pieces(answer, Math.max(1, piece)), body);
            } catch (IOException refused) {
                response = null;                       // what it may do with garbage
            } catch (RuntimeException | StackOverflowError | OutOfMemoryError other) {
                fail("not an IOException: " + other, other);
                return null;
            }
            assertEquals(GUARD, storage.get(ValueLayout.JAVA_BYTE, 0), "written before the body");
            assertEquals(GUARD, storage.get(ValueLayout.JAVA_BYTE, BODY + 1L),
                    "written after the body");
            if (response != null) {
                assertTrue(response.bodyLength() >= 0 && response.bodyLength() <= BODY,
                        "body length " + response.bodyLength());
                assertTrue(response.status() >= 0 && response.status() <= 999);
            }
            return response;
        }
    }

    @FuzzTest(maxDuration = "60s")
    void anyAnswerIsParsedOrRefused(byte[] answer) {
        if (answer.length == 0 || answer.length > 2 * BODY) {
            return;
        }
        parse(answer, (answer[0] & 0x0f) + 1);
    }

    /** The seeds themselves: what a real answer parses to, in any piece size. */
    @Test
    void realAnswersComeOutWhole() throws Exception {
        try (Arena arena = Arena.ofConfined()) {
            for (byte[] seed : SEEDS) {
                for (int piece : new int[] {1, 3, 17, 4096}) {
                    SecretFetch.readResponse(pieces(seed, piece), arena.allocate(BODY));
                }
            }
        }
        for (int piece : new int[] {1, 3, 17, 4096}) {
            SecretFetch.Response json = parse(SEEDS.get(0), piece);
            assertEquals(200, json.status());
            assertEquals(26, json.bodyLength());
            SecretFetch.Response chunked = parse(SEEDS.get(1), piece);
            assertEquals(200, chunked.status());
            assertEquals(17, chunked.bodyLength(), "two chunks, the terminal one ignored");
            SecretFetch.Response arc = parse(SEEDS.get(2), piece);
            assertEquals(401, arc.status());
            assertEquals("Basic realm=/var/opt/azcmagent/tokens/x.key", arc.challenge().trim());
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment body = arena.allocate(BODY);
            SecretFetch.Response chunked = SecretFetch.readResponse(pieces(SEEDS.get(1), 5), body);
            assertArrayEquals(bytes("{\"token\":\"abc\"}  "),
                    body.asSlice(0, chunked.bodyLength()).toArray(ValueLayout.JAVA_BYTE));
        }
    }

    /** Seeded mutations in every CI run - the coverage-guided search runs nightly. */
    @Test
    void mutatedAnswersAreParsedOrRefused() {
        long seed = Long.getLong("seclume.fetch.fuzz.seed", 0x5EC_F37C);
        Random random = new Random(seed);
        for (int round = 0; round < ROUNDS; round++) {
            byte[] answer = SEEDS.get(round % SEEDS.size()).clone();
            int edits = 1 + random.nextInt(4);
            for (int e = 0; e < edits; e++) {
                int at = random.nextInt(answer.length);
                switch (random.nextInt(4)) {
                    case 0 -> answer[at] = (byte) random.nextInt(256);
                    case 1 -> answer[at] = (byte) HTTP_BYTES.charAt(
                            random.nextInt(HTTP_BYTES.length()));
                    case 2 -> answer = java.util.Arrays.copyOf(answer, at);    // cut short
                    default -> {
                        byte[] longer = java.util.Arrays.copyOf(answer, answer.length + 64);
                        for (int i = answer.length; i < longer.length; i++) {
                            longer[i] = (byte) "fffffff\r\n9".charAt(random.nextInt(10));
                        }
                        answer = longer;
                    }
                }
                if (answer.length == 0) {
                    answer = new byte[] {'H'};
                }
            }
            try {
                parse(answer, 1 + random.nextInt(32));
            } catch (AssertionError broken) {
                throw new AssertionError("seed " + seed + " round " + round + ": "
                        + broken.getMessage(), broken);
            }
        }
    }
}
