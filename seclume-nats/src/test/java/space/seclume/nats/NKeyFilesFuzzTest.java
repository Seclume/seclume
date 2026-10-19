package space.seclume.nats;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;

import io.nats.client.NKey;

/**
 * A seed file or a {@code .creds} file is read before anything checks it:
 * the Base32, the CRC-16, the PEM-like blocks, the JWT. Whatever is in it,
 * the readers answer or refuse with {@link IllegalArgumentException}, the one
 * refusal they document - never another exception - and they do not change
 * the bytes they were given.
 *
 * <p>Only generated test keys cross the heap here.
 */
class NKeyFilesFuzzTest {

    private static final int ROUNDS = Integer.getInteger("seclume.nats.fuzz.rounds", 20_000);
    private static final byte[] NONCE = "nonce-of-the-server".getBytes(StandardCharsets.US_ASCII);

    private static List<byte[]> seeds() throws Exception {
        NKey user = NKey.createUser(null);
        String seed = new String(user.getSeed());
        user.clear();
        String creds = """
                -----BEGIN NATS USER JWT-----
                eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyIn0.c2ln
                ------END NATS USER JWT------

                -----BEGIN USER NKEY SEED-----
                %s
                ------END USER NKEY SEED------
                """.formatted(seed);
        return List.of(seed.getBytes(StandardCharsets.US_ASCII), // seclume-allow: a generated test seed
                creds.getBytes(StandardCharsets.US_ASCII));   // seclume-allow: a generated test file
    }

    private interface Reader {
        Object read(MemorySegment source, int length);
    }

    private static final List<Reader> READERS = List.of(
            NKeyOff::publicKey,
            (source, length) -> NKeyOff.sign(source, length, NONCE),
            NKeyOff::extractJwt,
            NKeyOff::extractStandaloneJwt);

    private static void readAll(byte[] input) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment source = arena.allocate(Math.max(1, input.length));
            MemorySegment.copy(input, 0, source, ValueLayout.JAVA_BYTE, 0, input.length);
            for (Reader reader : READERS) {
                try {
                    reader.read(source, input.length);
                } catch (IllegalArgumentException refused) {
                    // the documented refusal
                } catch (RuntimeException | StackOverflowError | OutOfMemoryError other) {
                    fail("not an IllegalArgumentException: " + other, other);
                }
            }
            assertArrayEquals(input, source.asSlice(0, input.length).toArray(ValueLayout.JAVA_BYTE),
                    "a reader changed its input");
        }
    }

    @Test
    void mutatedSeedAndCredsFilesAreReadOrRefused() throws Exception {
        List<byte[]> seeds = seeds();
        long seed = Long.getLong("seclume.nats.fuzz.seed", 0x5EC_4A75);
        Random random = new Random(seed);
        String base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567-\n ";
        for (int round = 0; round < ROUNDS; round++) {
            byte[] input = seeds.get(round % seeds.size()).clone();
            for (int e = 1 + random.nextInt(4); e > 0 && input.length > 0; e--) {
                int at = random.nextInt(input.length);
                switch (random.nextInt(4)) {
                    case 0 -> input[at] = (byte) random.nextInt(256);
                    case 1 -> input[at] = (byte) base32.charAt(random.nextInt(base32.length()));
                    case 2 -> input = Arrays.copyOf(input, at);
                    default -> input[at] = (byte) (input[at] ^ (1 << random.nextInt(8)));
                }
            }
            try {
                readAll(input);
            } catch (AssertionError broken) {
                throw new AssertionError("seed " + seed + " round " + round + ": "
                        + broken.getMessage(), broken);
            }
        }
    }
}
