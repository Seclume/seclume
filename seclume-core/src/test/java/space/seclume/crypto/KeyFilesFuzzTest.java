package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;

import com.code_intelligence.jazzer.junit.FuzzTest;

import space.seclume.internal.Base64Off;

/**
 * Key files are read before anything else is known about them - PEM or DER,
 * PKCS#8 or SEC 1, an OpenSSH file - and they come from a mount, a secret
 * manager, an operator's copy and paste. Whatever is in them, the readers
 * answer or refuse with {@link IllegalArgumentException}, the one refusal
 * they document, and write nothing outside the space they were given.
 *
 * <p>Only generated test keys cross the heap here.
 */
class KeyFilesFuzzTest {

    private static final byte GUARD = 0x5a;
    private static final int ROUNDS = Integer.getInteger("seclume.keys.fuzz.rounds", 20_000);

    private static List<byte[]> seeds() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        byte[] pkcs8 = generator.generateKeyPair().getPrivate().getEncoded();
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(pkcs8)
                + "\n-----END PRIVATE KEY-----\n";
        byte[] opensshBody = "openssh-key-v1\0\0\0\0\4none\0\0\0\4none\0\0\0\0\0\0\0\1"
                .getBytes(StandardCharsets.ISO_8859_1);
        String openssh = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                + Base64.getEncoder().encodeToString(opensshBody)
                + "\n-----END OPENSSH PRIVATE KEY-----\n";
        List<byte[]> seeds = new ArrayList<>();
        seeds.add(pkcs8);
        seeds.add(pem.getBytes(StandardCharsets.US_ASCII));
        seeds.add(openssh.getBytes(StandardCharsets.US_ASCII));
        return seeds;
    }

    /** Every reader on one input; only IllegalArgumentException may come out. */
    private static void readAll(byte[] input) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment source = arena.allocate(Math.max(1, input.length));
            MemorySegment.copy(input, 0, source, ValueLayout.JAVA_BYTE, 0, input.length);

            guarded(arena, 48, out -> EcPrivateKeyFile.scalar(source, input.length, out, 32));
            guarded(arena, 48, out -> EcPrivateKeyFile.scalar(source, input.length, out, 48));
            guarded(arena, Base64Off.decodedUpperBound(input.length),
                    out -> Base64Off.decode(source, 0, input.length, out, 0));
            if (OpenSshPrivateKey.is(source, input.length)) {
                guarded(arena, OpenSshPrivateKey.maxDerLength(input.length),
                        out -> OpenSshPrivateKey.toDer(source, input.length, out));
            }
            assertTrue(java.util.Arrays.equals(input, source.asSlice(0, input.length)
                    .toArray(ValueLayout.JAVA_BYTE)), "the input was changed");
        }
    }

    private interface Reader {
        int read(MemorySegment out);
    }

    /** {@code size} bytes between two guards; the reader's answer has to fit them. */
    private static void guarded(Arena arena, int size, Reader reader) {
        MemorySegment storage = arena.allocate(size + 2L);
        storage.fill(GUARD);
        MemorySegment out = storage.asSlice(1, size);
        try {
            int written = reader.read(out);
            assertTrue(written >= 0 && written <= size, "wrote " + written + " of " + size);
        } catch (IllegalArgumentException refused) {
            // the documented refusal
        } catch (RuntimeException | StackOverflowError | OutOfMemoryError other) {
            fail("not an IllegalArgumentException: " + other, other);
        }
        assertEquals(GUARD, storage.get(ValueLayout.JAVA_BYTE, 0), "written before the space");
        assertEquals(GUARD, storage.get(ValueLayout.JAVA_BYTE, size + 1L),
                "written after the space");
    }

    @FuzzTest(maxDuration = "60s")
    void anyKeyFileIsReadOrRefused(byte[] input) {
        if (input.length <= 16 * 1024) {
            readAll(input);
        }
    }

    /** The real shapes are read, not refused - a fuzzer that only sees refusals tests little. */
    @Test
    void theSeedsAreRealKeys() throws Exception {
        List<byte[]> seeds = seeds();
        try (Arena arena = Arena.ofConfined()) {
            for (byte[] key : seeds.subList(0, 2)) {
                MemorySegment source = arena.allocate(key.length);
                MemorySegment.copy(key, 0, source, ValueLayout.JAVA_BYTE, 0, key.length);
                assertEquals(32, EcPrivateKeyFile.scalar(source, key.length, arena.allocate(32)));
            }
        }
    }

    @Test
    void mutatedKeyFilesAreReadOrRefused() throws Exception {
        List<byte[]> seeds = seeds();
        long seed = Long.getLong("seclume.keys.fuzz.seed", 0x5EC_4E75);
        Random random = new Random(seed);
        for (int round = 0; round < ROUNDS; round++) {
            byte[] input = seeds.get(round % seeds.size()).clone();
            int edits = 1 + random.nextInt(4);
            for (int e = 0; e < edits && input.length > 0; e++) {
                int at = random.nextInt(input.length);
                switch (random.nextInt(4)) {
                    case 0 -> input[at] = (byte) random.nextInt(256);
                    case 1 -> input[at] = (byte) (0x80 | random.nextInt(4));   // long DER lengths
                    case 2 -> input = java.util.Arrays.copyOf(input, at);
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
