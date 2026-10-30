package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.code_intelligence.jazzer.junit.FuzzTest;

import space.seclume.crypto.PrivateSigningKey;

/**
 * The SPIFFE Workload API's answers, as {@link SpiffeWorkloadApi} reads them
 * where they lie: {@code X509SVIDResponse} and {@code JWTSVIDResponse}, from
 * bytes nobody vouches for - the agent's socket is local, but a compromised or
 * confused agent is exactly what a parser of its answers has to survive.
 * Whatever arrives ends in an SVID or an {@link IOException}: no index out of
 * bounds, no length taken off the wire as an allocation, no write outside the
 * token's target.
 *
 * <p>The sample runs in every build: valid answers made with openssl, then
 * {@value #ROUNDS} mutations of them - bytes flipped, varints made huge,
 * messages cut short. {@code JAZZER_FUZZ=1} searches further.
 */
class WorkloadApiAnswerFuzzTest {

    private static final int ROUNDS = Integer.getInteger("seclume.spiffe.fuzz.rounds", 3_000);
    private static final int TARGET = 4096;
    private static final byte GUARD = 0x5a;

    private static byte[] x509Seed;
    private static byte[] jwtSeed;

    @TempDir
    static Path directory;

    @BeforeAll
    static void seeds() throws Exception {
        byte[] certificate = null;
        byte[] key = null;
        if (openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-days", "1", "-subj", "/O=example.org", "-addext",
                "subjectAltName=URI:spiffe://example.org/web", "-keyout", "k.pem", "-out", "c.pem")
                && openssl("x509", "-in", "c.pem", "-outform", "DER", "-out", "c.der")
                && openssl("pkcs8", "-topk8", "-nocrypt", "-in", "k.pem", "-outform", "DER",
                        "-out", "k.der")) {
            certificate = Files.readAllBytes(directory.resolve("c.der"));
            key = Files.readAllBytes(directory.resolve("k.der"));
        } else {
            certificate = new byte[] {0x30, 0x03, 0x02, 0x01, 0x01};
            key = new byte[] {0x30, 0x00};
        }
        ByteArrayOutputStream svid = new ByteArrayOutputStream();
        field(svid, 1, "spiffe://example.org/web".getBytes(StandardCharsets.UTF_8));
        field(svid, 2, certificate);
        field(svid, 3, key);
        field(svid, 4, certificate);
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        field(entry, 1, "other.org".getBytes(StandardCharsets.UTF_8));
        field(entry, 2, certificate);
        ByteArrayOutputStream response = new ByteArrayOutputStream();
        field(response, 1, svid.toByteArray());
        field(response, 3, entry.toByteArray());
        x509Seed = response.toByteArray();

        ByteArrayOutputStream jwt = new ByteArrayOutputStream();
        field(jwt, 1, "spiffe://example.org/web".getBytes(StandardCharsets.UTF_8));
        field(jwt, 2, ("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLm9yZy93ZWIiLCJleHAi"
                + "OjQxMDI0NDQ4MDB9.c2ln").getBytes(StandardCharsets.US_ASCII));
        ByteArrayOutputStream jwtResponse = new ByteArrayOutputStream();
        field(jwtResponse, 1, jwt.toByteArray());
        jwtSeed = jwtResponse.toByteArray();
    }

    private static void field(ByteArrayOutputStream out, int number, byte[] value) {
        varint(out, (long) number << 3 | 2);
        varint(out, value.length);
        out.write(value, 0, value.length);
    }

    private static void varint(ByteArrayOutputStream out, long value) {
        while ((value & ~0x7fL) != 0) {
            out.write((int) (value & 0x7f) | 0x80);
            value >>>= 7;
        }
        out.write((int) value);
    }

    private static boolean openssl(String... arguments) throws Exception {
        List<String> command = new ArrayList<>(List.of("openssl"));
        command.addAll(List.of(arguments));
        try {
            Process process = new ProcessBuilder(command).directory(directory.toFile())
                    .redirectErrorStream(true).start();
            process.getInputStream().readAllBytes();
            return process.waitFor(60, TimeUnit.SECONDS) && process.exitValue() == 0;
        } catch (IOException noOpenssl) {
            return false;
        }
    }

    /** The answer as it arrives: five bytes of gRPC framing, then the message. */
    private static void x509(byte[] message) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment answer = arena.allocate(5L + message.length);
            MemorySegment.copy(message, 0, answer, ValueLayout.JAVA_BYTE, 5, message.length);
            try {
                SpiffeWorkloadApi.X509Svid svid = SpiffeWorkloadApi.parse(answer, message.length);
                svid.key().close();
            } catch (IOException expected) {
                // a broken answer, said as one
            }
        }
    }

    private static void jwt(byte[] message) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment answer = arena.allocate(5L + message.length);
            MemorySegment.copy(message, 0, answer, ValueLayout.JAVA_BYTE, 5, message.length);
            MemorySegment target = arena.allocate(TARGET + 16L);
            target.fill(GUARD);
            try {
                SpiffeWorkloadApi.jwt(answer, message.length, target.asSlice(0, TARGET));
            } catch (IOException expected) {
                // a broken answer, said as one
            }
            for (long i = TARGET; i < TARGET + 16L; i++) {
                if (target.get(ValueLayout.JAVA_BYTE, i) != GUARD) {
                    fail("the token was written past its target");
                }
            }
        }
    }

    @FuzzTest(maxDuration = "60s")
    void anX509SvidAnswerEndsInAnSvidOrAnIoException(byte[] message) {
        x509(message);
    }

    @FuzzTest(maxDuration = "60s")
    void aJwtSvidAnswerEndsInATokenOrAnIoException(byte[] message) {
        jwt(message);
    }

    @Test
    void theSeedsAreValidAnswers() throws IOException {
        assumeTrue(PrivateSigningKey.available(), "OpenSSL 3 on 64-bit Linux or CNG on Windows");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment answer = arena.allocate(5L + x509Seed.length);
            MemorySegment.copy(x509Seed, 0, answer, ValueLayout.JAVA_BYTE, 5, x509Seed.length);
            SpiffeWorkloadApi.X509Svid svid = SpiffeWorkloadApi.parse(answer, x509Seed.length);
            assertEquals("spiffe://example.org/web", svid.spiffeId());
            assertEquals(1, svid.federatedBundles().size());
            svid.key().close();
        }
    }

    /**
     * Found by the coverage-guided search: a length of nearly 2^63 wrapped
     * the bounds check's sum and reached the slice as an index out of bounds.
     */
    @Test
    void aLengthNear2To63IsACutShortAnswer() {
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        varint(message, 1L << 3 | 2);                     // field 1, length-delimited
        varint(message, Long.MAX_VALUE - 2);
        message.write(0);
        byte[] bytes = message.toByteArray();
        x509(bytes);
        jwt(bytes);
        ByteArrayOutputStream nested = new ByteArrayOutputStream();
        field(nested, 1, bytes);
        x509(nested.toByteArray());
        jwt(nested.toByteArray());
    }

    @Test
    void mutatedAnswersEndInAnSvidOrAnIoException() {
        assumeTrue(PrivateSigningKey.available(), "OpenSSL 3 on 64-bit Linux or CNG on Windows");
        Random random = new Random(Long.getLong("seclume.spiffe.fuzz.seed", 20261030L));
        for (int round = 0; round < ROUNDS; round++) {
            boolean useJwt = round % 3 == 0;
            byte[] message = mutate(useJwt ? jwtSeed : x509Seed, random);
            try {
                if (useJwt) {
                    jwt(message);
                } else {
                    x509(message);
                }
            } catch (RuntimeException | OutOfMemoryError e) {
                throw new AssertionError("round " + round + ": " + e, e);
            }
        }
    }

    /** Bytes flipped, a varint made huge, the message cut or grown. */
    static byte[] mutate(byte[] seed, Random random) {
        byte[] message = seed.clone();
        int changes = 1 + random.nextInt(4);
        for (int i = 0; i < changes && message.length > 0; i++) {
            int at = random.nextInt(message.length);
            switch (random.nextInt(5)) {
                case 0 -> message[at] = (byte) random.nextInt(256);
                case 1 -> message[at] = (byte) 0xff;                 // a varint that goes on
                case 2 -> message = java.util.Arrays.copyOf(message, at);
                case 3 -> message[at] = (byte) (message[at] ^ (1 << random.nextInt(8)));
                default -> {
                    byte[] grown = java.util.Arrays.copyOf(message, message.length + 10);
                    for (int k = message.length; k < grown.length; k++) {
                        grown[k] = (byte) 0xff;
                    }
                    message = grown;
                }
            }
        }
        return message;
    }
}
