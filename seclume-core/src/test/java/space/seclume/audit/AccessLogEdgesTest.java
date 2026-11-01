package space.seclume.audit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.crypto.PrivateSigningKey;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * The access log at its edges: the entry parser character by character and
 * number by number, the bytes a checkpoint signs, a signature at the longest
 * the verifier reads, an Ed25519 key, an existing empty file and one longer
 * than the window the writer reads its last entry from, how a source is
 * described, and the checkpoint timer's thread. Written against the mutants
 * PIT left alive in this package.
 *
 * <p>Isolated: the installed log is the process's.
 */
@Isolated
class AccessLogEdgesTest {

    @TempDir
    Path directory;

    @AfterEach
    void uninstall() {
        AccessLog.install(null);
    }

    private static PrivateSigningKey p256() {
        assumeTrue(PrivateSigningKey.available(), "no OpenSSL 3 or CNG to sign with");
        return PrivateSigningKey.generateP256();
    }

    private static List<String> lines(Path file) throws IOException {
        return new ArrayList<>(Files.readAllLines(file, StandardCharsets.US_ASCII));
    }

    private static void write(Path file, List<String> lines) throws IOException {
        Files.writeString(file, String.join("\n", lines) + "\n", StandardCharsets.US_ASCII);
    }

    // ------------------------------------------------------------ the parser

    @Test
    void theParserKeepsEveryFieldInItsOrderAndItsValueExactly() {
        Map<String, String> fields = AccessLogVerifier.fields(
                "{\"seq\":12,\"z\":\"last?\",\"a\":-7,\"m\":\"\",\"n\":0}");
        assertEquals(List.of("seq", "z", "a", "m", "n"), List.copyOf(fields.keySet()));
        assertEquals(List.of("12", "last?", "-7", "", "0"), List.copyOf(fields.values()));
        assertEquals(Map.of(), AccessLogVerifier.fields("{}"));
        assertNull(AccessLogVerifier.fields("{} "), "nothing after the object");
    }

    @Test
    void aNumberIsDigitsWithAnOptionalMinusAndAtMostNineteenCharacters() {
        for (String number : List.of("0", "9", "10", "-0", "-9", "1234567890123456789", "-123456789012345678")) {
            assertEquals(Map.of("a", number), AccessLogVerifier.fields("{\"a\":" + number + "}"), number);
        }
        for (String wrong : List.of("/", ":", "-/", "-:", "12345678901234567890", "-1234567890123456789", "--1",
                "1-", "1:", "1.5", "+1")) {
            assertNull(AccessLogVerifier.fields("{\"a\":" + wrong + "}"), wrong);
        }
    }

    @Test
    void aStringIsPrintableAsciiWithItsTwoEscapesAndUnicodeOnes() {
        assertEquals(Map.of("a", " ~"), AccessLogVerifier.fields("{\"a\":\" ~\"}"), "the ends of printable ASCII");
        assertEquals(Map.of("a", "q\"b\\"), AccessLogVerifier.fields("{\"a\":\"q\\\"b\\\\\"}"));
        assertEquals(Map.of("a", "A\u00e9\u20ac"), AccessLogVerifier.fields("{\"a\":\"\\u0041\\u00e9\\u20AC\"}"));
        assertEquals(Map.of("\u0001", "x"), AccessLogVerifier.fields("{\"\\u0001\":\"x\"}"), "a key may be escaped too");
        for (String wrong : List.of("\u001f", "\u007f", "\t", "\\u004", "\\u00g1", "\\n", "\\/", "\\")) {
            assertNull(AccessLogVerifier.fields("{\"a\":\"" + wrong + "\"}"), wrong);
        }
        assertNull(AccessLogVerifier.fields("{\"a\":\"\\u0041"), "four digits, then the end of the line");
        assertNull(AccessLogVerifier.fields("{\"a\":\"open"), "no closing quote");
    }

    @Test
    void whatIsNotSignedYetCountsFromTheFirstEntry() {
        assertEquals(10, new AccessLogVerifier.Result(1, 10, 0, 0, "h", List.of()).unsigned(), "nothing signed");
        assertEquals(6, new AccessLogVerifier.Result(1, 10, 1, 4, "h", List.of()).unsigned());
        assertEquals(0, new AccessLogVerifier.Result(1, 10, 2, 10, "h", List.of()).unsigned());
        assertEquals(6, new AccessLogVerifier.Result(5, 10, 1, 8, "h", List.of()).unsigned(), "a rotated log");
        assertEquals(0, new AccessLogVerifier.Result(5, 10, 1, 14, "h", List.of()).unsigned());
    }

    // ------------------------------------------------------ the writer's text

    @Test
    void aStringIsWrittenEscapedOutsidePrintableAscii() {
        assertEquals("\" ~\"", AccessLog.string(" ~"));
        assertEquals("\"\\u001f\\u007f\\u00e9\"", AccessLog.string("\u001f\u007f\u00e9"));
        assertEquals("\"\\\"\\\\\"", AccessLog.string("\"\\"));
        assertEquals("\"\"", AccessLog.string(""));
    }

    @Test
    void aLineIsHashedAsAsciiUpToTheTilde() throws NoSuchAlgorithmException {
        String text = "{\"a\":\" ~\"}";
        assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(text.getBytes(StandardCharsets.US_ASCII))), AccessLog.sha256(text));
        assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(new byte[0])),
                AccessLog.sha256(""));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> AccessLog.sha256("\u007f"));
        assertEquals("an access log line is ASCII", e.getMessage());
    }

    @Test
    void aCheckpointSignsTheDomainTheSequenceAndTheHead() {
        String head = "0123456789abcdef00ff10e0" + "a5".repeat(20);
        long seq = 0x0102030405060708L;
        byte[] expected = new byte[AccessLog.DOMAIN.length() + 8 + 32];
        byte[] domain = AccessLog.DOMAIN.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(domain, 0, expected, 0, domain.length);
        for (int i = 0; i < 8; i++) {
            expected[domain.length + i] = (byte) (seq >>> (56 - 8 * i));
        }
        System.arraycopy(HexFormat.of().parseHex(head), 0, expected, domain.length + 8, 32);
        try (Arena arena = Arena.ofConfined()) {
            assertArrayEquals(expected, AccessLog.signedMessage(arena, seq, head).toArray(ValueLayout.JAVA_BYTE));
            byte[] one = AccessLog.signedMessage(arena, 1, AccessLog.ZERO).toArray(ValueLayout.JAVA_BYTE);
            assertEquals(1, one[domain.length + 7], "the sequence number is big-endian");
            assertEquals(0, one[domain.length]);
        }
    }

    @Test
    void installReturnsTheLogBefore() throws IOException {
        try (AccessLog one = AccessLog.open(directory.resolve("one.jsonl"), null, null);
             AccessLog two = AccessLog.open(directory.resolve("two.jsonl"), null, null)) {
            assertNull(AccessLog.install(one));
            assertSame(one, AccessLog.installed());
            assertSame(one, AccessLog.install(two));
            assertSame(two, AccessLog.installed());
            assertSame(two, AccessLog.install(null));
            assertNull(AccessLog.installed());
        }
    }

    @Test
    void appendReturnsTheEntryItWrote() throws IOException {
        Path file = directory.resolve("append.jsonl");
        try (AccessLog log = AccessLog.open(file, null, null)) {
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("what", "x");
            AccessLog.Entry entry = log.append("test.event", fields);
            assertEquals(2, entry.seq(), "after log.opened");
            assertEquals("test.event", entry.event());
            assertEquals(Map.of("what", "x"), entry.fields());
            List<String> lines = lines(file);
            assertEquals(lines.get(1), entry.line());
            assertEquals(AccessLogVerifier.fields(lines.get(1)).get("hash"), entry.hash());
            assertEquals(AccessLogVerifier.fields(lines.get(0)).get("hash"), entry.prev());
        }
    }

    // ------------------------------------------------------ signatures read

    /** The log with every checkpoint's signature replaced by {@code signature}, rehashed. */
    private AccessLogVerifier.Result withSignature(Path file, String signature, byte[] publicKey) throws IOException {
        List<String> changed = new ArrayList<>();
        for (String line : lines(file)) {
            changed.add(line.replaceFirst("\"signature\":\"[0-9a-f]*\"", "\"signature\":\"" + signature + "\""));
        }
        Path copy = directory.resolve("changed-" + signature.length() + ".jsonl");
        write(copy, AccessLogTest.rehash(changed));
        return AccessLogVerifier.verify(copy, publicKey);
    }

    @Test
    void aSignatureIsReadUpTo4096HexDigits() throws IOException {
        try (PrivateSigningKey key = p256()) {
            Path file = directory.resolve("signed.jsonl");
            try (AccessLog log = AccessLog.open(file, key, null)) {
                log.append("test.event", Map.of());
            }
            assertTrue(AccessLogVerifier.verify(file, key.publicKey()).holds());
            for (String readable : List.of("00".repeat(2048), "AB".repeat(8), "3006020101020101")) {
                AccessLogVerifier.Result result = withSignature(file, readable, key.publicKey());
                assertFalse(result.holds());
                assertFalse(result.problems().get(0).contains("no readable signature"),
                        readable.length() + " digits are read: " + result.problems());
            }
            for (String unreadable : List.of("00".repeat(2049), "000", "0g", "")) {
                AccessLogVerifier.Result result = withSignature(file, unreadable, key.publicKey());
                assertTrue(result.problems().get(0).endsWith("has no readable signature"),
                        unreadable.length() + " digits: " + result.problems());
            }
        }
    }

    @Test
    void anEd25519KeySignsWithoutADigest() throws Exception {
        assumeTrue(PrivateSigningKey.available(), "no OpenSSL 3 or CNG to sign with");
        byte[] pkcs8 = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPrivate().getEncoded();
        PrivateSigningKey key;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment encoded = arena.allocate(pkcs8.length);
            MemorySegment.copy(pkcs8, 0, encoded, ValueLayout.JAVA_BYTE, 0, pkcs8.length);
            key = PrivateSigningKey.decode(encoded, pkcs8.length);
            encoded.fill((byte) 0);
        } catch (IllegalArgumentException | UnsupportedOperationException e) {
            assumeTrue(false, "no Ed25519 here: " + e.getMessage());
            return;
        }
        try (key) {
            Path file = directory.resolve("ed25519.jsonl");
            try (AccessLog log = AccessLog.open(file, key, null)) {
                log.append("test.event", Map.of());
                log.checkpoint();
            }
            assertTrue(lines(file).get(0).contains("\"signing\":\"Ed25519 "), lines(file).get(0));
            AccessLogVerifier.Result result = AccessLogVerifier.verify(file, key.publicKey());
            assertTrue(result.holds(), result.problems().toString());
            assertEquals(1, result.checkpoints());
        }
    }

    // ------------------------------------------------------- reopening

    @Test
    void anExistingEmptyFileStartsAtOne() throws IOException {
        Path file = Files.createFile(directory.resolve("empty.jsonl"));
        try (AccessLog log = AccessLog.open(file, null, null)) {
            assertEquals(2, log.append("test.event", Map.of()).seq());
        }
        AccessLogVerifier.Result result = AccessLogVerifier.verify(file, null);
        assertTrue(result.holds(), result.problems().toString());
        assertEquals(1, result.first());
    }

    @Test
    void aLogLongerThanTheWindowReadForItsLastEntryContinues() throws IOException {
        Path file = directory.resolve("long.jsonl");
        try (AccessLog log = AccessLog.open(file, null, null)) {
            String filler = "x".repeat(900);
            while (Files.size(file) < (1 << 16) + 5000) {
                log.append("test.filler", Map.of("filler", filler));
            }
        }
        long before = lines(file).size();
        try (AccessLog log = AccessLog.open(file, null, null)) {
            assertEquals(before + 2, log.append("test.event", Map.of()).seq());
        }
        AccessLogVerifier.Result result = AccessLogVerifier.verify(file, null);
        assertTrue(result.holds(), result.problems().toString());
        assertEquals(before + 2, result.entries());
    }

    // ------------------------------------------------------ describing sources

    private static SecretProvider provider(String description) {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                target.set(ValueLayout.JAVA_BYTE, 0, (byte) 'k');
                return 1;
            }

            @Override
            public int maxSecretLength() {
                return 1;
            }

            @Override
            public String toString() {
                return description;
            }
        };
    }

    private String sourceOfARead(SecretProvider provider) throws IOException {
        Path file = directory.resolve("source-" + System.nanoTime() + ".jsonl");
        try (AccessLog log = AccessLog.open(file, null, null)) {
            AccessLog.install(log);
            try (SecretScope _ = SecretScope.fromProvider(provider)) {
                // read once
            }
        } finally {
            AccessLog.install(null);
        }
        for (String line : lines(file)) {
            Map<String, String> fields = AccessLogVerifier.fields(line);
            if ("secret.read".equals(fields.get("event"))) {
                return fields.get("source");
            }
        }
        throw new AssertionError("no secret.read entry in " + lines(file));
    }

    @Test
    void aSourceIsItsDescriptionUpTo200Characters() throws IOException {
        String exactly = "d".repeat(200);
        assertEquals(exactly, sourceOfARead(provider(exactly)));
        assertEquals("e".repeat(200) + "...", sourceOfARead(provider("e".repeat(201))));
        assertEquals("FileSecretProvider[/run/secrets/db]",
                sourceOfARead(provider("FileSecretProvider[/run/secrets/db]")));
    }

    // ------------------------------------------------------ the timer

    private static List<Thread> checkpointThreads() {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(t -> t.getName().equals("seclume-access-log-checkpoint") && t.isAlive()).toList();
    }

    @Test
    void withoutAKeyOrAnIntervalThereIsNoTimer() throws IOException {
        int before = checkpointThreads().size();
        try (AccessLog log = AccessLog.open(directory.resolve("nokey.jsonl"), null, Duration.ofMillis(5))) {
            log.append("test.event", Map.of());
            assertEquals(before, checkpointThreads().size(), "nothing to sign with: no timer");
        }
    }

    @Test
    void theTimerIsADaemonThreadAndOnlyForAPositiveInterval() throws Exception {
        try (PrivateSigningKey key = p256()) {
            int before = checkpointThreads().size();
            for (Duration none : List.of(Duration.ZERO, Duration.ofSeconds(-1))) {
                try (AccessLog _ = AccessLog.open(directory.resolve("none" + none.getSeconds() + ".jsonl"), key, none)) {
                    assertEquals(before, checkpointThreads().size(), none + ": no timer");
                }
            }
            Path file = directory.resolve("timed.jsonl");
            try (AccessLog log = AccessLog.open(file, key, Duration.ofMillis(20))) {
                log.append("test.event", Map.of());
                long deadline = System.nanoTime() + 10_000_000_000L;
                while (!Files.readString(file).contains("\"event\":\"checkpoint\"") && System.nanoTime() < deadline) {
                    Thread.sleep(10);
                }
                List<Thread> threads = checkpointThreads();
                assertTrue(threads.size() > before, "a timer thread runs");
                assertTrue(threads.stream().allMatch(Thread::isDaemon), "and never keeps the JVM alive");
            }
            assertTrue(AccessLogVerifier.verify(file, key.publicKey()).holds());
        }
    }
}
