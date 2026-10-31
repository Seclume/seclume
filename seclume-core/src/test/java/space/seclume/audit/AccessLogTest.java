package space.seclume.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.crypto.PrivateSigningKey;
import space.seclume.field.FieldKeys;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;
import space.seclume.secret.SecretUnavailableException;

/**
 * The access log: what goes in, what never does, and every way of changing it
 * afterwards that the verifier must catch - and the one it cannot.
 *
 * <p>Isolated: the installed log is the process's.
 */
@Isolated
class AccessLogTest {

    /** A secret that must never be in the log, in any form. */
    private static final String CANARY = "zl-access-log-canary-7f3a9c";

    @TempDir
    Path directory;

    @AfterEach
    void uninstall() {
        AccessLog.install(null);
    }

    private static SecretProvider provider(String description) {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                byte[] bytes = CANARY.getBytes(StandardCharsets.US_ASCII);
                MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
                return bytes.length;
            }

            @Override
            public int maxSecretLength() {
                return 64;
            }

            @Override
            public String toString() {
                return description;
            }
        };
    }

    private static PrivateSigningKey key() {
        assumeTrue(PrivateSigningKey.available(), "no OpenSSL 3 or CNG to sign with");
        return PrivateSigningKey.generateP256();
    }

    private static void read(SecretProvider provider) {
        try (SecretScope scope = SecretScope.fromProvider(provider)) {
            assertEquals(CANARY.length(), scope.length());
        }
    }

    /** A signed log with a few reads, closed; returns the file and leaves the key's public half. */
    private Path signedLog(PrivateSigningKey key, int reads) throws IOException {
        Path file = directory.resolve("access.jsonl");
        try (AccessLog log = AccessLog.open(file, key, null)) {
            AccessLog.install(log);
            for (int i = 0; i < reads; i++) {
                read(provider("FileSecretProvider[/run/secrets/db-" + i + "]"));
                if (i == reads / 2) {
                    log.checkpoint();
                }
            }
        }
        return file;
    }

    private static List<String> lines(Path file) throws IOException {
        return new ArrayList<>(Files.readAllLines(file, StandardCharsets.US_ASCII));
    }

    private static void write(Path file, List<String> lines) throws IOException {
        Files.writeString(file, String.join("\n", lines) + "\n", StandardCharsets.US_ASCII);
    }

    @Test
    void readsAreRecordedAsFactsAndTheLogHolds() throws IOException {
        try (PrivateSigningKey key = key()) {
            Path file = signedLog(key, 4);
            String text = Files.readString(file);
            assertFalse(text.contains(CANARY), "the secret is in the access log");
            // Nor its length: no field holds it as its value (a hash may well contain the digits).
            for (String line : lines(file)) {
                for (Map.Entry<String, String> field : AccessLogVerifier.fields(line).entrySet()) {
                    assertFalse(!field.getKey().equals("seq")
                            && field.getValue().equals(Integer.toString(CANARY.length())),
                            field.getKey() + " holds the secret's length");
                }
            }
            List<String> lines = lines(file);
            assertTrue(lines.get(0).contains("\"event\":\"log.opened\""), lines.get(0));
            assertTrue(lines.get(1).contains("\"event\":\"secret.read\""), lines.get(1));
            assertTrue(lines.get(1).contains("\"source\":\"FileSecretProvider[/run/secrets/db-0]\""));
            assertTrue(lines.get(1).contains("\"outcome\":\"ok\""));
            assertTrue(lines.get(lines.size() - 1).contains("\"event\":\"checkpoint\""));

            AccessLogVerifier.Result result = AccessLogVerifier.verify(file, key.publicKey());
            assertTrue(result.holds(), result.problems().toString());
            assertEquals(1, result.first());
            assertEquals(lines.size(), result.entries());
            assertEquals(2, result.checkpoints());
            assertEquals(lines.size(), result.signedUpTo());
            assertEquals(0, result.unsigned());
        }
    }

    @Test
    void aFailedReadIsRecordedWithItsTypeOnly() throws IOException {
        Path file = directory.resolve("failed.jsonl");
        try (AccessLog log = AccessLog.open(file, null, null)) {
            AccessLog.install(log);
            SecretProvider failing = new SecretProvider() {
                @Override
                public int writeSecret(MemorySegment target) {
                    throw new SecretUnavailableException("the vault said no (" + CANARY + ")");
                }

                @Override
                public int maxSecretLength() {
                    return 64;
                }
            };
            assertThrows(SecretUnavailableException.class, () -> SecretScope.fromProvider(failing));
        }
        String text = Files.readString(file);
        assertTrue(text.contains("\"outcome\":\"failed\",\"error\":\"space.seclume.secret.SecretUnavailableException\""),
                text);
        assertFalse(text.contains(CANARY), "the failure's message reached the log");
    }

    @Test
    void aKeyRingIsRecorded() throws IOException {
        Path file = directory.resolve("ring.jsonl");
        try (AccessLog log = AccessLog.open(file, null, null)) {
            AccessLog.install(log);
            SecretProvider key = new SecretProvider() {
                @Override
                public int writeSecret(MemorySegment target) {
                    for (int i = 0; i < 32; i++) {
                        target.set(ValueLayout.JAVA_BYTE, i, (byte) i);
                    }
                    return 32;
                }

                @Override
                public int maxSecretLength() {
                    return 64;
                }
            };
            try (FieldKeys ignored = FieldKeys.builder().key(3, key).build()) {
                assertNotNull(ignored);
            }
        }
        String text = Files.readString(file);
        assertTrue(text.contains("\"event\":\"data-key.ring\""), text);
        assertTrue(text.contains("\"primary\":\"3\""), text);
    }

    @Test
    void aChangedEntryIsFound() throws IOException {
        try (PrivateSigningKey key = key()) {
            Path file = signedLog(key, 4);
            List<String> lines = lines(file);
            lines.set(2, lines.get(2).replace("db-1", "db-9"));
            write(file, lines);
            AccessLogVerifier.Result result = AccessLogVerifier.verify(file, key.publicKey());
            assertFalse(result.holds());
            assertTrue(result.problems().get(0).startsWith("line 3: entry 3 was changed"),
                    result.problems().toString());
        }
    }

    @Test
    void aRemovedEntryIsFound() throws IOException {
        try (PrivateSigningKey key = key()) {
            Path file = signedLog(key, 4);
            List<String> lines = lines(file);
            lines.remove(2);
            write(file, lines);
            AccessLogVerifier.Result result = AccessLogVerifier.verify(file, key.publicKey());
            assertTrue(result.problems().stream().anyMatch(p -> p.contains("follows entry 2")),
                    result.problems().toString());
            assertTrue(result.problems().stream().anyMatch(p -> p.contains("removed or slipped in")),
                    result.problems().toString());
        }
    }

    @Test
    void swappedEntriesAreFound() throws IOException {
        try (PrivateSigningKey key = key()) {
            Path file = signedLog(key, 4);
            List<String> lines = lines(file);
            String two = lines.get(1);
            lines.set(1, lines.get(2));
            lines.set(2, two);
            write(file, lines);
            assertFalse(AccessLogVerifier.verify(file, key.publicKey()).holds());
        }
    }

    /**
     * Someone who can write the file but not sign: they rewrite one entry and
     * recompute every hash after it. The chain holds again - the next
     * checkpoint's signature does not.
     */
    @Test
    void aRewrittenChainFailsAtTheNextSignature() throws IOException {
        try (PrivateSigningKey key = key()) {
            Path file = signedLog(key, 4);
            List<String> lines = lines(file);
            lines.set(1, lines.get(1).replace("db-0", "db-X"));
            List<String> rewritten = rehash(lines);
            write(file, rewritten);
            AccessLogVerifier.Result chainOnly = AccessLogVerifier.verify(file, null);
            assertTrue(chainOnly.holds(), "without the key the rewrite cannot be told: "
                    + chainOnly.problems());
            AccessLogVerifier.Result result = AccessLogVerifier.verify(file, key.publicKey());
            assertFalse(result.holds());
            assertTrue(result.problems().get(0).contains("a signature that does not hold"),
                    result.problems().toString());
        }
    }

    @Test
    void anotherKeysSignaturesAreRefused() throws IOException {
        try (PrivateSigningKey key = key(); PrivateSigningKey other = key()) {
            Path file = signedLog(key, 2);
            AccessLogVerifier.Result result = AccessLogVerifier.verify(file, other.publicKey());
            assertFalse(result.holds());
            assertTrue(result.problems().get(0).contains("signed by another key"), result.problems().toString());
        }
    }

    /** The one thing the chain cannot see on its own - said by a test, not hidden. */
    @Test
    void aCutOffTailHoldsAndIsVisibleOnlyAgainstACopyKeptElsewhere() throws IOException {
        try (PrivateSigningKey key = key()) {
            Path file = signedLog(key, 6);
            AccessLogVerifier.Result whole = AccessLogVerifier.verify(file, key.publicKey());
            List<String> lines = lines(file);
            int middleCheckpoint = 0;
            for (int i = 0; i < lines.size(); i++) {
                if (lines.get(i).contains("\"event\":\"checkpoint\"")) {
                    middleCheckpoint = i;
                    break;
                }
            }
            write(file, lines.subList(0, middleCheckpoint + 1));
            AccessLogVerifier.Result cut = AccessLogVerifier.verify(file, key.publicKey());
            assertTrue(cut.holds(), cut.problems().toString());
            assertTrue(cut.entries() < whole.entries());
            assertFalse(cut.head().equals(whole.head()), "the head a sink kept tells the two apart");
        }
    }

    @Test
    void aTornLastLineIsReportedAndNotWrittenOn() throws IOException {
        try (PrivateSigningKey key = key()) {
            Path file = signedLog(key, 2);
            String text = Files.readString(file);
            Files.writeString(file, text.substring(0, text.length() - 20));
            AccessLogVerifier.Result result = AccessLogVerifier.verify(file, key.publicKey());
            assertTrue(result.problems().stream().anyMatch(p -> p.contains("torn")), result.problems().toString());
            IOException e = assertThrows(IOException.class, () -> AccessLog.open(file, null, null));
            assertTrue(e.getMessage().contains("torn line"), e.getMessage());
        }
    }

    @Test
    void reopeningContinuesTheChain() throws IOException {
        try (PrivateSigningKey key = key()) {
            Path file = signedLog(key, 2);
            try (AccessLog log = AccessLog.open(file, key, null)) {
                AccessLog.install(log);
                read(provider("again"));
            }
            List<String> lines = lines(file);
            assertEquals(2, lines.stream().filter(l -> l.contains("\"event\":\"log.opened\"")).count());
            AccessLogVerifier.Result result = AccessLogVerifier.verify(file, key.publicKey());
            assertTrue(result.holds(), result.problems().toString());
            assertEquals(lines.size(), result.entries());
        }
    }

    @Test
    void aRotatedLogStartsLaterAndSaysSo() throws IOException {
        try (PrivateSigningKey key = key()) {
            Path file = signedLog(key, 4);
            List<String> lines = lines(file);
            write(file, lines.subList(3, lines.size()));
            AccessLogVerifier.Result result = AccessLogVerifier.verify(file, key.publicKey());
            assertTrue(result.holds(), result.problems().toString());
            assertEquals(4, result.first());
        }
    }

    @Test
    void oneWriterPerFile() throws IOException {
        Path file = directory.resolve("one.jsonl");
        try (AccessLog log = AccessLog.open(file, null, null)) {
            IOException e = assertThrows(IOException.class, () -> AccessLog.open(file, null, null));
            assertTrue(e.getMessage().contains("one writer"), e.getMessage());
            assertNotNull(log);
        }
    }

    @Test
    void sinksGetEveryEntryAndAFailingOneStopsNothing() throws IOException {
        Path file = directory.resolve("sinks.jsonl");
        List<AccessLog.Entry> seen = new ArrayList<>();
        try (AccessLog log = AccessLog.open(file, null, null)) {
            log.addSink(entry -> {
                throw new IllegalStateException("a broken exporter");
            });
            log.addSink(seen::add);
            AccessLog.install(log);
            read(provider("sink test"));
            AccessLog.event("custom.event", Map.of("what", "a test"));
        }
        assertEquals(2, seen.size());
        assertEquals("secret.read", seen.get(0).event());
        assertEquals(seen.get(0).hash(), seen.get(1).prev());
        assertEquals(lines(file).get(1), seen.get(0).line());
        assertEquals(lines(file).size(), 3);
    }

    @Test
    void theTimerSignsWithoutBeingAsked() throws Exception {
        try (PrivateSigningKey key = key()) {
            Path file = directory.resolve("timer.jsonl");
            try (AccessLog log = AccessLog.open(file, key, Duration.ofMillis(50))) {
                AccessLog.install(log);
                read(provider("timer"));
                long deadline = System.nanoTime() + 10_000_000_000L;
                while (!Files.readString(file).contains("\"event\":\"checkpoint\"")
                        && System.nanoTime() < deadline) {
                    Thread.sleep(20);
                }
                assertTrue(Files.readString(file).contains("\"event\":\"checkpoint\""));
            }
        }
    }

    @Test
    void withoutAnInstalledLogNothingIsWrittenAndNothingBreaks() {
        assertNull(AccessLog.installed());
        read(provider("nobody listening"));
        AccessLog.secretRead(null, null);
        AccessLog.event("x", Map.of());
    }

    @Test
    void whatIsNotAsciiIsEscapedAndStillVerifies() throws IOException {
        Path file = directory.resolve("unicode.jsonl");
        try (AccessLog log = AccessLog.open(file, null, null)) {
            AccessLog.install(log);
            read(provider("Schlüssel \"main\" \\ \n zl"));
        }
        String text = Files.readString(file, StandardCharsets.ISO_8859_1);
        for (char c : text.toCharArray()) {
            assertTrue(c == '\n' || (c >= 0x20 && c <= 0x7e), "not ASCII: " + (int) c);
        }
        assertTrue(text.contains("Schl\\u00fcssel \\\"main\\\" \\\\ \\u000a zl"), text);
        assertTrue(AccessLogVerifier.verify(file, null).holds());
    }

    @Test
    void theEntryParserIsStrict() {
        assertEquals(Map.of("a", "1", "b", "x"), AccessLogVerifier.fields("{\"a\":1,\"b\":\"x\"}"));
        assertEquals(Map.of(), AccessLogVerifier.fields("{}"));
        for (String wrong : List.of("", "{", "}", "{\"a\":1", "{\"a\":1,}", "{\"a\":1}x", "{a:1}",
                "{\"a\":1,\"a\":2}", "{\"a\":[1]}", "{\"a\":\"\\x\"}", "{\"a\":\"\u00e9\"}",
                "{\"a\":123456789012345678901}", "{\"a\":-}", "{\"a\" :1}")) {
            assertNull(AccessLogVerifier.fields(wrong), wrong);
        }
    }

    @Test
    void garbageLinesAreReportedNotThrown() throws IOException {
        Path file = directory.resolve("garbage.jsonl");
        Files.writeString(file, "not json\n{\"seq\":\"x\"}\n{\"seq\":1}\n\n");
        AccessLogVerifier.Result result = AccessLogVerifier.verify(file, null);
        assertFalse(result.holds());
        assertEquals(4, result.problems().size(), result.problems().toString());
    }

    /**
     * A signed log and its public key in {@code target/}, for CI's second
     * implementation of the check ({@code .github/scripts/verify_access_log.py},
     * hashlib and the openssl command line), with a changed copy it must refuse.
     */
    @Test
    void aSampleForTheIndependentVerifier() throws IOException {
        try (PrivateSigningKey key = key()) {
            Path file = signedLog(key, 5);
            Path target = Files.createDirectories(Path.of("target"));
            Files.copy(file, target.resolve("access-log-sample.jsonl"),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            Files.write(target.resolve("access-log-key.der"), key.publicKey());
            List<String> lines = lines(file);
            lines.set(2, lines.get(2).replace("db-1", "db-7"));
            write(target.resolve("access-log-changed.jsonl"), lines);
            write(target.resolve("access-log-rewritten.jsonl"), rehash(lines));
        }
    }

    /** Recomputes {@code prev} and {@code hash} down the chain - what a forger without the key does. */
    static List<String> rehash(List<String> lines) {
        List<String> out = new ArrayList<>();
        String prev = AccessLog.ZERO;
        for (String line : lines) {
            int prevAt = line.indexOf(",\"prev\":\"");
            String start = line.substring(0, prevAt);
            if (start.contains("\"event\":\"checkpoint\"")) {
                // The forger names the new head, too - and cannot sign it.
                start = start.replaceFirst("\"head\":\"[0-9a-f]{64}\"", "\"head\":\"" + prev + "\"");
            }
            String body = start + ",\"prev\":\"" + prev + "\"";
            String hash = AccessLog.sha256(body + "}");
            out.add(body + ",\"hash\":\"" + hash + "\"}");
            prev = hash;
        }
        return out;
    }
}
