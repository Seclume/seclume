package space.seclume.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.crypto.PrivateSigningKey;

/**
 * A log opened again continues the chain from its last line - and signs, at
 * its next checkpoint, everything before. So whatever stood after the last
 * checkpoint when it was opened again must not come out of the next one
 * vouched for: entries someone wrote into the file while the application was
 * down, or that the application wrote before it was killed without its last
 * checkpoint, were signed by nobody.
 */
@Isolated
class AccessLogRestartTest {

    @TempDir
    Path directory;

    private static PrivateSigningKey key() {
        assumeTrue(PrivateSigningKey.available(), "no OpenSSL 3 or CNG to sign with");
        return PrivateSigningKey.generateP256();
    }

    @Test
    void aLogClosedAndOpenedAgainVerifies() throws IOException {
        Path file = directory.resolve("access.jsonl");
        try (PrivateSigningKey key = key()) {
            try (AccessLog log = AccessLog.open(file, key, null)) {
                log.append("first.run", Map.of());
            }
            try (AccessLog log = AccessLog.open(file, key, null)) {
                log.append("second.run", Map.of());
            }
            AccessLogVerifier.Result result = AccessLogVerifier.verify(file, key.publicKey());
            assertEquals(List.of(), result.problems());
            assertEquals(0, result.unsigned());
        }
    }

    @Test
    void entriesWrittenWhileTheApplicationWasDownAreNotLaunderedByItsNextCheckpoint()
            throws IOException {
        Path file = directory.resolve("access.jsonl");
        try (PrivateSigningKey key = key()) {
            try (AccessLog log = AccessLog.open(file, key, null)) {
                log.append("secret.read", Map.of("source", "the real one"));
            }
            // Someone who can write the file, while the application is down,
            // appends an entry that chains correctly - there is no key to it.
            String forged = forgedAfter(Files.readAllLines(file, StandardCharsets.US_ASCII));
            Files.writeString(file, forged + "\n", StandardCharsets.US_ASCII,
                    StandardOpenOption.APPEND);
            assertEquals(1, AccessLogVerifier.verify(file, key.publicKey()).unsigned(),
                    "before the restart, the forged entry is the unsigned tail");

            try (AccessLog log = AccessLog.open(file, key, null)) {
                log.append("after.restart", Map.of());
            }
            AccessLogVerifier.Result result = AccessLogVerifier.verify(file, key.publicKey());
            assertTrue(result.problems().stream().anyMatch(p -> p.contains("vouched")),
                    "the forged entry came out signed: " + result.problems());
        }
    }

    /**
     * The checkpoint is looked for from the end a block at a time: here it
     * stands far more than one block before it, behind entries a writer
     * without the key added - a run whose last checkpoint a crash took looks
     * the same. Exactly those are named.
     */
    @Test
    void theLastCheckpointIsFoundFarBackAndExactlyTheEntriesAfterItAreNamed() throws IOException {
        Path file = directory.resolve("access.jsonl");
        try (PrivateSigningKey key = key()) {
            try (AccessLog log = AccessLog.open(file, key, null)) {
                for (int i = 0; i < 5; i++) {
                    log.append("before", Map.of("i", Integer.toString(i)));
                }
            }
            long signed = AccessLogVerifier.verify(file, key.publicKey()).signedUpTo();
            try (AccessLog unsigned = AccessLog.open(file, null, null)) {
                // More than a megabyte: the blocks are read and joined, not
                // one line gathered up to the limit of a line
                for (int i = 0; i < 6000; i++) {
                    unsigned.append("without.key", Map.of("i", Integer.toString(i), "pad", "x".repeat(i % 97)));
                }
            }
            assertTrue(Files.size(file) > 1 << 20, "the tail spans more than a megabyte");
            long reopened = AccessLogVerifier.verify(file, key.publicKey()).first()
                    + AccessLogVerifier.verify(file, key.publicKey()).entries();
            try (AccessLog log = AccessLog.open(file, key, null)) {
                log.append("after", Map.of());
            }
            AccessLogVerifier.Result result = AccessLogVerifier.verify(file, key.publicKey());
            assertEquals(1, result.problems().size(), result.problems().toString());
            assertTrue(result.problems().get(0).contains("entries " + (signed + 1) + " to "
                    + (reopened - 1) + " were vouched for by no checkpoint"), result.problems().get(0));
        }
    }

    /**
     * A log no checkpoint of this key ever signed - written without one, now
     * opened with it: the whole file is read for a checkpoint, none is found,
     * and every entry before the opening is named.
     */
    @Test
    void aLogThisKeyNeverSignedIsNamedWhole() throws IOException {
        Path file = directory.resolve("access.jsonl");
        try (PrivateSigningKey key = key()) {
            try (AccessLog log = AccessLog.open(file, null, null)) {
                log.append("unsigned", Map.of());
            }
            try (AccessLog log = AccessLog.open(file, key, null)) {
                log.append("signed", Map.of());
            }
            AccessLogVerifier.Result result = AccessLogVerifier.verify(file, key.publicKey());
            assertEquals(1, result.problems().size(), result.problems().toString());
            assertTrue(result.problems().get(0).contains("entries 1 to 2 were vouched for by no "
                    + "checkpoint"), result.problems().get(0));
        }
    }

    /**
     * A rotated file can begin with a checkpoint: it is the first line read,
     * last, and it counts like any other.
     */
    @Test
    void aFileThatBeginsWithACheckpointIsVouchedForFromIt() throws IOException {
        Path whole = directory.resolve("whole.jsonl");
        Path rotated = directory.resolve("rotated.jsonl");
        try (PrivateSigningKey key = key()) {
            try (AccessLog log = AccessLog.open(whole, key, null)) {
                log.append("before", Map.of());
            }
            List<String> lines = Files.readAllLines(whole, StandardCharsets.US_ASCII);
            String checkpoint = lines.get(lines.size() - 1);
            assertTrue(checkpoint.contains("\"event\":\"checkpoint\""), checkpoint);
            Files.writeString(rotated, checkpoint + "\n", StandardCharsets.US_ASCII);
            try (AccessLog log = AccessLog.open(rotated, key, null)) {
                log.append("after", Map.of());
            }
            String opened = Files.readAllLines(rotated, StandardCharsets.US_ASCII).get(1);
            assertTrue(opened.contains("\"vouched\":\"" + AccessLogVerifier.fields(checkpoint)
                    .get("seq") + "\""), opened);
            assertEquals(List.of(), AccessLogVerifier.verify(rotated, key.publicKey()).problems());
        }
    }

    /**
     * A {@code vouched} that is no number, or not before its own entry, is
     * named too - a writer never writes one, so it was written by someone else.
     */
    @Test
    void aVouchedThatIsNoNumberOrNotBeforeItsEntryIsAProblem() {
        try (PrivateSigningKey key = key()) {
            String signing = "SHA256withECDSA " + AccessLog.fingerprint(key.publicKey());
            for (String vouched : List.of("2", "1", "-1", "x")) {
                String log = chain("{\"seq\":1,\"time\":\"2026-11-11T00:00:00Z\",\"event\":\"log.opened\","
                        + "\"signing\":\"" + signing + "\",\"vouched\":\"" + vouched + "\"");
                List<String> problems = AccessLogVerifier.verify(log, key.publicKey()).problems();
                assertEquals(1, problems.size(), vouched + ": " + problems);
                assertTrue(problems.get(0).contains("opened again"), problems.get(0));
                assertEquals(List.of(), AccessLogVerifier.verify(log, null).problems(),
                        "without the key there is nothing vouched for to check");
            }
            String fine = chain("{\"seq\":1,\"time\":\"2026-11-11T00:00:00Z\",\"event\":\"log.opened\","
                    + "\"signing\":\"" + signing + "\",\"vouched\":\"0\"");
            assertEquals(List.of(), AccessLogVerifier.verify(fine, key.publicKey()).problems());
        }
    }

    /** One entry, chained to nothing before it, as a log's text. */
    private static String chain(String bodyWithoutPrev) {
        String body = bodyWithoutPrev + ",\"prev\":\"" + AccessLog.ZERO + "\"";
        return body + ",\"hash\":\"" + AccessLog.sha256(body + "}") + "\"}\n";
    }

    /** An entry after the last line of {@code lines}, chained and hashed as the log does. */
    private static String forgedAfter(List<String> lines) {
        Map<String, String> last = AccessLogVerifier.fields(lines.get(lines.size() - 1));
        long seq = lines.size() + 1;                    // a line each, from 1
        String body = "{\"seq\":" + seq + ",\"time\":\"2026-11-11T00:00:00Z\","
                + "\"event\":\"secret.read\",\"source\":\"someone else\",\"prev\":\""
                + last.get("hash") + "\"";
        return body + ",\"hash\":\"" + AccessLog.sha256(body + "}") + "\"}";
    }
}
