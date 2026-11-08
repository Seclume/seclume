package space.seclume.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.audit.AccessLog;
import space.seclume.crypto.PrivateSigningKey;

/** {@code --audit-verify}: a log that holds, one that does not, with the key as DER and as PEM. */
class AuditVerifyTest {

    @TempDir
    Path directory;

    @Test
    void holdsChangedAndTheKeyInBothSpellings() throws Exception {
        assumeTrue(PrivateSigningKey.available(), "no OpenSSL 3 or CNG to sign with");
        try (PrivateSigningKey key = PrivateSigningKey.generateP256()) {
            Path file = directory.resolve("access.jsonl");
            try (AccessLog log = AccessLog.open(file, key, null)) {
                AccessLog.install(log);
                AccessLog.event("secret.read", Map.of("provider", "file", "outcome", "ok"));
            } finally {
                AccessLog.install(null);
            }
            Path der = Files.write(directory.resolve("key.der"), key.publicKey());
            Path pem = Files.writeString(directory.resolve("key.pem"), "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                            .encodeToString(key.publicKey()) + "\n-----END PUBLIC KEY-----\n");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            PrintStream print = new PrintStream(out, true, StandardCharsets.UTF_8);
            assertEquals(0, AuditVerify.run(List.of(file.toString(), der.toString()), print, print));
            assertEquals(0, AuditVerify.run(List.of(file.toString(), pem.toString()), print, print));
            assertTrue(out.toString(StandardCharsets.UTF_8).contains("1 signed and holding"), out.toString());
            assertEquals(0, AuditVerify.run(List.of(file.toString()), print, print));
            assertTrue(out.toString(StandardCharsets.UTF_8).contains("not checked - no public key given"));

            List<String> lines = Files.readAllLines(file);
            lines.set(1, lines.get(1).replace("\"file\"", "\"vault\""));
            Files.writeString(file, String.join("\n", lines) + "\n");
            out.reset();
            assertEquals(1, AuditVerify.run(List.of(file.toString(), pem.toString()), print, print));
            assertTrue(out.toString(StandardCharsets.UTF_8).contains("was changed"), out.toString());

            assertEquals(2, AuditVerify.run(List.of(), print, print));
            assertEquals(2, AuditVerify.run(List.of(directory.resolve("absent").toString()), print, print));
            Path broken = Files.writeString(directory.resolve("broken.pem"), "-----BEGIN PUBLIC KEY-----\nAAAA\n");
            assertEquals(2, AuditVerify.run(List.of(file.toString(), broken.toString()), print, print));
        }
    }

    /**
     * Cut at the start, a log holds - it is what a rotated one looks like. The
     * tool says the first entries are not there; given the file before, it
     * checks the chain across both and finds what is missing.
     */
    @Test
    void aLogCutAtTheStartIsToldAndTheFileBeforeChecksIt() throws Exception {
        Path file = directory.resolve("access.jsonl");
        try (AccessLog log = AccessLog.open(file, null, null)) {
            AccessLog.install(log);
            for (int i = 0; i < 5; i++) {
                AccessLog.event("secret.read", Map.of("provider", "file", "outcome", "ok"));
            }
        } finally {
            AccessLog.install(null);
        }
        List<String> lines = Files.readAllLines(file);
        Path older = Files.writeString(directory.resolve("access.jsonl.1"),
                String.join("\n", lines.subList(0, 3)) + "\n");
        Path newer = Files.writeString(directory.resolve("access-now.jsonl"),
                String.join("\n", lines.subList(3, lines.size())) + "\n");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream print = new PrintStream(out, true, StandardCharsets.UTF_8);

        assertEquals(0, AuditVerify.run(List.of(newer.toString()), print, print));
        assertTrue(out.toString(StandardCharsets.UTF_8).contains("the first 3 entries are not here"),
                out.toString(StandardCharsets.UTF_8));

        out.reset();
        assertEquals(0, AuditVerify.run(List.of(older.toString(), newer.toString()), print, print));
        assertTrue(!out.toString(StandardCharsets.UTF_8).contains("are not here"),
                out.toString(StandardCharsets.UTF_8));

        Path gap = Files.writeString(directory.resolve("access-gap.jsonl.1"),
                String.join("\n", lines.subList(0, 2)) + "\n");
        out.reset();
        assertEquals(1, AuditVerify.run(List.of(gap.toString(), newer.toString()), print, print),
                "an entry between the two files is missing: " + out.toString(StandardCharsets.UTF_8));
    }
}
