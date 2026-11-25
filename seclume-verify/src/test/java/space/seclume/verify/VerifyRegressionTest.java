package space.seclume.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.audit.AccessLog;
import space.seclume.crypto.PrivateSigningKey;

/**
 * Two audit findings of seclume-verify. {@code audit} with a key passed a log
 * without a single signed checkpoint - anyone who can write the file rebuilds
 * the chain - and exited 0 with entries after the last checkpoint. And
 * {@code migrate} wrote option values from the source URL unencoded:
 * {@code applicationName=billing&tls=off} turned TLS off.
 */
class VerifyRegressionTest {

    @TempDir
    Path directory;

    @Test
    void aLogWithoutACheckpointIsNotVouchedFor() throws Exception {
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
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            PrintStream print = new PrintStream(out, true, StandardCharsets.UTF_8);
            assertEquals(0, AuditVerify.run(List.of(file.toString(), der.toString()), print, print),
                    "the genuine log - the control");

            List<String> forged = new ArrayList<>();
            for (String line : Files.readAllLines(file)) {
                if (!line.contains("\"event\":\"checkpoint\"")) {
                    forged.add(line);
                }
            }
            Files.writeString(file, String.join("\n", forged) + "\n");
            assertNotEquals(0, AuditVerify.run(List.of(file.toString(), der.toString()), print,
                    print), "a chain no signature vouches for passed: " + out);
        }
    }

    @Test
    void anOptionValueCannotAddAnOption() {
        Migrate.Result result = Migrate.translateUrl("jdbc:postgresql://db/app?sslmode=verify-full"
                + "&ApplicationName=billing%26tls%3Doff");
        for (String property : result.properties()) {
            assertFalse(property.contains("&tls=off"), property);
        }
    }
}
