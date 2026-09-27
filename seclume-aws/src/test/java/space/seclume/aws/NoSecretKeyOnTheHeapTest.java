package space.seclume.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.ref.Reference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;

import space.seclume.tck.NoSecretInHeap;

/**
 * After signed requests the secret key is not on the heap - and it would be,
 * as the control shows, once anything reads it the usual way. A JVM of its
 * own (see the pom): nothing else here has held the key.
 */
class NoSecretKeyOnTheHeapTest {

    @TempDir
    Path directory;

    @Test
    void theSecretKeyIsNotOnTheHeap() throws Exception {
        Path key = SecretKeyFile.make(directory);
        try (FakeAws aws = new FakeAws(null);
             S3Client s3 = SeclumeAws.configure(S3Client.builder(),
                     SecretKeyFile.spec("AKIAEXAMPLE", key))
                     .endpointOverride(aws.endpoint()).forcePathStyle(true).build()) {
            for (int i = 0; i < 3; i++) {
                s3.putObject(b -> b.bucket("b").key("k"), RequestBody.fromString("v"));
                assertEquals("v", s3.getObjectAsBytes(b -> b.bucket("b").key("k"))
                        .asString(StandardCharsets.UTF_8));
            }
            NoSecretInHeap.assertAbsent(key);
        }

        String leaked = Files.readString(key); // the control, put on the heap on purpose
        AssertionError found = assertThrows(AssertionError.class,
                () -> NoSecretInHeap.assertAbsent(key));
        assertTrue(found.getMessage().contains("the secret is on the heap"), found.getMessage());
        Reference.reachabilityFence(leaked);
    }
}
