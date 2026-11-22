package space.seclume.aws;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The bucket of a virtual-host style URL is the first label of its host. A
 * name that is no bucket name went into the host as it was: {@code
 * evil.example#} made a presigned "link to S3" that points at evil.example.
 */
class PresignBucketTest {

    @Test
    void bucketNamesAreWhatS3Takes() {
        for (String good : new String[] {"reports", "my-bucket.eu", "a1b", "x".repeat(63)}) {
            assertDoesNotThrow(() -> SeclumeS3Presigner.bucketAsHost(good), good);
        }
        for (String bad : new String[] {"evil.example#", "evil.example/x", "a?b", "a@b", "Upper",
                "ab", "x".repeat(64), "-ab", "ab-", "a..b", "a.-b", "192.168.0.1", "", null}) {
            assertThrows(IllegalArgumentException.class, () -> SeclumeS3Presigner.bucketAsHost(bad),
                    String.valueOf(bad));
        }
    }

    @Test
    void aPresignedUrlCannotBePointedElsewhereThroughTheBucket(@TempDir Path directory)
            throws Exception {
        SeclumeS3Presigner presigner = SeclumeS3Presigner.of(SecretKeyFile.spec("AKIAEXAMPLE",
                SecretKeyFile.make(directory)) + "&region=eu-central-1");
        assertThrows(IllegalArgumentException.class,
                () -> presigner.presignGet("evil.example#", "report.pdf", Duration.ofMinutes(5)));
    }
}
