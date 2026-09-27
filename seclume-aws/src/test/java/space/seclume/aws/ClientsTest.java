package space.seclume.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.sqs.SqsClient;

/**
 * The SDK's S3 and SQS clients, signing through seclume, against a server that
 * checks each signature with the SDK's own signer.
 */
class ClientsTest {

    @TempDir
    Path directory;

    private S3Client s3(FakeAws aws, String spec) {
        return SeclumeAws.configure(S3Client.builder(), spec)
                .endpointOverride(aws.endpoint()).forcePathStyle(true).build();
    }

    @Test
    void s3PutGetListDelete() throws Exception {
        Path key = SecretKeyFile.make(directory);
        try (FakeAws aws = new FakeAws(() -> read(key));
             S3Client s3 = s3(aws, SecretKeyFile.spec("AKIAEXAMPLE", key))) {
            s3.putObject(b -> b.bucket("reports").key("2026/09/ümlaut report.txt")
                    .contentType("text/plain"), RequestBody.fromString("quarterly numbers"));
            s3.putObject(b -> b.bucket("reports").key("empty"), RequestBody.empty());
            assertEquals("quarterly numbers", s3.getObjectAsBytes(b -> b.bucket("reports")
                    .key("2026/09/ümlaut report.txt")).asString(StandardCharsets.UTF_8));
            List<String> keys = s3.listObjectsV2(b -> b.bucket("reports").prefix("2026/"))
                    .contents().stream().map(S3Object::key).toList();
            assertTrue(keys.contains("2026/09/ümlaut report.txt"), keys.toString());
            s3.deleteObject(b -> b.bucket("reports").key("empty"));
            assertEquals(List.of(), aws.rejected);
        }
    }

    @Test
    void sqsSendMessage() throws Exception {
        Path key = SecretKeyFile.make(directory);
        try (FakeAws aws = new FakeAws(() -> read(key));
             SqsClient sqs = SeclumeAws.configure(SqsClient.builder(),
                     SecretKeyFile.spec("AKIAEXAMPLE", key))
                     .endpointOverride(aws.endpoint()).build()) {
            String id = sqs.sendMessage(b -> b.queueUrl(aws.endpoint() + "/123/orders")
                    .messageBody("order 42")).messageId();
            assertEquals("m-1", id);
            assertEquals(List.of("order 42"), aws.messages);
            assertEquals(List.of(), aws.rejected);
        }
    }

    @Test
    void aWrongKeyIsRejected() throws Exception {
        Path key = SecretKeyFile.make(directory);
        Path other = SecretKeyFile.make(Files.createDirectories(directory.resolve("other")));
        try (FakeAws aws = new FakeAws(() -> read(key));
             S3Client s3 = s3(aws, SecretKeyFile.spec("AKIAEXAMPLE", other))) {
            S3Exception refused = assertThrows(S3Exception.class, () -> s3.putObject(
                    b -> b.bucket("reports").key("x"), RequestBody.fromString("x")));
            assertEquals(403, refused.statusCode());
        }
    }

    private static String read(Path key) {
        try {
            return Files.readString(key);
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }
}
