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

    /**
     * Over HTTPS, as S3 is: the SDK asks for the body unsigned and for a
     * checksum - which this signer puts into a header, not a chunked trailer.
     */
    @Test
    void s3OverHttpsWithUnsignedBodies() throws Exception {
        Path key = SecretKeyFile.make(directory);
        Tls tls = Tls.make(directory.resolve("tls"));
        try (FakeAws aws = new FakeAws(() -> read(key), tls.server());
             S3Client s3 = SeclumeAws.configure(S3Client.builder(),
                             SecretKeyFile.spec("AKIAEXAMPLE", key))
                     .endpointOverride(aws.endpoint()).forcePathStyle(true)
                     .httpClient(software.amazon.awssdk.http.apache5.Apache5HttpClient.builder()
                             .tlsTrustManagersProvider(tls::trustManagers).build())
                     .build()) {
            byte[] large = new byte[3 * 1024 * 1024 + 17];
            for (int i = 0; i < large.length; i++) {
                large[i] = (byte) (i * 31 + (i >>> 7));
            }
            s3.putObject(b -> b.bucket("b").key("large.bin"), RequestBody.fromBytes(large));
            s3.putObject(b -> b.bucket("b").key("small.txt"), RequestBody.fromString("small"));
            assertTrue(java.util.Arrays.equals(large, s3.getObjectAsBytes(
                    b -> b.bucket("b").key("large.bin")).asByteArray()));
            assertEquals(List.of(), aws.rejected);
        }
    }

    /** A self-signed certificate for localhost, as a server context and a trust list. */
    private record Tls(javax.net.ssl.SSLContext server,
                       javax.net.ssl.TrustManager[] trustManagers) {

        static Tls make(Path directory) throws Exception {
            Files.createDirectories(directory);
            Path script = directory.resolve("tls.sh");
            Files.writeString(script, "cd '" + directory + "' && openssl req -x509 -newkey "
                    + "rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2 -subj /CN=localhost"
                    + " -addext subjectAltName=DNS:localhost 2>/dev/null && openssl pkcs12 "
                    + "-export -in cert.pem -inkey key.pem -out store.p12 -passout pass:store\n");
            Process process = new ProcessBuilder("/bin/sh", script.toString()).start();
            assertEquals(0, process.waitFor());
            java.security.KeyStore store = java.security.KeyStore.getInstance("PKCS12");
            try (var in = Files.newInputStream(directory.resolve("store.p12"))) {
                store.load(in, "store".toCharArray());
            }
            javax.net.ssl.KeyManagerFactory keys = javax.net.ssl.KeyManagerFactory
                    .getInstance("PKIX");
            keys.init(store, "store".toCharArray());
            javax.net.ssl.SSLContext server = javax.net.ssl.SSLContext.getInstance("TLS");
            server.init(keys.getKeyManagers(), null, null);
            javax.net.ssl.TrustManagerFactory trust = javax.net.ssl.TrustManagerFactory
                    .getInstance("PKIX");
            trust.init(store);
            return new Tls(server, trust.getTrustManagers());
        }
    }

    @Test
    void sqsSendMessage() throws Exception {
        Path key = SecretKeyFile.make(directory);
        try (FakeAws aws = new FakeAws(() -> read(key));
             SqsClient sqs = SeclumeAws.configure(SqsClient.builder(),
                     SecretKeyFile.spec("AKIAEXAMPLE", key))
                     .endpointOverride(aws.endpoint()).checksumValidationEnabled(false).build()) {
            String id = sqs.sendMessage(b -> b.queueUrl(aws.endpoint() + "/123/orders")
                    .messageBody("order 42")).messageId();
            assertEquals("m-1", id);
            assertEquals(List.of("order 42"), aws.messages);
            assertEquals(List.of(), aws.rejected);
        }
    }

    @Test
    void anAsyncClientSignsItsBody() throws Exception {
        Path key = SecretKeyFile.make(directory);
        try (FakeAws aws = new FakeAws(() -> read(key));
             software.amazon.awssdk.services.sqs.SqsAsyncClient sqs = SeclumeAws.configure(
                     software.amazon.awssdk.services.sqs.SqsAsyncClient.builder(),
                     SecretKeyFile.spec("AKIAEXAMPLE", key))
                     .endpointOverride(aws.endpoint()).checksumValidationEnabled(false).build()) {
            sqs.sendMessage(b -> b.queueUrl(aws.endpoint() + "/123/orders")
                    .messageBody("async order")).get();
            assertEquals(List.of("async order"), aws.messages);
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
