package space.seclume.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.checksums.DefaultChecksumAlgorithm;
import software.amazon.awssdk.http.ContentStreamProvider;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4FamilyHttpSigner;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.SignRequest;
import software.amazon.awssdk.http.auth.spi.signer.SignedRequest;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;

/**
 * Request by request, seclume's signature is the one the SDK's own signer
 * makes with the same key - the reference here holds the key as a String,
 * which is why this class runs in a JVM of its own.
 */
class SigV4EquivalenceTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-09-27T12:34:56Z"),
            ZoneOffset.UTC);

    @TempDir
    Path directory;

    private record Case(String name, SdkHttpRequest request, byte[] body,
                        Consumer<SignRequest.Builder<AwsCredentialsIdentity>> properties) {
    }

    private static SdkHttpRequest.Builder request(SdkHttpMethod method, String url) {
        return SdkHttpRequest.builder().method(method).uri(URI.create(url));
    }

    private static Consumer<SignRequest.Builder<AwsCredentialsIdentity>> s3(boolean signPayload) {
        return b -> b.putProperty(AwsV4FamilyHttpSigner.SERVICE_SIGNING_NAME, "s3")
                .putProperty(AwsV4FamilyHttpSigner.DOUBLE_URL_ENCODE, false)
                .putProperty(AwsV4FamilyHttpSigner.NORMALIZE_PATH, false)
                .putProperty(AwsV4FamilyHttpSigner.PAYLOAD_SIGNING_ENABLED, signPayload);
    }

    private static Consumer<SignRequest.Builder<AwsCredentialsIdentity>> service(String name) {
        return b -> b.putProperty(AwsV4FamilyHttpSigner.SERVICE_SIGNING_NAME, name);
    }

    private static List<Case> cases() {
        byte[] body = "{\"QueueUrl\":\"q\",\"MessageBody\":\"hello  world\"}"
                .getBytes(StandardCharsets.UTF_8);
        return List.of(
                new Case("s3 get, unsigned payload",
                        request(SdkHttpMethod.GET, "https://bucket.s3.eu-central-1.amazonaws.com"
                                + "/a%20b/c%2Bd%3D.txt").build(), null, s3(false)),
                new Case("s3 put, signed payload",
                        request(SdkHttpMethod.PUT, "https://s3.eu-central-1.amazonaws.com/b/k.txt")
                                .putHeader("Content-Type", "text/plain")
                                .putHeader("Content-Length", "12").build(),
                        "hello, world".getBytes(StandardCharsets.UTF_8), s3(true)),
                new Case("s3 put, crc32 checksum",
                        request(SdkHttpMethod.PUT, "https://s3.eu-central-1.amazonaws.com/b/k.txt")
                                .putHeader("Content-Length", "12").build(),
                        "hello, world".getBytes(StandardCharsets.UTF_8),
                        s3(false).andThen(b -> b.putProperty(
                                AwsV4FamilyHttpSigner.CHECKSUM_ALGORITHM,
                                DefaultChecksumAlgorithm.CRC32))),
                new Case("s3 list with a query and a port",
                        request(SdkHttpMethod.GET, "http://127.0.0.1:9000/bucket"
                                + "?list-type=2&prefix=a%2Fb%20c&delimiter=%2F&start-after=")
                                .build(), null, s3(true)),
                new Case("sqs json post",
                        request(SdkHttpMethod.POST, "https://sqs.eu-central-1.amazonaws.com/")
                                .putHeader("Content-Type", "application/x-amz-json-1.0")
                                .putHeader("X-Amz-Target", "AmazonSQS.SendMessage")
                                .putHeader("Content-Length", String.valueOf(body.length)).build(),
                        body, service("sqs")),
                new Case("double encoding, normalization, odd headers",
                        request(SdkHttpMethod.GET, "https://example.amazonaws.com"
                                + "/a/./b/../c%20d/%C3%A4/?b=2&a=1&a=0&%C3%BC=x%2By&empty")
                                .putHeader("X-Amz-Meta-Spaces", "  lots   of    space ")
                                .appendHeader("X-Amz-Meta-Many", "one")
                                .appendHeader("X-Amz-Meta-Many", "two")
                                .putHeader("User-Agent", "left out")
                                .build(), null, service("execute-api")),
                new Case("dot segments",
                        request(SdkHttpMethod.GET, "https://example.amazonaws.com/a/./b/../c/")
                                .build(), null, service("execute-api")),
                new Case("an encoded path",
                        request(SdkHttpMethod.GET, "https://example.amazonaws.com/c%20d/%C3%A4")
                                .build(), null, service("execute-api")),
                new Case("query b=2&a=1",
                        request(SdkHttpMethod.GET, "https://example.amazonaws.com/?b=2&a=1").build(),
                        null, service("execute-api")),
                new Case("query a=1&a=0",
                        request(SdkHttpMethod.GET, "https://example.amazonaws.com/?a=1&a=0").build(),
                        null, service("execute-api")),
                new Case("query %C3%BC=x",
                        request(SdkHttpMethod.GET, "https://example.amazonaws.com/?%C3%BC=x").build(),
                        null, service("execute-api")),
                new Case("query x=x%2By",
                        request(SdkHttpMethod.GET, "https://example.amazonaws.com/?x=x%2By").build(),
                        null, service("execute-api")),
                new Case("query empty",
                        request(SdkHttpMethod.GET, "https://example.amazonaws.com/?empty").build(),
                        null, service("execute-api")),
                new Case("query empty=",
                        request(SdkHttpMethod.GET, "https://example.amazonaws.com/?empty=").build(),
                        null, service("execute-api")),

                new Case("headers with spaces and two values",
                        request(SdkHttpMethod.GET, "https://example.amazonaws.com/")
                                .putHeader("X-Amz-Meta-Spaces", "  lots   of    space ")
                                .appendHeader("X-Amz-Meta-Many", "one")
                                .appendHeader("X-Amz-Meta-Many", "two").build(), null,
                        service("execute-api")),
                new Case("a bare get",
                        request(SdkHttpMethod.GET, "https://example.amazonaws.com/").build(),
                        null, service("service")));
    }

    private static SignedRequest sign(HttpSigner<AwsCredentialsIdentity> signer,
                                      AwsCredentialsIdentity identity, Case c) {
        SignRequest.Builder<AwsCredentialsIdentity> builder = SignRequest.builder(identity)
                .request(c.request())
                .putProperty(AwsV4HttpSigner.REGION_NAME, "eu-central-1")
                .putProperty(HttpSigner.SIGNING_CLOCK, CLOCK);
        if (c.body() != null) {
            builder.payload(ContentStreamProvider.fromByteArray(c.body()));
        }
        c.properties().accept(builder);
        return signer.sign(builder.build());
    }

    @Test
    void signsAsTheSdkDoes() throws Exception {
        Path file = SecretKeyFile.make(directory);
        String secret = Files.readString(file); // the reference signer needs it as a String
        HttpSigner<AwsCredentialsIdentity> ours =
                SeclumeAws.signer(SecretKeyFile.spec("AKIAEXAMPLE", file));
        AwsCredentialsIdentity placeholder = AwsCredentialsIdentity.create("AKIAEXAMPLE",
                SeclumeAws.PLACEHOLDER);
        AwsCredentialsIdentity real = AwsCredentialsIdentity.create("AKIAEXAMPLE", secret);
        StringBuilder failures = new StringBuilder();
        for (Case c : cases()) {
            SdkHttpRequest expected = sign(AwsV4HttpSigner.create(), real, c).request();
            SdkHttpRequest actual = sign(ours, placeholder, c).request();
            for (String header : List.of("Authorization", "x-amz-content-sha256",
                    "x-amz-checksum-crc32", "X-Amz-Date")) {
                if (!expected.firstMatchingHeader(header).equals(
                        actual.firstMatchingHeader(header))) {
                    failures.append(c.name()).append(": ").append(header).append(" expected ")
                            .append(expected.firstMatchingHeader(header)).append(" but was ")
                            .append(actual.firstMatchingHeader(header)).append('\n');
                }
            }
        }
        assertEquals("", failures.toString());
    }

    /**
     * AWS's own test suite, {@code get-vanilla}: its string to sign, signed with
     * its published key through the derivation in native memory. (The signer as
     * a whole also signs {@code x-amz-content-sha256}, as the SDK does, which
     * that vector predates - the comparison above covers the rest.)
     */
    @Test
    void theAwsTestVector() throws Exception {
        Path file = directory.resolve("example-key");
        Files.writeString(file, "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
        String toSign = "AWS4-HMAC-SHA256\n20150830T123600Z\n"
                + "20150830/us-east-1/service/aws4_request\n"
                + "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63";
        try (var arena = java.lang.foreign.Arena.ofConfined();
             var key = space.seclume.secret.SecretProviders.of(
                     java.util.Map.of("provider", "file", "path", file.toString()))) {
            assertEquals("5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
                    space.seclume.internal.AwsSigV4.hex(space.seclume.internal.AwsSigV4.sign(
                            arena, key::writeSecret, toSign, "20150830", "us-east-1",
                            "service")));
        }
    }

    @Test
    void aSecretInTheSdkIsRefused() throws Exception {
        Path file = SecretKeyFile.make(directory);
        HttpSigner<AwsCredentialsIdentity> ours =
                SeclumeAws.signer(SecretKeyFile.spec("AKIAEXAMPLE", file));
        IllegalStateException refused = assertThrows(IllegalStateException.class,
                () -> sign(ours, AwsCredentialsIdentity.create("AKIAEXAMPLE", "a-real-secret"),
                        cases().get(0)));
        assertTrue(refused.getMessage().contains("credentials of its own"),
                refused.getMessage());
        assertThrows(IllegalArgumentException.class, () -> SeclumeAws.signer(
                "access-key-id=A&secret-access-key=x&provider=file&path=" + file));
    }
}
