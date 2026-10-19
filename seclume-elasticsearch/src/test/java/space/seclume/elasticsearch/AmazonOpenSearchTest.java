package space.seclume.elasticsearch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.opensearch.client.opensearch.OpenSearchClient;

import software.amazon.awssdk.http.ContentStreamProvider;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4FamilyHttpSigner;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.SignRequest;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;

/**
 * Amazon OpenSearch Service through opensearch-java's own AwsSdk2Transport:
 * the request that reaches the (local, TLS) server carries the signature the
 * SDK's signer makes with the real key - signed again here with that key to
 * compare - though the transport itself only ever had a placeholder.
 */
@Timeout(120)
class AmazonOpenSearchTest {

    private static final Pattern AUTHORIZATION = Pattern.compile("AWS4-HMAC-SHA256 "
            + "Credential=([^/]+)/(\\d{8})/([^/]+)/([^/]+)/aws4_request, "
            + "SignedHeaders=([^,]+), Signature=([0-9a-f]{64})");

    @TempDir
    Path directory;

    @Test
    void theDomainGetsTheSignatureOfTheRealKey() throws Exception {
        Path key = directory.resolve("aws-key");
        Files.writeString(key, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        TestPki pki = TestPki.generate();
        List<String> authorizations = new CopyOnWriteArrayList<>();
        try (FakeHttpsServer server = new FakeHttpsServer(pki.serverContext())) {
            server.accepts = value -> authorizations.add(value);
            String url = "https://localhost:" + server.port() + "/?auth=aws&region=eu-central-1"
                    + "&access-key-id=AKIAEXAMPLE&provider=file&path="
                    + key.toString().replace('\\', '/') + "&tlsPin=" + pki.pin();
            var transport = SeclumeOpenSearch.awsTransport(url);
            try {
                assertEquals("c", new OpenSearchClient(transport).info().clusterName());
            } finally {
                transport.close();
            }
            assertEquals(1, server.received.size());
            FakeHttpsServer.Received received = server.received.get(0);
            String authorization = authorizations.get(0);
            Matcher parsed = AUTHORIZATION.matcher(authorization);
            assertTrue(parsed.matches(), authorization);
            assertEquals("AKIAEXAMPLE", parsed.group(1));
            assertEquals("eu-central-1", parsed.group(3));
            assertEquals("es", parsed.group(4));

            SdkHttpRequest.Builder request = SdkHttpRequest.builder()
                    .method(SdkHttpMethod.fromValue(received.method()))
                    .uri(URI.create("https://localhost:" + server.port() + received.target()));
            for (String name : parsed.group(5).split(";")) {
                if (!name.equals("host")) {
                    request.putHeader(name, received.headers().get(name));
                }
            }
            String stamp = received.headers().get("X-Amz-Date").get(0);
            Clock clock = Clock.fixed(LocalDateTime.parse(stamp, DateTimeFormatter.ofPattern(
                    "yyyyMMdd'T'HHmmss'Z'")).toInstant(ZoneOffset.UTC), ZoneOffset.UTC);
            String expected = AwsV4HttpSigner.create().sign(SignRequest.builder(
                    AwsCredentialsIdentity.create("AKIAEXAMPLE", Files.readString(key)))
                    .request(request.build())
                    .payload(ContentStreamProvider.fromByteArray(received.body()
                            .getBytes(StandardCharsets.UTF_8)))
                    .putProperty(AwsV4HttpSigner.REGION_NAME, "eu-central-1")
                    .putProperty(AwsV4FamilyHttpSigner.SERVICE_SIGNING_NAME, "es")
                    .putProperty(HttpSigner.SIGNING_CLOCK, clock)
                    .build()).request().firstMatchingHeader("Authorization").orElse("");
            assertEquals(expected, authorization,
                    "the request is not signed as the SDK signs it with the real key");
        }
    }

    @Test
    void whatTheAwsUrlRefuses() {
        String spec = "&region=eu-central-1&access-key-id=AKIAEXAMPLE&provider=file&path=/x";
        for (String url : new String[] {
            "http://search-x.es.amazonaws.com/?auth=aws" + spec,
            "https://user@search-x.es.amazonaws.com/?auth=aws" + spec,
            "https://search-x.es.amazonaws.com/?auth=basic" + spec,
            "https://search-x.es.amazonaws.com/?auth=aws&service=s3" + spec,
            "https://search-x.es.amazonaws.com/?auth=aws&access-key-id=AKIA&provider=file&path=/x"}) {
            assertThrows(IllegalArgumentException.class, () -> SeclumeOpenSearch.awsTransport(url),
                    url);
        }
    }
}
