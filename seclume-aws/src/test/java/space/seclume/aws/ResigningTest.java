package space.seclume.aws;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.http.ContentStreamProvider;
import software.amazon.awssdk.http.HttpExecuteRequest;
import software.amazon.awssdk.http.HttpExecuteResponse;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4FamilyHttpSigner;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.SignRequest;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;

/**
 * A request the SDK's own signer signed with the placeholder - as OpenSearch's
 * transport does - arrives signed with the real key: the fake service signs
 * it again with the SDK's signer and the key, and the two agree.
 */
class ResigningTest {

    @TempDir
    Path directory;

    private static String read(Path key) {
        try {
            return Files.readString(key);
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** What the client hands its HTTP client: the request, signed by the SDK with the placeholder. */
    private static HttpExecuteRequest signedWithThePlaceholder(SeclumeAws.Resigning resigning,
                                                               URI endpoint, byte[] body) {
        SdkHttpRequest request = SdkHttpRequest.builder().method(SdkHttpMethod.PUT)
                .uri(endpoint.resolve("/orders/doc-1"))
                .putHeader("Content-Type", "application/json")
                .putHeader("Content-Length", String.valueOf(body.length)).build();
        AwsCredentialsIdentity placeholder = resigning.credentials().resolveCredentials();
        SdkHttpRequest signed = AwsV4HttpSigner.create().sign(SignRequest.builder(placeholder)
                .request(request).payload(ContentStreamProvider.fromByteArray(body))
                .putProperty(AwsV4FamilyHttpSigner.SERVICE_SIGNING_NAME, "es")
                .putProperty(AwsV4HttpSigner.REGION_NAME, "eu-central-1").build()).request();
        return HttpExecuteRequest.builder().request(signed)
                .contentStreamProvider(ContentStreamProvider.fromByteArray(body)).build();
    }

    @Test
    void theRequestArrivesSignedWithTheRealKey() throws Exception {
        Path key = SecretKeyFile.make(directory);
        byte[] body = "{\"sku\":\"a-1\"}".getBytes(StandardCharsets.UTF_8);
        SeclumeAws.Resigning resigning = SeclumeAws.resigning(
                SecretKeyFile.spec("AKIAEXAMPLE", key), "es");
        try (FakeAws aws = new FakeAws(() -> read(key))) {
            assertEquals(SeclumeAws.PLACEHOLDER,
                    resigning.credentials().resolveCredentials().secretAccessKey());
            HttpExecuteResponse response = resigning.httpClient()
                    .prepareRequest(signedWithThePlaceholder(resigning, aws.endpoint(), body))
                    .call();
            assertEquals(200, response.httpResponse().statusCode(), aws.rejected.toString());
            assertTrue(aws.rejected.isEmpty(), aws.rejected.toString());
            assertArrayEquals(body, aws.objects.get("orders/doc-1"));
        } finally {
            resigning.httpClient().close();
        }
    }

    /** The control: the placeholder's signature, sent as it is, is refused by the service. */
    @Test
    void thePlaceholdersOwnSignatureIsRefused() throws Exception {
        Path key = SecretKeyFile.make(directory);
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        SeclumeAws.Resigning resigning = SeclumeAws.resigning(
                SecretKeyFile.spec("AKIAEXAMPLE", key), "es");
        try (FakeAws aws = new FakeAws(() -> read(key));
             var plain = software.amazon.awssdk.http.apache5.Apache5HttpClient.create()) {
            HttpExecuteResponse response = plain.prepareRequest(
                    signedWithThePlaceholder(resigning, aws.endpoint(), body)).call();
            assertEquals(403, response.httpResponse().statusCode());
            assertEquals(1, aws.rejected.size());
        } finally {
            resigning.httpClient().close();
        }
    }

    @Test
    void aRegionIsRequired() {
        assertThrows(IllegalArgumentException.class, () -> SeclumeAws.resigning(
                "access-key-id=AKIAEXAMPLE&provider=file&path=/run/secrets/x", "es"));
    }
}
