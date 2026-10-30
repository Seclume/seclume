package space.seclume.admission;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.crypto.PrivateSigningKey;
import space.seclume.keys.SeclumeKeys;

/**
 * The webhook over HTTPS, as the API server calls it: an AdmissionReview in,
 * the same uid out, allowed, with the patch for the pod base64-encoded -
 * served with a key seclume-keys holds in native memory.
 */
@Timeout(120)
class AdmissionServerTest {

    @TempDir
    Path directory;

    private static final String REVIEW = """
            {"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview",
             "request":{"uid":"705ab4f5-6393-11e8-b7cc-42010a800002",
              "kind":{"group":"","version":"v1","kind":"Pod"},"namespace":"shop",
              "object":{"metadata":{"generateName":"orders-",
                "annotations":{"seclume.space/redact-dumps":"true"}},
               "spec":{"containers":[{"name":"app","image":"orders",
                 "env":[{"name":"DB_PASSWORD","value":"literal-password-in-spec"}]}]}}}}""";

    @Test
    void theApiServerGetsThePatchForThePod() throws Exception {
        assumeTrue(PrivateSigningKey.available(), "OpenSSL 3 on 64-bit Linux or CNG on Windows");
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-days", "1", "-subj", "/CN=seclume-admission.seclume-system.svc",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "-keyout", "tls.key", "-out", "tls.crt");
        SSLContext serving = SeclumeKeys.sslContext(directory.resolve("tls.crt"),
                "provider=file&path=" + directory.resolve("tls.key"));
        Injection.Settings settings = Injection.Settings.of("img");
        try (AdmissionServer server = AdmissionServer.start(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), serving, settings)) {
            HttpClient client = HttpClient.newBuilder().sslContext(trusting()).build();
            String base = "https://127.0.0.1:" + server.port();

            HttpResponse<String> health = client.send(HttpRequest.newBuilder(
                    URI.create(base + "/healthz")).build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, health.statusCode());

            HttpResponse<String> answer = client.send(HttpRequest.newBuilder(
                    URI.create(base + "/mutate")).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(REVIEW)).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, answer.statusCode(), answer.body());
            Map<String, Object> review = Json.asObject(Json.parse(answer.body()));
            assertEquals("admission.k8s.io/v1", review.get("apiVersion"));
            assertEquals("AdmissionReview", review.get("kind"));
            Map<String, Object> response = Json.asObject(review.get("response"));
            assertEquals("705ab4f5-6393-11e8-b7cc-42010a800002", response.get("uid"));
            assertEquals(Boolean.TRUE, response.get("allowed"));
            assertEquals("JSONPatch", response.get("patchType"));
            String patch = StandardCharsets.UTF_8.decode(java.nio.ByteBuffer.wrap(
                    Base64.getDecoder().decode((String) response.get("patch")))).toString();
            Map<String, Object> pod = Json.asObject(Json.asObject(Json.asObject(
                    Json.parse(REVIEW)).get("request")).get("object"));
            assertEquals(Json.write(Injection.mutate(pod, settings).patch()), patch);
            assertFalse(answer.body().contains("literal-password-in-spec"),
                    "the answer repeats a value of the pod's");

            HttpResponse<String> broken = client.send(HttpRequest.newBuilder(
                    URI.create(base + "/mutate"))
                    .POST(HttpRequest.BodyPublishers.ofString("{\"request\":")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(400, broken.statusCode());
        }
    }

    @Test
    void whatIsNotAPodIsLetThroughUnchanged() {
        String answer = AdmissionServer.review("""
                {"apiVersion":"admission.k8s.io/v1","request":{"uid":"u1",
                 "kind":{"kind":"Deployment"},"object":{"metadata":{"annotations":
                 {"seclume.space/redact-dumps":"true"}}}}}""", Injection.Settings.of("img"));
        Map<String, Object> response = Json.asObject(Json.asObject(Json.parse(answer))
                .get("response"));
        assertEquals("u1", response.get("uid"));
        assertEquals(Boolean.TRUE, response.get("allowed"));
        assertNull(response.get("patch"));
    }

    @Test
    void aReviewWithoutAUidIsNoReview() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> AdmissionServer.review("{\"request\":{}}", Injection.Settings.of("img")));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> AdmissionServer.review("[]", Injection.Settings.of("img")));
    }

    private SSLContext trusting() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setCertificateEntry("webhook",
                java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(
                        java.nio.file.Files.newInputStream(directory.resolve("tls.crt"))));
        TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX");
        factory.init(store);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, factory.getTrustManagers(), null);
        return context;
    }

    private void openssl(String... arguments) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>(List.of("-c", "exec openssl \"$@\"", "openssl"));
        command.addAll(List.of(arguments));
        Process process = space.seclume.tck.Shell.builder(command.toArray(String[]::new))
                .directory(directory.toFile()).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(),
                StandardCharsets.UTF_8);
        if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IOException("openssl " + arguments[0] + " failed: " + output);
        }
    }
}
