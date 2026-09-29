package space.seclume.kubernetes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.ref.Reference;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.V1Pod;

import space.seclume.tck.NoSecretInHeap;

/** The official client against an API server in another process; the token rotates. */
class KubernetesClientTest {

    @TempDir
    static Path directory;

    static Process server;
    static String url;

    @BeforeAll
    static void start() throws Exception {
        Path script = directory.resolve("setup.sh");
        Files.writeString(script, String.join("\n", "set -e", "cd '" + directory + "'",
                "openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out ca.crt -days 2"
                        + " -subj /CN=localhost -addext subjectAltName=DNS:localhost 2>/dev/null",
                "openssl pkcs12 -export -in ca.crt -inkey key.pem -out store.p12 -passout pass:store",
                "head -c 300 /dev/urandom | base64 | tr -d '\\n/+=' > token", ""));
        assertEquals(0, space.seclume.tck.Shell.builder(script.toString()).start().waitFor());
        server = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java")
                .toString(), "-cp", System.getProperty("java.class.path"),
                ApiServerProcess.class.getName(), directory.toString())
                .redirectErrorStream(true).redirectOutput(directory.resolve("server.log").toFile())
                .start();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
        while (!Files.exists(directory.resolve("port"))) {
            assertTrue(server.isAlive() && System.nanoTime() < deadline, "no API server");
            Thread.sleep(50);
        }
        url = "https://localhost:" + Files.readString(directory.resolve("port")).trim()
                + "?tlsRootCert=" + directory.resolve("ca.crt").toString().replace('\\', '/')
                + "&provider=file&path=" + directory.resolve("token").toString().replace('\\', '/');
    }

    @AfterAll
    static void stop() {
        if (server != null) {
            server.destroy();
        }
    }

    private static List<String> pods(ApiClient client) throws ApiException {
        return new CoreV1Api(client).listNamespacedPod("default").execute().getItems().stream()
                .map(V1Pod::getMetadata).map(m -> m.getName()).toList();
    }

    @Test
    void listsPodsAndFollowsARotatedToken() throws Exception {
        ApiClient client = SeclumeKubernetes.client(url);
        assertEquals(List.of("web-1"), pods(client));
        rotate();
        assertEquals(List.of("web-1"), pods(client));      // the same client, the new token
    }

    @Test
    void aWrongTokenIsRefused() throws Exception {
        Path wrong = directory.resolve("wrong-token");
        Files.writeString(wrong, "not-the-token");
        ApiClient client = SeclumeKubernetes.client(url.replace(
                directory.resolve("token").toString().replace('\\', '/'),
                wrong.toString().replace('\\', '/')));
        ApiException refused = assertThrows(ApiException.class, () -> pods(client));
        assertEquals(401, refused.getCode());
    }

    @Test
    void theTokenIsNotOnTheHeap() throws Exception {
        ApiClient client = SeclumeKubernetes.client(url);
        for (int i = 0; i < 3; i++) {
            pods(client);
        }
        NoSecretInHeap.assertAbsent(directory.resolve("token"));
        String leaked = Files.readString(directory.resolve("token")); // the control
        AssertionError found = assertThrows(AssertionError.class,
                () -> NoSecretInHeap.assertAbsent(directory.resolve("token")));
        assertTrue(found.getMessage().contains("the secret is on the heap"), found.getMessage());
        Reference.reachabilityFence(leaked);
    }

    /** A new token in the file, as the kubelet writes one - by a shell, not this JVM. */
    private static void rotate() throws Exception {
        Path script = directory.resolve("rotate.sh");
        Files.writeString(script, "cd '" + directory + "' && head -c 300 /dev/urandom | base64"
                + " | tr -d '\\n/+=' > token.new && mv token.new token\n");
        assertEquals(0, space.seclume.tck.Shell.builder(script.toString()).start().waitFor());
    }
}
