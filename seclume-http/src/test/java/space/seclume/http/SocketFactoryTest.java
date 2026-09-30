package space.seclume.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.ref.Reference;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import space.seclume.tck.NoSecretInHeap;

/**
 * OkHttp and HttpsURLConnection over {@link SeclumeSslSocketFactory}: they hold
 * placeholders, and the server - another process - sees the secrets.
 */
class SocketFactoryTest {

    @TempDir
    static Path directory;

    static Process server;
    static String base;
    static SeclumeSslSocketFactory tls;
    static String token;
    static String password;

    @BeforeAll
    static void start() throws Exception {
        Path script = directory.resolve("secrets.sh");
        Files.writeString(script, String.join("\n", "set -e", "cd '" + directory + "'",
                "openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2"
                        + " -subj /CN=localhost -addext subjectAltName=DNS:localhost 2>/dev/null",
                "openssl pkcs12 -export -in cert.pem -inkey key.pem -out store.p12 -passout pass:store",
                "head -c 48 /dev/urandom | base64 | tr -d '\\n/+=' > token",
                "head -c 24 /dev/urandom | base64 | tr -d '\\n' > password", ""));
        assertEquals(0, space.seclume.tck.Shell.builder(script.toString()).start().waitFor());
        server = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java")
                .toString(), "-cp", System.getProperty("java.class.path"),
                CredentialServerProcess.class.getName(), directory.toString())
                .redirectErrorStream(true).redirectOutput(directory.resolve("server.log").toFile())
                .start();
        Path port = directory.resolve("port");
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
        while (!Files.exists(port)) {
            assertTrue(server.isAlive() && System.nanoTime() < deadline, "the server did not start");
            Thread.sleep(50);
        }
        base = "https://localhost:" + Files.readString(port).trim();
        tls = SeclumeSslSocketFactory.of("tlsRootCert=" + directory.resolve("cert.pem"));
        token = SeclumeSslSocketFactory.placeholder("provider=file&path="
                + directory.resolve("token"));
        password = SeclumeSslSocketFactory.placeholder("provider=file&path="
                + directory.resolve("password"));
    }

    @AfterAll
    static void stop() throws InterruptedException {
        if (server != null) {
            // Waited for: on Windows the process holds its log in the
            // temporary directory open, and that is deleted right after.
            server.destroy();
            if (!server.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)) {
                server.destroyForcibly().waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            }
        }
    }

    private static OkHttpClient okHttp() {
        return new OkHttpClient.Builder().sslSocketFactory(tls, tls.trustManager())
                .hostnameVerifier(tls.hostnameVerifier()).build();
    }

    private static String call(OkHttpClient client, String path, String header, String value,
                               String body) throws Exception {
        Request.Builder request = new Request.Builder().url(base + path).header(header, value);
        if (body != null) {
            request.post(RequestBody.create(body, MediaType.get("text/plain")));
        }
        try (Response response = client.newCall(request.build()).execute()) {
            return response.body().string();
        }
    }

    @Test
    void okHttpWithBearerApiKeyAndBasic() throws Exception {
        OkHttpClient client = okHttp();
        assertEquals("ok ", call(client, "/bearer", "Authorization", "Bearer " + token, null));
        assertEquals("ok ", call(client, "/api-key", "X-Api-Key", token, null));
        String basic = "Basic " + Base64.getEncoder().encodeToString(("deploy:" + password)
                .getBytes(StandardCharsets.UTF_8));
        assertEquals("ok ", call(client, "/basic", "Authorization", basic, null));
        // a body that happens to hold a placeholder is sent as it is
        String body = "a note mentioning " + token + " in passing";
        assertEquals("ok " + body, call(client, "/bearer", "Authorization", "Bearer " + token,
                body));
        // and a wrong credential is refused by the server, not rewritten
        assertTrue(call(client, "/bearer", "Authorization", "Bearer guessed", null)
                .startsWith("refused"));
    }

    /** A head with a placeholder is a SecretUse event; one without is not. */
    @Test
    void aWrittenSecretIsRecorded() throws Exception {
        OkHttpClient client = okHttp();
        var events = space.seclume.tck.Recorded.during(() -> {
            call(client, "/bearer", "Authorization", "Bearer " + token, null);
            call(client, "/bearer", "X-Nothing", "none", null);
        }, "space.seclume.SecretUse");
        assertEquals(1, events.size(), events.toString());
        assertEquals("http", events.get(0).getString("kind"));
        assertEquals("header", events.get(0).getString("mechanism"));
    }

    @Test
    void httpsUrlConnection() throws Exception {
        HttpsURLConnection connection = (HttpsURLConnection) URI.create(base + "/basic").toURL()
                .openConnection();
        connection.setSSLSocketFactory(tls);
        connection.setHostnameVerifier(tls.hostnameVerifier());
        connection.setRequestProperty("Authorization", "Basic " + Base64.getEncoder()
                .encodeToString(("deploy:" + password).getBytes(StandardCharsets.UTF_8)));
        connection.setDoOutput(true);
        try (OutputStream out = connection.getOutputStream()) {
            out.write("uploaded".getBytes(StandardCharsets.UTF_8));
        }
        assertEquals(200, connection.getResponseCode());
        try (InputStream in = connection.getInputStream()) {
            assertEquals("ok uploaded", new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    @Test
    void anUnknownPlaceholderIsNotSent() {
        OkHttpClient client = okHttp();
        String forged = CredentialPlaceholders.PREFIX + "0000000000000000000000000-1";
        assertThrows(java.io.IOException.class, () -> call(client, "/bearer", "Authorization",
                "Bearer " + forged, null));
    }

    @Test
    void theSecretsAreNotOnTheHeap() throws Exception {
        OkHttpClient client = okHttp();
        for (int i = 0; i < 3; i++) {
            call(client, "/bearer", "Authorization", "Bearer " + token, "x");
            call(client, "/basic", "Authorization", "Basic " + Base64.getEncoder()
                    .encodeToString(("deploy:" + password).getBytes(StandardCharsets.UTF_8)), null);
        }
        NoSecretInHeap.assertAbsent(directory.resolve("token"));
        NoSecretInHeap.assertAbsent(directory.resolve("password"));
        String leaked = Files.readString(directory.resolve("token")); // the control
        AssertionError found = assertThrows(AssertionError.class,
                () -> NoSecretInHeap.assertAbsent(directory.resolve("token")));
        assertTrue(found.getMessage().contains("the secret is on the heap"), found.getMessage());
        Reference.reachabilityFence(leaked);
    }
}
