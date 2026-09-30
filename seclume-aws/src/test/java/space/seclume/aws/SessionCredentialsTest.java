package space.seclume.aws;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.ref.Reference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;

import space.seclume.tck.NoSecretInHeap;

/**
 * Temporary credentials - from a container endpoint and from STS for a web
 * identity - with the secret key, the session token and the tokens that
 * fetch them all out of this JVM's heap. The servers are another process.
 */
class SessionCredentialsTest {

    @TempDir
    static Path directory;

    static Process aws;
    static int s3Port;
    static int stsPort;
    static int containerPort;

    @BeforeAll
    static void start() throws Exception {
        Path script = directory.resolve("secrets.sh");
        Files.writeString(script, String.join("\n",
                "set -e", "cd '" + directory + "'",
                "openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2"
                        + " -subj /CN=localhost -addext subjectAltName=DNS:localhost 2>/dev/null",
                "openssl pkcs12 -export -in cert.pem -inkey key.pem -out store.p12 -passout pass:store",
                "printf ASIAEXAMPLETEMPORARY > access-key-id",
                "head -c 30 /dev/urandom | base64 | tr -d '\\n' > secret-key",
                "head -c 600 /dev/urandom | base64 | tr -d '\\n' > session-token",
                "head -c 32 /dev/urandom | base64 | tr -d '\\n' > container-token",
                "printf 'eyJhbGciOiJSUzI1NiJ9.' > web-identity-token",
                "head -c 120 /dev/urandom | base64 | tr -d '\\n/+=' >> web-identity-token",
                ""));
        Process prepare = space.seclume.tck.Shell.builder(script.toString()).redirectErrorStream(true)
                .start();
        assertEquals(0, prepare.waitFor(), new String(prepare.getInputStream().readAllBytes()));
        aws = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("java.class.path"), FakeAwsProcess.class.getName(),
                directory.toString()).redirectErrorStream(true)
                .redirectOutput(directory.resolve("aws.log").toFile()).start();
        Path ports = directory.resolve("ports");
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
        while (!Files.exists(ports)) {
            assertTrue(aws.isAlive(), () -> "the fake AWS ended: " + log());
            assertTrue(System.nanoTime() < deadline, "the fake AWS did not start");
            Thread.sleep(50);
        }
        String[] numbers = Files.readString(ports).split(" ");
        s3Port = Integer.parseInt(numbers[0]);
        stsPort = Integer.parseInt(numbers[1]);
        containerPort = Integer.parseInt(numbers[2]);
    }

    @AfterAll
    static void stop() throws InterruptedException {
        if (aws != null) {
            // Waited for, not only told: on Windows the process still holds
            // aws.log open for a moment, and the temporary directory's
            // deletion right after this failed the class one build in three.
            aws.destroy();
            if (!aws.waitFor(10, TimeUnit.SECONDS)) {
                aws.destroyForcibly().waitFor(10, TimeUnit.SECONDS);
            }
        }
    }

    private static String log() {
        try {
            return Files.readString(directory.resolve("aws.log"));
        } catch (java.io.IOException e) {
            return e.toString();
        }
    }

    private static List<String> rejected() throws Exception {
        Thread.sleep(400);                        // the fake writes its findings every 200 ms
        return Files.readAllLines(directory.resolve("rejected"));
    }

    private static String trust() {
        return "&tlsRootCert=" + directory.resolve("cert.pem");
    }

    static String container() {
        return "credentials=container&region=eu-central-1&container-uri=http://127.0.0.1:"
                + containerPort + "/v1/credentials&container-token-file="
                + directory.resolve("container-token") + trust();
    }

    static String webIdentity() {
        return "credentials=web-identity&region=eu-central-1&role-arn=arn:aws:iam::123456789012"
                + ":role/app&web-identity-token-file=" + directory.resolve("web-identity-token")
                + "&sts-endpoint=localhost:" + stsPort + trust();
    }

    private static S3Client s3(String spec) {
        return SeclumeAws.configure(S3Client.builder(), spec)
                .endpointOverride(java.net.URI.create("https://localhost:" + s3Port))
                .forcePathStyle(true).build();
    }

    private static void exercise(S3Client s3, String prefix) {
        byte[] large = new byte[2 * 1024 * 1024 + 3];
        for (int i = 0; i < large.length; i++) {
            large[i] = (byte) (i * 17 + (i >>> 9));
        }
        s3.putObject(b -> b.bucket("b").key(prefix + "/large.bin"), RequestBody.fromBytes(large));
        s3.putObject(b -> b.bucket("b").key(prefix + "/streamed.bin"), RequestBody.fromContentProvider(
                () -> new java.io.ByteArrayInputStream(large), "application/octet-stream"));
        s3.putObject(b -> b.bucket("b").key(prefix + "/small.txt"), RequestBody.fromString("small"));
        assertArrayEquals(large, s3.getObjectAsBytes(b -> b.bucket("b")
                .key(prefix + "/streamed.bin")).asByteArray());
        assertEquals("small", s3.getObjectAsBytes(b -> b.bucket("b").key(prefix + "/small.txt"))
                .asString(StandardCharsets.UTF_8));
    }

    @Test
    void containerCredentials() throws Exception {
        try (S3Client s3 = s3(container())) {
            exercise(s3, "container");
        }
        assertEquals(List.of(), rejected());
    }

    @Test
    void webIdentityCredentials() throws Exception {
        try (S3Client s3 = s3(webIdentity())) {
            exercise(s3, "irsa");
        }
        assertEquals(List.of(), rejected());
    }

    @Test
    void anAsyncClientIsRefusedWithTemporaryCredentials() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> SeclumeAws.configure(software.amazon.awssdk.services.s3.S3AsyncClient
                        .builder(), container()));
        assertTrue(refused.getMessage().contains("synchronous"), refused.getMessage());
    }

    @Test
    void noneOfTheSecretsIsOnTheHeap() throws Exception {
        try (S3Client viaContainer = s3(container()); S3Client viaIrsa = s3(webIdentity())) {
            exercise(viaContainer, "heap-1");
            exercise(viaIrsa, "heap-2");
        }
        assertEquals(List.of(), rejected());
        for (String secret : List.of("secret-key", "session-token", "container-token",
                "web-identity-token")) {
            NoSecretInHeap.assertAbsent(directory.resolve(secret));
        }
        String leaked = Files.readString(directory.resolve("session-token")); // the control
        AssertionError found = assertThrows(AssertionError.class,
                () -> NoSecretInHeap.assertAbsent(directory.resolve("session-token")));
        assertTrue(found.getMessage().contains("the secret is on the heap"), found.getMessage());
        Reference.reachabilityFence(leaked);
    }
}
