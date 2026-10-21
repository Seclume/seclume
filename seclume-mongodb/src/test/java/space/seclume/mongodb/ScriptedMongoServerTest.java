package space.seclume.mongodb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bson.Document;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.mongodb.MongoException;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoDatabase;

import space.seclume.tck.NoSecretInHeap;

class ScriptedMongoServerTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @TempDir
    Path tempDir;

    @Test
    void successfulHandshakeAndPingAndHeapCheck() throws Exception {
        byte[] pw = new byte[24];
        RANDOM.nextBytes(pw);
        for (int i = 0; i < pw.length; i++) {
            pw[i] = (byte) ('a' + (pw[i] & 0x7f) % 26);
        }
        Path secretFile = tempDir.resolve("secret.pw");
        Files.write(secretFile, pw);

        byte[] serverKey = ScriptedMongoServer.deriveServerKey(pw, ScriptedMongoServer.SALT,
                ScriptedMongoServer.ITERATIONS);
        Arrays.fill(pw, (byte) 0);

        Path proofFile = tempDir.resolve("proof.txt");

        try (ScriptedMongoServer server = ScriptedMongoServer.start(tempDir,
                ScriptedMongoServer.Mode.NORMAL, "orders", serverKey)) {
            server.setProofDumpFile(proofFile);

            String url = "mongodb://orders@localhost:" + server.port()
                    + "/?authSource=admin&provider=file&path="
                    + secretFile.toString().replace('\\', '/')
                    + "&tlsRootCert=" + server.certFile().toString().replace('\\', '/');

            try (MongoClient client = SeclumeMongo.client(url)) {
                MongoDatabase db = client.getDatabase("admin");
                Document pingResult = db.runCommand(new Document("ping", 1));
                assertNotNull(pingResult);
                assertEquals(1.0, pingResult.getDouble("ok"));
            }

            // Verify the secret never leaked onto the JVM heap
            NoSecretInHeap.assertAbsent(secretFile);

            // Verify the client proof never leaked onto the JVM heap
            assertTrue(Files.exists(proofFile), "proof was saved by server");
            NoSecretInHeap.assertAbsent(proofFile);
        }
    }

    @Test
    void serverDoesNotOfferScramSha256IsRefused() throws Exception {
        Path secretFile = tempDir.resolve("secret.pw");
        Files.writeString(secretFile, "correct-password-42");

        try (ScriptedMongoServer server = ScriptedMongoServer.startWithPassword(tempDir,
                ScriptedMongoServer.Mode.NO_SCRAM_SHA_256, "orders", "correct-password-42")) {
            String url = "mongodb://orders@localhost:" + server.port()
                    + "/?authSource=admin&provider=file&path="
                    + secretFile.toString().replace('\\', '/')
                    + "&tlsRootCert=" + server.certFile().toString().replace('\\', '/');

            try (MongoClient client = SeclumeMongo.client(url)) {
                MongoDatabase db = client.getDatabase("admin");
                MongoException ex = assertThrows(MongoException.class,
                        () -> db.runCommand(new Document("ping", 1)));
                assertTrue(ex.getMessage().contains("server does not offer SCRAM-SHA-256"), ex.getMessage());
            }
        }
    }

    @Test
    void serverRequestingTooFewIterationsIsRefused() throws Exception {
        Path secretFile = tempDir.resolve("secret.pw");
        Files.writeString(secretFile, "correct-password-42");

        try (ScriptedMongoServer server = ScriptedMongoServer.startWithPassword(tempDir,
                ScriptedMongoServer.Mode.LOW_ITERATIONS, "orders", "correct-password-42")) {
            String url = "mongodb://orders@localhost:" + server.port()
                    + "/?authSource=admin&provider=file&path="
                    + secretFile.toString().replace('\\', '/')
                    + "&tlsRootCert=" + server.certFile().toString().replace('\\', '/');

            try (MongoClient client = SeclumeMongo.client(url)) {
                MongoDatabase db = client.getDatabase("admin");
                MongoException ex = assertThrows(MongoException.class,
                        () -> db.runCommand(new Document("ping", 1)));
                assertTrue(ex.getMessage().contains("minimum is 4096") || ex.getMessage().contains("iterations"),
                        ex.getMessage());
            }
        }
    }

    @Test
    void serverNonceWithoutClientNoncePrefixIsRefused() throws Exception {
        Path secretFile = tempDir.resolve("secret.pw");
        Files.writeString(secretFile, "correct-password-42");

        try (ScriptedMongoServer server = ScriptedMongoServer.startWithPassword(tempDir,
                ScriptedMongoServer.Mode.BAD_SERVER_NONCE, "orders", "correct-password-42")) {
            String url = "mongodb://orders@localhost:" + server.port()
                    + "/?authSource=admin&provider=file&path="
                    + secretFile.toString().replace('\\', '/')
                    + "&tlsRootCert=" + server.certFile().toString().replace('\\', '/');

            try (MongoClient client = SeclumeMongo.client(url)) {
                MongoDatabase db = client.getDatabase("admin");
                MongoException ex = assertThrows(MongoException.class,
                        () -> db.runCommand(new Document("ping", 1)));
                assertTrue(ex.getMessage().contains("server nonce does not start with ours"), ex.getMessage());
            }
        }
    }

    @Test
    void wrongServerSignatureIsRefused() throws Exception {
        Path secretFile = tempDir.resolve("secret.pw");
        Files.writeString(secretFile, "correct-password-42");

        try (ScriptedMongoServer server = ScriptedMongoServer.startWithPassword(tempDir,
                ScriptedMongoServer.Mode.WRONG_SERVER_SIG, "orders", "correct-password-42")) {
            String url = "mongodb://orders@localhost:" + server.port()
                    + "/?authSource=admin&provider=file&path="
                    + secretFile.toString().replace('\\', '/')
                    + "&tlsRootCert=" + server.certFile().toString().replace('\\', '/');

            try (MongoClient client = SeclumeMongo.client(url)) {
                MongoDatabase db = client.getDatabase("admin");
                MongoException ex = assertThrows(MongoException.class,
                        () -> db.runCommand(new Document("ping", 1)));
                assertTrue(ex.getMessage().contains("mutual authentication failed")
                        || ex.getMessage().contains("server signature mismatch")
                        || ex.getMessage().contains("could not prove that it knows the password"),
                        ex.getMessage());
            }
        }
    }

    @Test
    void nonAsciiPasswordIsRefused() throws Exception {
        Path secretFile = tempDir.resolve("secret.pw");
        Files.write(secretFile, new byte[] {'p', 'a', 's', 's', (byte) 0xC3, (byte) 0xBC}); // non-ASCII

        try (ScriptedMongoServer server = ScriptedMongoServer.startWithPassword(tempDir,
                ScriptedMongoServer.Mode.NORMAL, "orders", "pass")) {
            String url = "mongodb://orders@localhost:" + server.port()
                    + "/?authSource=admin&provider=file&path="
                    + secretFile.toString().replace('\\', '/')
                    + "&tlsRootCert=" + server.certFile().toString().replace('\\', '/');

            try (MongoClient client = SeclumeMongo.client(url)) {
                MongoDatabase db = client.getDatabase("admin");
                MongoException ex = assertThrows(MongoException.class,
                        () -> db.runCommand(new Document("ping", 1)));
                assertTrue(ex.getMessage().contains("password contains non-ASCII characters"), ex.getMessage());
            }
        }
    }

    @Test
    void prematureConnectionCloseIsDetected() throws Exception {
        Path secretFile = tempDir.resolve("secret.pw");
        Files.writeString(secretFile, "correct-password-42");

        try (ScriptedMongoServer server = ScriptedMongoServer.startWithPassword(tempDir,
                ScriptedMongoServer.Mode.DROP_AFTER_HELLO, "orders", "correct-password-42")) {
            String url = "mongodb://orders@localhost:" + server.port()
                    + "/?authSource=admin&provider=file&path="
                    + secretFile.toString().replace('\\', '/')
                    + "&tlsRootCert=" + server.certFile().toString().replace('\\', '/');

            try (MongoClient client = SeclumeMongo.client(url)) {
                MongoDatabase db = client.getDatabase("admin");
                MongoException ex = assertThrows(MongoException.class,
                        () -> db.runCommand(new Document("ping", 1)));
                assertTrue(ex.getMessage().contains("closed prematurely") || ex.getMessage().contains("EOFException")
                        || ex.getMessage().contains("connection closed"), ex.getMessage());
            }
        }
    }

    @Test
    void hostnameMismatchIsRefused() throws Exception {
        Path secretFile = tempDir.resolve("secret.pw");
        Files.writeString(secretFile, "correct-password-42");

        try (ScriptedMongoServer server = ScriptedMongoServer.startWithPassword(tempDir,
                ScriptedMongoServer.Mode.NORMAL, "orders", "correct-password-42")) {
            // Certificate SAN has dns:localhost, ip:127.0.0.1. Connecting via 127.0.0.2 fails hostname check.
            String url = "mongodb://orders@127.0.0.2:" + server.port()
                    + "/?authSource=admin&provider=file&path="
                    + secretFile.toString().replace('\\', '/')
                    + "&tlsRootCert=" + server.certFile().toString().replace('\\', '/')
                    + "&serverSelectionTimeoutMS=2000&connectTimeoutMS=2000";

            try (MongoClient client = SeclumeMongo.client(url)) {
                MongoDatabase db = client.getDatabase("admin");
                assertThrows(MongoException.class, () -> db.runCommand(new Document("ping", 1)));
            }
        }
    }

    /**
     * A server that takes the login and then says nothing does not hold the
     * connection for ever: the connect timeout bounds TLS and SCRAM. Asked of
     * the socket itself, not through a client: the driver's server selection
     * gives up on its own and would hide a connect that never returns - a
     * thread and a socket left hanging per attempt.
     */
    @Test
    void aSilentServerDuringTheLoginEndsAtTheConnectTimeout() throws Exception {
        Path secretFile = tempDir.resolve("secret.pw");
        Files.writeString(secretFile, "correct-password-42");

        try (ScriptedMongoServer server = ScriptedMongoServer.startWithPassword(tempDir,
                ScriptedMongoServer.Mode.SILENT_AFTER_SASL_START, "orders", "correct-password-42")) {
            String url = "mongodb://orders@localhost:" + server.port()
                    + "/?authSource=admin&provider=file&path="
                    + secretFile.toString().replace('\\', '/')
                    + "&tlsRootCert=" + server.certFile().toString().replace('\\', '/');
            javax.net.ssl.SSLSocketFactory sockets = SeclumeMongo.sslContext(url).getSocketFactory();

            long started = System.nanoTime();
            org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(
                    java.time.Duration.ofSeconds(8), () -> {
                        try (java.net.Socket socket = sockets.createSocket()) {
                            assertThrows(java.io.IOException.class, () -> socket.connect(
                                    new java.net.InetSocketAddress("localhost", server.port()), 1500));
                        }
                    }, "the login waited on a silent server instead of timing out");
            long millis = (System.nanoTime() - started) / 1_000_000;
            assertTrue(millis >= 1000, "it gave up before the timeout: " + millis + " ms");
        }
    }
}
