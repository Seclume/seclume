package space.seclume.mongodb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;

import org.bson.Document;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoDatabase;

import space.seclume.tck.NoSecretInHeap;
import space.seclume.tck.TestHosts;

/**
 * Live test against a real MongoDB 8 instance with TLS (requireTLS).
 * Skipped via {@link org.junit.jupiter.api.Assumptions} when no server is present.
 */
class LocalMongoTlsTest {

    private static String host;
    private static int port;
    private static Path passwordFile;
    private static Path caFile;

    @BeforeAll
    static void checkConfigured() {
        host = System.getProperty("seclume.mongo.host", TestHosts.database());
        port = Integer.getInteger("seclume.mongo.port", 27017);
        passwordFile = find(".local-mongo-password");
        caFile = find(".local-mongo-ca.pem");
        assumeTrue(passwordFile != null, "no password file found (.local-mongo-password)");
        assumeTrue(caFile != null, "no CA file found (.local-mongo-ca.pem)");
        assumeTrue(canConnect(host, port), "MongoDB not reachable on " + host + ":" + port);
    }

    private static boolean canConnect(String host, int port) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), 2000);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private static Path find(String name) {
        if (name == null) {
            return null;
        }
        for (Path candidate : new Path[] {Path.of(name), Path.of("..", name)}) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    @Test
    void connectAndQueryRealMongo() throws Exception {
        String url = "mongodb://seclume_test@" + host + ":" + port
                + "/?authSource=admin&provider=file&path="
                + passwordFile.toString().replace('\\', '/')
                + "&tlsRootCert=" + caFile.toString().replace('\\', '/');

        try (MongoClient client = SeclumeMongo.client(url)) {
            MongoDatabase db = client.getDatabase("admin");
            Document result = db.runCommand(new Document("ping", 1));
            assertNotNull(result);
            assertEquals(1.0, result.getDouble("ok"));
        }

        NoSecretInHeap.assertAbsent(passwordFile);
    }
}
