package space.seclume.mongodb.driver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.bson.Document;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.mongodb.MongoException;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;

import space.seclume.tck.NoSecretInHeap;
import space.seclume.tck.TestHosts;

/**
 * MONGODB-X509 against the replica set, whose CA list includes the test
 * client CA (.local-certauth) and which has the user CN=certuser in $external.
 */
@Timeout(120)
class LocalX509Test {

    private static String hosts;
    private static Path ca;
    private static Path certificates;

    @BeforeAll
    static void needsTheFixture() {
        String host = System.getProperty("seclume.mongo.host", TestHosts.database());
        ca = find(".local-mongo-rs-ca.pem");
        certificates = find(".local-certauth");
        assumeTrue(ca != null && certificates != null, "no replica set or certificate fixture");
        assumeTrue(Files.isReadable(certificates.resolve("certuser.key")), "no client key");
        for (int port = 27021; port <= 27023; port++) {
            try (Socket probe = new Socket()) {
                probe.connect(new InetSocketAddress(host, port), 2000);
            } catch (IOException e) {
                assumeTrue(false, "no replica set member on " + host + ":" + port);
            }
        }
        hosts = host + ":27021," + host + ":27022," + host + ":27023";
    }

    private static Path find(String name) {
        for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
            if (Files.exists(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static String url(String certificate) {
        return "mongodb://" + hosts + "/?replicaSet=slm-rs&authMechanism=MONGODB-X509"
                + "&tlsRootCert=" + ca.toString().replace('\\', '/')
                + "&clientCert=" + certificates.resolve(certificate + ".crt").toString()
                        .replace('\\', '/')
                + "&clientKey-provider=file&clientKey-path="
                + certificates.resolve(certificate + ".key").toString().replace('\\', '/')
                + "&serverSelectionTimeoutMS=5000";
    }

    @Test
    void theCertificateLogsIn() throws Exception {
        try (MongoClient client = SeclumeMongoClients.create(url("certuser"))) {
            Document status = client.getDatabase("admin").runCommand(
                    new Document("connectionStatus", 1));
            List<Document> users = status.get("authInfo", Document.class)
                    .getList("authenticatedUsers", Document.class);
            assertEquals(1, users.size(), status.toJson());
            assertEquals("CN=certuser", users.get(0).getString("user"));
            assertEquals("$external", users.get(0).getString("db"));
            MongoCollection<Document> things = client.getDatabase("seclume_test")
                    .getCollection("zl_x509_" + new ObjectId().toHexString());
            things.insertOne(new Document("_id", 1));
            assertEquals(1, things.countDocuments());
            things.drop();
        }
        NoSecretInHeap.assertAbsent(certificates.resolve("certuser.key"));
    }

    /** A certificate of another CA, and one that only claims to be certuser: refused. */
    @Test
    void anotherCertificateIsRefused() {
        for (String other : List.of("stranger", "forged")) {
            try (MongoClient client = SeclumeMongoClients.create(url(other))) {
                assertThrows(MongoException.class, () -> client.getDatabase("admin")
                        .runCommand(new Document("ping", 1)), other);
            }
        }
    }

    @Test
    void x509WithoutACertificateIsRefusedAtOnce() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> SeclumeMongoClients.create("mongodb://" + hosts
                        + "/?replicaSet=slm-rs&authMechanism=MONGODB-X509&tlsRootCert="
                        + ca.toString().replace('\\', '/')));
        assertEquals(true, refused.getMessage().contains("client certificate"));
    }
}
