package space.seclume.mongodb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MongoUrlTest {

    @TempDir
    Path tempDir;

    @Test
    void validUrlWithUserInfo() throws Exception {
        Path pw = tempDir.resolve("pw.txt");
        Files.writeString(pw, "secret123");

        String url = "mongodb://orders@localhost:27017/?authSource=admin&provider=file&path="
                + pw.toString().replace('\\', '/');
        MongoUrl parsed = MongoUrl.parse(url);

        assertEquals("localhost", parsed.host());
        assertEquals(27017, parsed.port());
        assertEquals("orders", parsed.user());
        assertEquals("admin", parsed.authSource());
        assertEquals(10_000, parsed.connectTimeout());
        assertNotNull(parsed.secret());
        assertEquals("mongodb://localhost:27017/", parsed.driverConnectionString());
    }

    @Test
    void validUrlWithQueryUserAndCustomSettings() throws Exception {
        Path pw = tempDir.resolve("pw.txt");
        Files.writeString(pw, "secret123");

        String url = "mongodb://cluster.example.invalid/?user=billing&authSource=billing_db"
                + "&connectTimeout=5000&timeout=2500&provider=file&path="
                + pw.toString().replace('\\', '/');
        MongoUrl parsed = MongoUrl.parse(url);

        assertEquals("cluster.example.invalid", parsed.host());
        assertEquals(27017, parsed.port());
        assertEquals("billing", parsed.user());
        assertEquals("billing_db", parsed.authSource());
        assertEquals(5000, parsed.connectTimeout());
        assertEquals(2500, parsed.timeout());
    }

    @Test
    void multiHostUrlPreservesDriverOptions() throws Exception {
        Path pw = tempDir.resolve("pw.txt");
        Files.writeString(pw, "secret123");

        String url = "mongodb://orders@host1:27017,host2:27018/orders_db?replicaSet=rs0"
                + "&readPreference=secondary&appName=billingApp&connectTimeoutMS=6000"
                + "&provider=file&path=" + pw.toString().replace('\\', '/')
                + "&tlsRootCert=/tmp/ca.pem";
        MongoUrl parsed = MongoUrl.parse(url);

        assertEquals("host1", parsed.host());
        assertEquals(27017, parsed.port());
        assertEquals("orders", parsed.user());
        assertEquals(6000, parsed.connectTimeout());
        assertTrue(parsed.driverConnectionString().startsWith("mongodb://host1:27017,host2:27018/orders_db?"));
        assertTrue(parsed.driverConnectionString().contains("replicaSet=rs0"));
        assertTrue(parsed.driverConnectionString().contains("readPreference=secondary"));
        assertTrue(parsed.driverConnectionString().contains("appName=billingApp"));
        assertTrue(parsed.driverConnectionString().contains("connectTimeoutMS=6000"));
        // Seclume options must not be in driver connection string
        assertTrue(!parsed.driverConnectionString().contains("provider="));
        assertTrue(!parsed.driverConnectionString().contains("orders@"));
        assertTrue(!parsed.driverConnectionString().contains("tlsRootCert="));
    }

    @Test
    void tlsFalseIsRefused() throws Exception {
        Path pw = tempDir.resolve("pw.txt");
        Files.writeString(pw, "secret123");

        IllegalArgumentException ex1 = assertThrows(IllegalArgumentException.class,
                () -> MongoUrl.parse("mongodb://orders@localhost:27017/?tls=false&provider=file&path="
                        + pw.toString().replace('\\', '/')));
        assertTrue(ex1.getMessage().contains("tls=false / ssl=false is refused"), ex1.getMessage());

        IllegalArgumentException ex2 = assertThrows(IllegalArgumentException.class,
                () -> MongoUrl.parse("mongodb://orders@localhost:27017/?ssl=false&provider=file&path="
                        + pw.toString().replace('\\', '/')));
        assertTrue(ex2.getMessage().contains("tls=false / ssl=false is refused"), ex2.getMessage());
    }

    @Test
    void passwordInUserInfoIsRefused() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> MongoUrl.parse("mongodb://user:pass@localhost:27017/"));
        assertTrue(ex.getMessage().contains("password in the URL is refused"), ex.getMessage());
    }

    @Test
    void passwordInQueryIsRefused() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> MongoUrl.parse("mongodb://localhost:27017/?user=alice&password=secret"));
        assertTrue(ex.getMessage().contains("password in the URL is refused"), ex.getMessage());
    }

    @Test
    void missingUserIsRefused() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> MongoUrl.parse("mongodb://localhost:27017/?authSource=admin"));
        assertTrue(ex.getMessage().contains("requires a user name"), ex.getMessage());
    }

    @Test
    void invalidSchemeIsRefused() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> MongoUrl.parse("http://localhost:27017/"));
        assertTrue(ex.getMessage().contains("begins with mongodb://"), ex.getMessage());
    }

    /** A refused URL is not repeated in the message: it may carry a password. */
    @org.junit.jupiter.api.Test
    void aRefusedSchemeDoesNotRepeatTheUrl() {
        IllegalArgumentException refused = org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> MongoUrl.parse("http://orders:hunter2secret@db.example.invalid/"));
        org.junit.jupiter.api.Assertions.assertFalse(
                refused.getMessage().contains("hunter2secret"), refused.getMessage());
    }

    /** A builder that brings its own credential is refused, not cleared behind its back. */
    @org.junit.jupiter.api.Test
    void aBuilderWithACredentialOfItsOwnIsRefused() {
        com.mongodb.MongoClientSettings.Builder builder = com.mongodb.MongoClientSettings.builder()
                .credential(com.mongodb.MongoCredential.createScramSha256Credential(
                        "orders", "admin", "on-the-heap".toCharArray()));
        IllegalArgumentException refused = org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class, () -> SeclumeMongo.configure(builder,
                        "mongodb://orders@db.example.invalid/?provider=none"));
        org.junit.jupiter.api.Assertions.assertTrue(
                refused.getMessage().contains("credential of its own"), refused.getMessage());
    }
}
