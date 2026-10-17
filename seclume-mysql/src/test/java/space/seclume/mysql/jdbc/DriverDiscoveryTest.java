package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.SQLException;

import org.junit.jupiter.api.Test;

/**
 * That an application finds this driver at all - without a server.
 *
 * <p>Everything else here connects first, so the one step before connecting was
 * only ever proven when a database happened to be running: the file under
 * {@code META-INF/services} that tells the {@code ServiceLoader} our class name.
 * A rename, a typo, a resource that does not make it into the jar - each of them
 * leaves a driver that is perfectly correct and that nobody can reach, and an
 * ordinary build stays green.
 *
 * <p>So this asks the way an application asks: by URL, through the
 * {@code DriverManager}, without naming the class. Naming it would load it, its
 * static block would register it, and the service file could be empty for all
 * the test would notice.
 */
class DriverDiscoveryTest {

    private static final String SERVICE = "META-INF/services/java.sql.Driver";

    @Test
    void theDriverManagerFindsUsByUrl() throws SQLException {
        Driver driver = DriverManager.getDriver("jdbc:seclume:mysql://host/db");
        assertNotNull(driver, "no driver for our own URL");
        assertEquals(registeredName(), driver.getClass().getName(),
                "the driver that answers is not the one " + SERVICE + " names");
    }

    /** The second spelling is the same driver, not a second registration. */
    @Test
    void theOtherSpellingLeadsToTheSameDriver() throws SQLException {
        assertSame(DriverManager.getDriver("jdbc:seclume:mysql://host/db").getClass(),
                DriverManager.getDriver("jdbc:seclume:mariadb://host/db").getClass(),
                "both prefixes must be answered by one driver");
    }

    /** And it keeps its hands off what is not its own. */
    @Test
    void aForeignUrlIsNotOurs() {
        assertThrows(SQLException.class,
                () -> DriverManager.getDriver("jdbc:seclume:postgresql://host/db"),
                "we answered a URL that belongs to somebody else");
    }

    @Test
    void rdsIamUsesTheUrlHostPortAndUserUnlessOverridden(
            @org.junit.jupiter.api.io.TempDir java.nio.file.Path dir) throws Exception {
        java.nio.file.Path key = dir.resolve("aws-key");
        java.nio.file.Files.writeString(key, "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");

        var direct = MyUrl.settings(
                "jdbc:seclume:mysql://mydb.cluster.eu-central-1.rds.amazonaws.com:3306/app"
                + "?user=app_user&provider=rds-iam&region=eu-central-1"
                + "&access-key-id=AKIAIOSFODNN7EXAMPLE&key-provider=file&key-path=" + key,
                null);
        String directToken = readSecret(direct.secret());
        assertTrue(directToken.startsWith(
                "mydb.cluster.eu-central-1.rds.amazonaws.com:3306/?Action=connect&DBUser=app_user"),
                directToken);

        var tunneled = MyUrl.settings(
                "jdbc:seclume:mysql://127.0.0.1:13306/app"
                + "?user=app_user&provider=rds-iam&region=eu-central-1"
                + "&host=mydb.cluster.eu-central-1.rds.amazonaws.com&port=3306&db-user=iam_user"
                + "&access-key-id=AKIAIOSFODNN7EXAMPLE&key-provider=file&key-path=" + key,
                null);
        assertEquals("127.0.0.1", tunneled.host());
        assertEquals(13306, tunneled.port());
        String tunneledToken = readSecret(tunneled.secret());
        assertTrue(tunneledToken.startsWith(
                "mydb.cluster.eu-central-1.rds.amazonaws.com:3306/?Action=connect&DBUser=iam_user"),
                tunneledToken);
    }

    private static String readSecret(space.seclume.secret.SecretProvider provider) {
        try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
            java.lang.foreign.MemorySegment seg = arena.allocate(provider.maxSecretLength());
            int n = provider.writeSecret(seg);
            byte[] bytes = new byte[n];
            java.lang.foreign.MemorySegment.copy(
                    seg, java.lang.foreign.ValueLayout.JAVA_BYTE, 0, bytes, 0, n);
            return new String(bytes, StandardCharsets.US_ASCII);
        }
    }

    /** The class name as it actually ships, read from the resource. */
    private static String registeredName() {
        try (InputStream service =
                     DriverDiscoveryTest.class.getClassLoader().getResourceAsStream(SERVICE)) {
            assertNotNull(service, SERVICE + " is not on the classpath - nothing finds this driver");
            return new String(service.readAllBytes(), StandardCharsets.UTF_8).strip();
        } catch (IOException e) {
            throw new AssertionError("cannot read " + SERVICE, e);
        }
    }
}
