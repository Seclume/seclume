package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.secret.SecretScope;
import space.seclume.tck.TestHosts;
import space.seclume.tls.ClientIdentities;

/**
 * A login with no password anywhere, the MySQL way.
 *
 * <p>MySQL has no certificate authentication plugin in the community server.
 * What it has is an account whose password is empty and which is only
 * accepted with a client certificate of a given subject from a given issuer:
 *
 * <pre>
 * CREATE USER 'certuser'@'%' IDENTIFIED WITH caching_sha2_password BY ''
 *   REQUIRE SUBJECT '/CN=certuser' AND ISSUER '/CN=seclume-certauth-test-ca';
 * </pre>
 *
 * <p>Against a server of its own ({@code seclume.mycert.*}) with a test CA as
 * {@code ssl-ca}. The certificates are the ones the PostgreSQL test uses, in
 * the ignored directory {@code .local-certauth}. As there, the success case is
 * only half of it: the server is asked which certificate it saw, and every
 * wrong certificate - and none - has to be refused.
 */
@Timeout(60)
class LocalCertificateLoginTest {

    private static TestHosts.Server server;
    private static Path certificates;

    @BeforeAll
    static void aServerThatAcceptsCertificates() {
        Assumptions.assumeTrue(TestHosts.isConfigured("mycert"),
                "no seclume.mycert.host - no server set up for REQUIRE SUBJECT");
        server = TestHosts.server("mycert", 3308);
        try (java.net.Socket probe = new java.net.Socket()) {
            probe.connect(new java.net.InetSocketAddress(server.host(), server.port()), 2000);
        } catch (java.io.IOException stopped) {
            Assumptions.abort("nothing on " + server.host() + ":" + server.port()
                    + " - the certificate-login container is not running");
        }
        certificates = directory();
        Assumptions.assumeTrue(certificates != null, "no .local-certauth directory");
    }

    @AfterAll
    static void dropIdentities() {
        ClientIdentities.closeAll();
    }

    @Test
    void theCertificateAloneLogsIn() throws Exception {
        try (Connection connection = DriverManager.getConnection(url("certuser", "certuser"));
             Statement statement = connection.createStatement();
             ResultSet row = statement.executeQuery("select current_user(), "
                     + "(select variable_value from performance_schema.session_status "
                     + "where variable_name = 'Ssl_version')")) {
            assertTrue(row.next());
            assertEquals("certuser@%", row.getString(1));
            assertEquals("TLSv1.3", row.getString(2));
        }
        assertEquals(0, SecretScope.open(), "a secret scope was left open");
    }

    /** A valid certificate from the right CA, but for another subject. */
    @Test
    void anotherSubjectIsRefusedByTheServer() {
        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url("certuser", "stranger")).close());
        assertEquals("28000", refused.getSQLState(), refused.getMessage());
    }

    /** The right subject from another issuer does not get past the handshake. */
    @Test
    void theRightSubjectFromAnotherIssuerIsRefused() {
        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url("certuser", "forged")).close());
        assertTrue(refused.getMessage().contains("right after the client certificate was sent"),
                refused.getMessage());
    }

    /** No certificate, where the account requires one. */
    @Test
    void noCertificateIsRefusedByTheServer() {
        String url = "jdbc:seclume:mysql://" + server.host() + ":" + server.port()
                + "/certdb?user=certuser&tls=require&tlsStack=seclume&provider=none";
        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url).close());
        assertEquals("28000", refused.getSQLState(), refused.getMessage());
    }

    private static String url(String user, String certificate) {
        return "jdbc:seclume:mysql://" + server.host() + ":" + server.port()
                + "/certdb?user=" + user + "&tls=require&tlsStack=seclume&provider=none"
                + "&clientCert=" + certificates.resolve(certificate + ".crt")
                + "&clientKey-provider=file&clientKey-path="
                + certificates.resolve(certificate + ".key");
    }

    private static Path directory() {
        for (Path candidate : new Path[] {Path.of(".local-certauth"),
                Path.of("..", ".local-certauth")}) {
            if (Files.isDirectory(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }
}
