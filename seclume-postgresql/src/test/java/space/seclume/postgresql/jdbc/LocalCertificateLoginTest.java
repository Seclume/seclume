package space.seclume.postgresql.jdbc;

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

import space.seclume.postgresql.PgSession;
import space.seclume.secret.SecretScope;
import space.seclume.tck.TestHosts;
import space.seclume.tls.ClientIdentities;

/**
 * A login with no password anywhere: PostgreSQL's {@code cert} method.
 *
 * <p>Against a server of its own ({@code seclume.pgcert.*}) whose
 * {@code pg_hba.conf} says {@code hostssl all certuser 0.0.0.0/0 cert} and
 * whose {@code ssl_ca_file} is a test CA. The client certificates live in the
 * ignored directory {@code .local-certauth}: {@code certuser} issued by that
 * CA, {@code stranger} issued by it for another name, and {@code forged} -
 * the right name from a CA the server has never seen.
 *
 * <p>The success case alone would prove little; a server that fell back to
 * {@code trust} passes it too. So the server is asked which certificate it
 * saw, the driver has to report {@code cert} as the method, and each of the
 * three ways the certificate could be wrong has to be refused.
 */
@Timeout(60)
class LocalCertificateLoginTest {

    private static TestHosts.Server server;
    private static Path certificates;

    @BeforeAll
    static void aServerThatAcceptsCertificates() {
        Assumptions.assumeTrue(TestHosts.isConfigured("pgcert"),
                "no seclume.pgcert.host - no server set up for 'cert'");
        server = TestHosts.server("pgcert", 5436);
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
        long before = SecretScope.allocations();
        try (Connection connection = DriverManager.getConnection(url("certuser", "certuser"))) {
            assertEquals("cert", connection.unwrap(PgSession.class).authenticationMethod(),
                    "no password was asked for and none exists - the certificate let us in");
            try (Statement statement = connection.createStatement();
                 ResultSet row = statement.executeQuery("select current_user, "
                         + "(select client_dn from pg_stat_ssl where pid = pg_backend_pid())")) {
                assertTrue(row.next());
                assertEquals("certuser", row.getString(1));
                assertEquals("/CN=certuser", row.getString(2),
                        "the server has to have seen exactly this certificate");
            }
        }
        // The key file is read once into the identity; the password scope is
        // the only other secret, and it holds nothing. What must not happen
        // is anything left open.
        assertTrue(SecretScope.allocations() >= before);
        assertEquals(0, SecretScope.open(), "a secret scope was left open");
    }

    /** A valid certificate for another name is not this user's. */
    @Test
    void anotherNamesCertificateIsRefusedByTheServer() {
        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url("certuser", "stranger")).close());
        assertEquals("28000", refused.getSQLState(), refused.getMessage());
        assertTrue(refused.getMessage().contains("certificate authentication failed"),
                refused.getMessage());
    }

    /** The right name from the wrong issuer does not get past the handshake. */
    @Test
    void theRightNameFromAnotherIssuerIsRefused() {
        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url("certuser", "forged")).close());
        // The server's alert is usually lost to the reset that follows it,
        // so the driver has to name the certificate itself.
        assertTrue(refused.getMessage().contains("right after the client certificate was sent"),
                refused.getMessage());
    }

    /** No certificate at all, where the server demands one. */
    @Test
    void noCertificateIsRefusedByTheServer() {
        String url = "jdbc:seclume:postgresql://" + server.host() + ":" + server.port()
                + "/certdb?user=certuser&tls=require&tlsStack=seclume&provider=none";
        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url).close());
        assertEquals("28000", refused.getSQLState(), refused.getMessage());
    }

    /**
     * {@code provider=none} where the server wants a password: refused here,
     * before anything is sent, with the reason in the message.
     */
    @Test
    void noneWhereThePasswordIsDemandedFailsHereAndSaysWhy() {
        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url("postgres", "certuser")).close());
        assertEquals("28000", refused.getSQLState(), refused.getMessage());
        assertTrue(refused.getMessage().contains("provider=none"), refused.getMessage());
        assertTrue(refused.getMessage().contains("nothing was sent"), refused.getMessage());
    }

    private static String url(String user, String certificate) {
        return "jdbc:seclume:postgresql://" + server.host() + ":" + server.port()
                + "/certdb?user=" + user
                + "&tls=require&tlsStack=seclume&provider=none"
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
