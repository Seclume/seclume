package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.internal.TrustChoice;

/**
 * SQL Server's default TDS 7.4 handshake keeps the same trust as every other
 * connection: tlsPin is compared, tlsRootCert is used, and the certificate has
 * to name the host. It used to take the JVM's default context with no host
 * name check and to ignore both options (found in review, 25.09.2026).
 */
class LocalTds74TrustTest {

    private static final String HOST =
            System.getProperty("seclume.mssql.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mssql.port", 1433);

    private static Path password;
    private static X509Certificate serverCertificate;

    @BeforeAll
    static void findTheServer() throws Exception {
        for (Path candidate : List.of(Path.of(".local-mssql-password"),
                Path.of("..", ".local-mssql-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mssql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no SQL Server on " + HOST + ":" + PORT);
        }
        // The certificate as the server presents it, taken with no check -
        // only to learn its key and its names.
        try (TdsChannel channel = TdsChannel.connect(HOST, PORT, 10_000)) {
            new PreLogin().exchange(channel, Tds.ENCRYPT_ON);
            TdsTls tls = TdsTls.create(channel.raw(), HOST, PORT, true);
            tls.handshake();
            serverCertificate = tls.peerCertificate();
        }
        assertNotNull(serverCertificate);
    }

    private static String url(String options) {
        return "jdbc:seclume:sqlserver://" + HOST + ":" + PORT + "/master?user=sa"
                + options + "&provider=file&path=" + password.toString().replace('\\', '/');
    }

    @Test
    void theRightPinIsTheTrust() throws Exception {
        String pin = TrustChoice.pinOf(serverCertificate).replace("+", "%2B");
        try (Connection connection = DriverManager.getConnection(url("&tlsPin=" + pin))) {
            assertTrue(connection.isValid(5));
        }
    }

    @Test
    void aWrongPinIsRefusedEvenWithTrustServerCertificate() {
        String wrong = "sha256/" + Base64.getEncoder().encodeToString(new byte[32]);
        SQLException refused = assertThrows(SQLException.class, () -> DriverManager.getConnection(
                url("&trustServerCertificate=true&tlsPin=" + wrong)).close());
        assertTrue(String.valueOf(causes(refused)).contains("not the pinned one"),
                String.valueOf(causes(refused)));
    }

    /**
     * tlsRootCert makes the chain trusted - so what refuses a certificate
     * that does not name the address dialled is the host name check, which
     * this path did not have.
     */
    @Test
    void aTrustedCertificateMustStillNameTheHost(@TempDir Path directory) throws Exception {
        Path root = directory.resolve("server.pem");
        Files.writeString(root, "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII))
                        .encodeToString(serverCertificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n");
        String rootOption = "&tlsRootCert=" + root.toString().replace('\\', '/');
        boolean namesTheHost = names(serverCertificate, HOST);
        if (namesTheHost) {
            try (Connection connection = DriverManager.getConnection(url(rootOption))) {
                assertTrue(connection.isValid(5));
            }
            return;
        }
        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url(rootOption)).close());
        String why = String.valueOf(causes(refused));
        assertFalse(why.contains("PKIX path building failed"),
                "the chain was not trusted, so tlsRootCert was ignored: " + why);
        assertTrue(why.contains("subject alternative") || why.contains("No name matching")
                || why.contains("hostname"), "expected a host name refusal: " + why);
    }

    private static boolean names(X509Certificate certificate, String host) throws Exception {
        if (certificate.getSubjectAlternativeNames() != null) {
            for (List<?> name : certificate.getSubjectAlternativeNames()) {
                if (host.equalsIgnoreCase(String.valueOf(name.get(1)))) {
                    return true;
                }
            }
        }
        return false;
    }

    private static StringBuilder causes(Throwable thrown) {
        StringBuilder text = new StringBuilder();
        for (Throwable t = thrown; t != null; t = t.getCause()) {
            text.append(t.getMessage()).append(" | ");
        }
        return text;
    }
}
