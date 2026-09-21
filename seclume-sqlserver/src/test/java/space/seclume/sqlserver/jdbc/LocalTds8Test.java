package space.seclume.sqlserver.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.sqlserver.tds.TdsVersion;

/**
 * TDS 8.0 - TLS around the whole connection, from the first byte.
 *
 * <p>This is the one thing that was structurally out of reach for SQL Server.
 * Under TDS 7.4 the handshake runs <em>inside</em> pre-login packets and the
 * nesting inverts afterwards, a shape that is TLS 1.2 by construction -
 * TLS 1.3 moves handshake messages past the point where the inversion would
 * have to happen. So this driver could never use seclume's own TLS stack, and
 * therefore never present a client certificate whose private key stays off
 * the heap. TDS 8.0 removes the nesting and with it the obstacle.
 *
 * <p><b>What each case is for.</b> That the connection stands at all; that it
 * really ran on the own stack rather than quietly falling back, which is
 * asked of the description because both stacks negotiate the same suite
 * against the same server; that the JDK's TLS reaches the same server the
 * same way, so the choice is a choice; and that the whole thing is reachable
 * from a connection string, which is how anybody will actually use it.
 *
 * <p>Needs SQL Server 2022 or later. An older server refuses the connection
 * rather than falling back, which is correct and is why the default stays
 * 7.4 - so this skips where the version is not there rather than failing.
 */
@Timeout(120)
class LocalTds8Test {

    private static final String HOST =
            System.getProperty("seclume.mssql.host", space.seclume.tck.TestHosts.database());
    /**
     * A server of its own, and not the one the rest of the suite uses.
     *
     * <p>Strict encryption turned out to need <b>SQL Server 2025</b>: the 2022
     * Linux container refuses a TLS-first connection whatever certificate it
     * is given, and Microsoft's own driver fails against it identically. So
     * this points at a second container rather than at the shared fixture -
     * which also keeps the 7.4 case here honest, because it runs against the
     * same 2025 server and shows the old nesting still works there.
     */
    private static final int PORT = Integer.getInteger("seclume.mssql8.port", 1435);
    private static Path password;

    @BeforeAll
    static void findTheServer() {
        for (Path candidate : List.of(Path.of(".local-mssql-password"),
                Path.of("..", ".local-mssql-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mssql-password");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no SQL Server on " + HOST + ":" + PORT);
        }
    }

    /**
     * Does this server accept TLS before any TDS byte at all.
     *
     * <p>Asked with a plain {@code SSLSocket}, so that the answer is about
     * the <b>server</b> and not about anything in this driver. Strict
     * encryption needs a certificate provisioned through {@code mssql-conf}
     * ({@code network.tlscert} and {@code network.tlskey}); the certificate a
     * container generates for itself serves the nested 7.4 handshake and not
     * this one. Where that has not been done the server closes the
     * connection during the handshake, and these cases skip with a message
     * saying so rather than failing - a fixture that has not been configured
     * is not a defect in the driver.
     */
    private static void requireStrictEncryption() {
        try {
            javax.net.ssl.SSLContext context = javax.net.ssl.SSLContext.getInstance("TLS");
            context.init(null, new javax.net.ssl.TrustManager[] {new TrustAnything()}, null);
            java.net.Socket plain = new java.net.Socket();
            plain.connect(new InetSocketAddress(HOST, PORT), 3000);
            try (javax.net.ssl.SSLSocket ssl = (javax.net.ssl.SSLSocket)
                    context.getSocketFactory().createSocket(plain, HOST, PORT, true)) {
                ssl.startHandshake();
            }
        } catch (Exception refused) {
            Assumptions.abort("this SQL Server does not accept TLS before TDS. Provisioning a "
                    + "certificate through mssql-conf was tried and is not enough on the "
                    + "2022 Linux container - see TESTING.md, 'TDS 8.0 and the server that "
                    + "would not have it'. It answered: " + refused);
        }
    }

    /** The container signs its own certificate; verification is off throughout here. */
    private static final class TrustAnything implements javax.net.ssl.X509TrustManager {
        @Override
        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String type) {
        }

        @Override
        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String type) {
        }

        @Override
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[0];
        }
    }

    /**
     * The container's certificate is signed by nobody, so verification is off
     * here and named as what it is - the same choice every other test in this
     * module makes against the same server.
     */
    private static String url(String extra) {
        return "jdbc:seclume:sqlserver://" + HOST + ":" + PORT + "/master"
                + "?user=sa&trustServerCertificate=true&provider=file&path="
                + password.toString().replace(java.io.File.separatorChar, '/') + extra;
    }

    @Test
    void carriesAWholeSessionOnOurOwnTls() throws Exception {
        requireStrictEncryption();
        try (Connection connection = DriverManager.getConnection(
                url("&tds=8.0&tlsStack=seclume"))) {
            String tls = describe(connection);
            System.err.println("[tds 8.0, own stack] " + tls);
            assertNotNull(tls, "TDS 8.0 is encrypted by construction");
            assertTrue(tls.startsWith("TLSv1.3 / TLS_AES_"),
                    "the own stack speaks TLS 1.3 and two suites; it reported: " + tls);
            // Both stacks negotiate the same protocol and suite against this
            // server, so without the marker a silent fall back to JSSE would
            // read as a pass.
            assertTrue(tls.endsWith(" (seclume)"),
                    "this connection was not carried by our own stack: " + tls);

            try (Statement statement = connection.createStatement();
                    ResultSet rows = statement.executeQuery("select 42, @@version")) {
                assertTrue(rows.next());
                assertEquals(42, rows.getInt(1));
                assertNotNull(rows.getString(2));
            }
        }
    }

    /** And the JDK's TLS reaches the same server the same way. */
    @Test
    void theJdkStackAlsoSpeaksIt() throws Exception {
        requireStrictEncryption();
        try (Connection connection = DriverManager.getConnection(url("&tds=8.0"));
                Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery("select 1")) {
            String tls = describe(connection);
            System.err.println("[tds 8.0, jsse] " + tls);
            assertNotNull(tls);
            assertTrue(!tls.endsWith(" (seclume)"), "jsse was asked for and " + tls + " answered");
            assertTrue(rows.next());
        }
    }

    /**
     * 7.4 keeps working, unchanged and still the default.
     *
     * <p>The point of the case is the default: a driver that quietly started
     * requiring SQL Server 2022 would be a worse neighbour than one that asks.
     */
    @Test
    void theOldNestingIsStillTheDefault() throws Exception {
        try (Connection connection = DriverManager.getConnection(url(""))) {
            String tls = describe(connection);
            System.err.println("[tds 7.4, default] " + tls);
            assertNotNull(tls, "7.4 still encrypts, just differently");
            assertTrue(tls.startsWith("TLSv1.2"),
                    "the nested handshake is TLS 1.2 by construction: " + tls);
        }
    }

    /** A spelling nobody uses is refused rather than read as the default. */
    @Test
    void refusesAnUnknownVersion() {
        assertThrows(SQLException.class, () -> TdsVersion.of("9"));
        assertThrows(SQLException.class, () -> DriverManager.getConnection(url("&tds=9")));
    }

    /** Microsoft's word for the same thing is accepted. */
    @Test
    void strictIsTheSameAsEightPointZero() throws Exception {
        requireStrictEncryption();
        assertEquals(TdsVersion.TDS_8_0, TdsVersion.of("strict"));
        try (Connection connection = DriverManager.getConnection(
                url("&tds=strict&tlsStack=seclume"))) {
            assertTrue(describe(connection).endsWith(" (seclume)"));
        }
    }

    /**
     * A client certificate on SQL Server - the thing that was out of reach.
     *
     * <p>Not a full mutual handshake: this server asks for no client
     * certificate, and configuring one to do so is a piece of server
     * administration rather than a driver test. What is asserted is the part
     * that was impossible before - that the identity is <b>carried into the
     * handshake</b> on this driver at all, shown by the one refusal that
     * needs no key: the JDK's TLS cannot present a client certificate
     * without putting its private key on the heap.
     */
    @Test
    void aClientCertificateReachesTheHandshakeNow() {
        // No server needed: the complaint comes out of the URL, before
        // anything is dialled. That is what makes this case cheap enough to
        // have while the strict-encryption fixture is still unconfigured.
        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url("&tds=8.0&clientCert=/etc/tls/nothing.crt")));
        assertTrue(refused.getMessage().contains("clientKey-provider"),
                "the URL did not reach the identity builder: " + refused.getMessage());
    }

    private static String describe(Connection connection) throws SQLException {
        return connection.unwrap(space.seclume.sqlserver.tds.TdsSession.class).tlsDescription();
    }
}
