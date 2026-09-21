package space.seclume.oracle.jdbc;

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

import space.seclume.oracle.OracleSession;

/**
 * Oracle over TCPS, on both TLS stacks.
 *
 * <p>The last of the four to be proven on seclume's own TLS, and the one that
 * was held up by a fixture rather than by anything in the driver: Oracle does
 * not negotiate encryption the way PostgreSQL and MySQL do. There is nothing
 * to ask for. A TCPS listener expects the handshake as the <b>first</b> thing
 * on the socket and never speaks the protocol in the clear; a TCP listener
 * never speaks TLS. So this needs a second listener, and until there was one
 * the Oracle path was written the same way as the other two and unproven.
 *
 * <p><b>What each case is for.</b> That a whole session runs on the own
 * stack, asserted on the description because both stacks negotiate the same
 * suite against the same server and "TLSv1.3" alone would prove nothing about
 * who provided it; that the JDK's TLS reaches the same listener, so the
 * choice is a choice; and that {@code verify-full} refuses a certificate
 * nobody vouches for, which is the half that would otherwise pass while
 * authenticating nothing.
 *
 * <p>A separate container on port 2484 - see TESTING.md. Without it these
 * skip.
 */
@Timeout(120)
class LocalOracleTlsTest {

    private static final String HOST =
            System.getProperty("seclume.oracle.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.oracle.tcps.port", 2484);
    private static final String SERVICE =
            System.getProperty("seclume.oracle.service", "FREEPDB1");
    private static Path password;

    @BeforeAll
    static void findTheListener() {
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-oracle-password");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no Oracle TCPS listener on " + HOST + ":" + PORT
                    + " - see TESTING.md, 'Oracle over TCPS'");
        }
    }

    /**
     * The wallet's certificate is self-signed, so verification is off in the
     * two positive cases and named as what it is.
     */
    private static String url(String extra) {
        return "jdbc:seclume:oracle://" + HOST + ":" + PORT + "/" + SERVICE
                + "?user=seclume_test&provider=file&path="
                + password.toString().replace(java.io.File.separatorChar, '/') + extra;
    }

    @Test
    void carriesAWholeSessionOnOurOwnTls() throws Exception {
        try (Connection connection = DriverManager.getConnection(
                url("&tls=require&tlsStack=seclume"))) {
            String tls = describe(connection);
            System.err.println("[tcps, own stack] " + tls);
            assertNotNull(tls, "a TCPS listener is encrypted by construction");
            assertTrue(tls.startsWith("TLSv1.3 / TLS_AES_"),
                    "the own stack speaks TLS 1.3 and two suites; it reported: " + tls);
            // Without the marker a silent fall back to JSSE would read as a
            // pass: both stacks negotiate the same suite against this server.
            assertTrue(tls.endsWith(" (seclume)"),
                    "this connection was not carried by our own stack: " + tls);

            try (Statement statement = connection.createStatement();
                    ResultSet rows = statement.executeQuery(
                            "select 42, sys_context('userenv', 'network_protocol') from dual")) {
                assertTrue(rows.next());
                assertEquals(42, rows.getInt(1));
                // Oracle's own opinion of the connection, which is worth more
                // than ours: it says tcps only when the listener really did.
                assertEquals("tcps", rows.getString(2));
            }
        }
    }

    /** And the JDK's TLS reaches the same listener. */
    @Test
    void theJdkStackAlsoSpeaksIt() throws Exception {
        try (Connection connection = DriverManager.getConnection(url("&tls=require"));
                Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery("select 1 from dual")) {
            String tls = describe(connection);
            System.err.println("[tcps, jsse] " + tls);
            assertNotNull(tls);
            assertTrue(!tls.endsWith(" (seclume)"), "jsse was asked for and " + tls + " answered");
            assertTrue(rows.next());
        }
    }

    /**
     * Self-signed, so verify-full has to refuse it - on the own stack as on
     * the other, because a mode that authenticates and still accepts anything
     * is worse than no mode at all.
     */
    @Test
    void verifyFullRefusesTheSelfSignedCertificate() {
        for (String stack : new String[] {"", "&tlsStack=seclume"}) {
            SQLException refused = assertThrows(SQLException.class,
                    () -> DriverManager.getConnection(url("&tls=verify-full" + stack)).close(),
                    "verify-full accepted a certificate nobody signed" + stack);
            System.err.println("[tcps] verify-full" + stack + ": " + refused.getMessage());
        }
    }

    private static String describe(Connection connection) throws SQLException {
        return connection.unwrap(OracleSession.class).tlsDescription();
    }
}
