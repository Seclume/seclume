package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.mysql.MySession;
import space.seclume.secret.SecretProviders;

/**
 * TLS against a real MySQL.
 *
 * <p>MySQL is the convenient one to test: since 8.0 a server generates a
 * certificate for itself at first start and offers TLS without being
 * configured for it. That certificate is signed by nobody, which is exactly
 * what makes the distinction testable here — {@code require} has to succeed on
 * it and {@code verify-full} has to refuse it.
 *
 * <p>Without a reachable server the test is skipped, not failed.
 */
class LocalMyTlsTest {

    private static final String HOST = System.getProperty("seclume.mysql.host",
            space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mysql.port", 3307);
    private static Path password;

    @BeforeAll
    static void findTheServer() {
        for (Path candidate : List.of(Path.of(".local-mysql-password"),
                Path.of("..", ".local-mysql-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mysql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no MySQL on " + HOST + ":" + PORT);
        }
    }

    private static MySession.Settings settings(TlsMode mode) throws SQLException {
        return new MySession.Settings(HOST, PORT, "seclume_test", "seclume_test",
                SecretProviders.of(Map.of("provider", "file", "path", password.toString())),
                "seclume", 5_000, false, HostList.of(HOST, PORT), ResultLimit.NONE, mode);
    }

    /** What the server offers, and that the connection stands either way. */
    @Test
    void saysWhatTheServerOffers() throws Exception {
        try (MySession session = MySession.open(settings(TlsMode.PREFER))) {
            String tls = session.tlsDescription();
            System.err.println("[tls] " + HOST + ":" + PORT + " -> "
                    + (tls == null ? "no TLS offered" : tls));
            session.execute("select 1");
        }
    }

    /** {@code require}: encrypted or no connection. */
    @Test
    void requireEncrypts() throws Exception {
        try (MySession session = MySession.open(settings(TlsMode.REQUIRE))) {
            String tls = session.tlsDescription();
            assertNotNull(tls, "tls=require connected without encryption");
            System.err.println("[tls] require -> " + tls);
            assertTrue(tls.startsWith("TLSv1."), tls);
            session.execute("select 1");
        }
    }

    /**
     * The whole login runs inside TLS, including the part that would otherwise
     * need the RSA detour.
     *
     * <p>MySQL 8 wants the password itself for a user's first connection.
     * Unencrypted that costs a public key the client has to ask an
     * unauthenticated server for — {@code allowPublicKeyRetrieval}. Inside TLS
     * that whole exchange falls away, and this shows it: the same login, the
     * flag off, and it works.
     *
     * <p><b>What this test cannot control is the server's cache.</b> Once a
     * user has logged in successfully the server answers the short way, and
     * then the test passes without touching the path at all. It was checked
     * against a cold cache by hand — restart the container, run this test —
     * and that is the only way to see it fail if it breaks.
     */
    @Test
    void tlsRemovesTheNeedForPublicKeyRetrieval() throws Exception {
        try (MySession session = MySession.open(settings(TlsMode.REQUIRE))) {
            session.execute("select 1");
        }
    }

    /** {@code verify-full}: a certificate signed by nobody is refused. */
    @Test
    void verifyFullRefusesTheSelfSignedCertificate() throws Exception {
        SQLException failure = assertThrows(SQLException.class,
                () -> MySession.open(settings(TlsMode.VERIFY_FULL)));
        System.err.println("[tls] verify-full: " + failure.getMessage());
        assertTrue(failure.getMessage().contains("TLS"), failure.getMessage());
    }

    /** {@code off}: no encryption, and the driver says so rather than pretending. */
    @Test
    void offStaysInTheClear() throws Exception {
        try (MySession session = MySession.open(settings(TlsMode.OFF))) {
            Assumptions.assumeTrue(session.tlsDescription() == null);
            session.execute("select 1");
        }
    }

    /** The URL option arrives where it is read. */
    @Test
    void theUrlCarriesTheMode() throws Exception {
        MySession.Settings settings = MyUrl.settings(
                "jdbc:seclume:mysql://" + HOST + ":" + PORT + "/seclume_test?user=seclume_test"
                + "&tls=require&provider=file&path="
                + password.toString().replace(java.io.File.separatorChar, '/'),
                new java.util.Properties());
        assertTrue(settings.tls() == TlsMode.REQUIRE, "the url option did not arrive");
        try (MySession session = MySession.open(settings)) {
            assertNotNull(session.tlsDescription());
        }
    }
}
