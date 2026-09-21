package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
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
import java.util.Map;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.postgresql.PgSession;
import space.seclume.secret.SecretProviders;
import space.seclume.tck.TestHosts;

/**
 * The driver on seclume's own TLS 1.3 stack, against a real server.
 *
 * <p>Until now the two halves stood apart. The TLS client was proven against
 * JSSE, against the RFC 8448 vectors and against a PostgreSQL socket - but
 * nothing above it was a driver. The drivers were proven against real servers
 * - but always through an {@code SSLEngine}. This is the join, and it is the
 * whole of S8: the same session code, the same login, the same query, with
 * the encryption underneath swapped for ours.
 *
 * <p><b>What each test here is actually for.</b>
 *
 * <ul>
 *   <li><b>The query</b> proves the channel carries a full conversation in
 *       both directions, not just a handshake - startup, authentication,
 *       parameter status, a result and a close;
 *   <li><b>the channel binding</b> proves the certificate survived the swap.
 *       It is the one thing above TLS that reaches back into it, and it is
 *       the part that would have broken silently: a client that cannot find
 *       the certificate falls back to unbound SCRAM and still logs in. The
 *       assertion is therefore on the mechanism chosen, never on „it
 *       connected";
 *   <li><b>verify-full</b> proves the trust half is really wired, because the
 *       fixture's certificate is self-signed and a stack that authenticates
 *       nothing would pass every other test in this class;
 *   <li><b>the two stacks side by side</b> prove that the choice is a choice -
 *       same server, same query, same answer, and each says which one carried
 *       it.
 * </ul>
 *
 * <p>Skipped where there is no TLS server, like every other local test here.
 */
@Timeout(120)
class LocalOwnTlsStackTest {

    private static final int PORT = Integer.getInteger("seclume.pgtls.port", 5433);

    private static String host() {
        return System.getProperty("seclume.pgtls.host", TestHosts.database());
    }

    private static Path secret() {
        for (Path candidate : List.of(Path.of(".local-pgtls-password"),
                Path.of("..", ".local-pgtls-password"))) {
            if (Files.exists(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    /** A stopped container is a skip; an unreachable one that is configured is too. */
    private static Path fixture() {
        Path secret = secret();
        Assumptions.assumeTrue(secret != null, "no TLS server configured");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host(), PORT), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no TLS server on " + host() + ":" + PORT);
        }
        return secret;
    }

    private static PgSession.Settings settings(Path secret, TlsMode mode, TlsStack stack)
            throws SQLException {
        return new PgSession.Settings(host(), PORT, "seclume_test", "seclume_test",
                SecretProviders.of(Map.of("provider", "file", "path", secret.toString())),
                "seclume", 5_000, HostList.of(host(), PORT), ResultLimit.NONE, mode, stack);
    }

    @Test
    void carriesAWholeSessionOnOurOwnTls() throws Exception {
        Path secret = fixture();
        try (PgSession session = PgSession.open(settings(secret, TlsMode.REQUIRE,
                TlsStack.SECLUME))) {
            String tls = session.tlsDescription();
            System.err.println("[own stack] " + host() + ":" + PORT + " -> " + tls);
            assertTrue(tls != null, "tls=require has to end up encrypted");
            assertTrue(tls.startsWith("TLSv1.3 / TLS_AES_"),
                    "this stack speaks TLS 1.3 and two suites; it reported: " + tls);
            // Without this the test would pass on JSSE too - it negotiates the
            // same protocol and the same suite against the same server, so
            // „TLSv1.3" proves encryption and nothing about who provided it.
            assertTrue(tls.endsWith(" (seclume)"),
                    "this connection was not carried by our own stack: " + tls);
            session.execute("select 1");
        }
    }

    /**
     * SCRAM-SHA-256-PLUS over our own records.
     *
     * <p>The binding hashes the server's certificate, so this fails unless
     * the handshake kept it - and it fails the right way round: PostgreSQL
     * recomputes the fingerprint from its own certificate and ends the login
     * if it disagrees. What is asserted here is the client's own choice of
     * mechanism, because falling back to unbound SCRAM would still connect.
     */
    @Test
    void bindsTheLoginToOurOwnConnection() throws Exception {
        Path secret = fixture();
        try (PgSession session = PgSession.open(settings(secret, TlsMode.REQUIRE,
                TlsStack.SECLUME))) {
            System.err.println("[own stack] binding -> " + session.channelBinding());
            assertEquals("used", session.channelBinding(),
                    "the login was not bound to the connection");
            session.execute("select 1");
        }
    }

    /** Self-signed, so verify-full has to refuse it here exactly as it does on JSSE. */
    @Test
    void verifyFullRefusesTheSelfSignedCertificate() throws Exception {
        Path secret = fixture();
        PgSession.Settings verify = settings(secret, TlsMode.VERIFY_FULL, TlsStack.SECLUME);
        SQLException refused = assertThrows(SQLException.class,
                () -> PgSession.open(verify).close());
        System.err.println("[own stack] verify-full: " + refused.getMessage());
    }

    /**
     * Both stacks, one after the other, same answer.
     *
     * <p>The point is not that 1 equals 1. It is that nothing above the TLS
     * layer notices which one it is sitting on - and that both really ran,
     * which is why each prints what it negotiated.
     */
    @Test
    void bothStacksReachTheSameServer() throws Exception {
        Path secret = fixture();
        for (TlsStack stack : TlsStack.values()) {
            try (PgSession session = PgSession.open(settings(secret, TlsMode.REQUIRE, stack))) {
                String tls = session.tlsDescription();
                System.err.println("[" + stack + "] " + tls);
                assertTrue(tls != null, stack + " did not encrypt");
                assertEquals(stack == TlsStack.SECLUME, tls.endsWith(" (seclume)"),
                        stack + " was asked for and " + tls + " answered");
                session.execute("select 1");
            }
        }
    }

    /** How an application actually asks for it. */
    @Test
    void theUrlCarriesTheStack() throws Exception {
        Path secret = fixture();
        String url = "jdbc:seclume:postgresql://" + host() + ":" + PORT + "/seclume_test"
                + "?user=seclume_test&provider=file&path="
                + secret.toString().replace(File.separatorChar, '/')
                + "&tls=require&tlsStack=seclume";
        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery("select 42")) {
            assertTrue(rows.next());
            assertEquals(42, rows.getInt(1));
        }
    }

    /** An unknown stack is refused rather than quietly treated as the default. */
    @Test
    void refusesAnUnknownStack() {
        assertThrows(SQLException.class, () -> TlsStack.of("homemade"));
    }
}
