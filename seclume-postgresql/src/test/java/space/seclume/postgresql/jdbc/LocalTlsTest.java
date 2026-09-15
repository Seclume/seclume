package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.internal.jdbc.TlsMode;
import space.seclume.postgresql.PgSession;
import space.seclume.secret.SecretProviders;

/**
 * TLS against the local PostgreSQL.
 *
 * <p>Whether it encrypts depends on the server: one built without a
 * certificate answers the request with „no", and that answer is a result and
 * not a failure. The test therefore reports what the server said rather than
 * demanding one of the two.
 */
class LocalTlsTest {

    private static final String HOST = System.getProperty("seclume.pg.host", "127.0.0.1");
    private static final int PORT = Integer.getInteger("seclume.pg.port", 5432);
    private static Path password;

    @BeforeAll
    static void findThePassword() {
        for (Path candidate : List.of(Path.of(".local-pg-password"),
                Path.of("..", ".local-pg-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-pg-password");
    }

    /**
     * A stopped container is a skip, not a failure.
     *
     * <p>The password file outliving the container is the normal case here -
     * these are throwaway servers that get stopped between sessions. Checking
     * only for the file turned that into a red build, which is what every
     * other local test in this repository already avoids by dialling the port
     * first.
     */
    private static void requireReachable(String host, int port) {
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), 2000);
        } catch (java.io.IOException e) {
            Assumptions.abort("no TLS server on " + host + ":" + port);
        }
    }

    private static PgSession.Settings settings(TlsMode mode) throws SQLException {
        return new PgSession.Settings(HOST, PORT, "seclume_test", "seclume_test",
                SecretProviders.of(java.util.Map.of("provider", "file", "path", password.toString())), "seclume", 5_000,
                space.seclume.internal.jdbc.HostList.of(HOST, PORT),
                space.seclume.internal.jdbc.ResultLimit.NONE, mode);
    }

    /** What the server answers, and that a connection stands either way. */
    @Test
    void saysWhetherTheServerOffersTls() throws Exception {
        try (PgSession session = PgSession.open(settings(TlsMode.PREFER))) {
            String tls = session.tlsDescription();
            System.err.println("[tls] server " + HOST + ":" + PORT + " -> "
                    + (tls == null ? "no TLS offered" : tls));
            session.execute("select 1");   // the connection has to work either way
        }
    }

    /**
     * The handshake itself, against a server that really offers TLS.
     *
     * <p>Skipped when there is none: a negotiation that always ends in „no"
     * proves the negotiation and nothing about TLS.
     */
    @Test
    void speaksTlsWhenTheServerOffersIt() throws Exception {
        Path secret = null;
        for (Path candidate : List.of(Path.of(".local-pgtls-password"),
                Path.of("..", ".local-pgtls-password"))) {
            if (Files.exists(candidate)) {
                secret = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(secret != null, "no TLS server configured");
        String host = System.getProperty("seclume.pgtls.host", "db.example.invalid");
        int port = Integer.getInteger("seclume.pgtls.port", 5433);
        requireReachable(host, port);

        PgSession.Settings require = new PgSession.Settings(host, port, "seclume_test",
                "seclume_test",
                SecretProviders.of(java.util.Map.of("provider", "file", "path",
                        secret.toString())),
                "seclume", 5_000,
                space.seclume.internal.jdbc.HostList.of(host, port),
                space.seclume.internal.jdbc.ResultLimit.NONE, TlsMode.REQUIRE);

        try (PgSession session = PgSession.open(require)) {
            String tls = session.tlsDescription();
            System.err.println("[tls] " + host + ":" + port + " -> " + tls);
            assertTrue(tls != null, "tls=require has to end up encrypted");
            assertTrue(tls.startsWith("TLSv1.3") || tls.startsWith("TLSv1.2"),
                    "unexpected protocol: " + tls);
            session.execute("select 1");
        }
    }

    /**
     * SCRAM-SHA-256-PLUS: the login is bound to this connection.
     *
     * <p>The check that matters is not „no exception" - a login with a wrong
     * binding fails, but so does a login with a wrong password, and both say
     * the same thing. What is asserted is that the client actually chose the
     * bound mechanism, because a client that quietly fell back to plain SCRAM
     * would pass a „did it connect" test every time.
     *
     * <p>That the binding is <b>right</b> is the server's verdict: PostgreSQL
     * recomputes the fingerprint from its own certificate and compares. A
     * wrong hash or a wrong GS2 header ends the login here, not later.
     */
    @Test
    void bindsTheLoginToTheConnection() throws Exception {
        Path secret = null;
        for (Path candidate : List.of(Path.of(".local-pgtls-password"),
                Path.of("..", ".local-pgtls-password"))) {
            if (Files.exists(candidate)) {
                secret = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(secret != null, "no TLS server configured");
        String host = System.getProperty("seclume.pgtls.host", "db.example.invalid");
        int port = Integer.getInteger("seclume.pgtls.port", 5433);
        requireReachable(host, port);

        PgSession.Settings require = new PgSession.Settings(host, port, "seclume_test",
                "seclume_test",
                SecretProviders.of(java.util.Map.of("provider", "file", "path",
                        secret.toString())),
                "seclume", 5_000,
                space.seclume.internal.jdbc.HostList.of(host, port),
                space.seclume.internal.jdbc.ResultLimit.NONE, TlsMode.REQUIRE);

        try (PgSession session = PgSession.open(require)) {
            System.err.println("[binding] " + session.channelBinding());
            assertTrue("used".equals(session.channelBinding()),
                    "the client did not bind the login: " + session.channelBinding());
            session.execute("select 1");
        }
    }

    /**
     * Without TLS the client says {@code n} - it could not bind even if it
     * wanted to, and claiming otherwise would be the one lie the GS2 header
     * exists to prevent.
     */
    @Test
    void saysItCannotBindWithoutTls() throws Exception {
        try (PgSession session = PgSession.open(settings(TlsMode.OFF))) {
            Assumptions.assumeTrue(session.tlsDescription() == null);
            System.err.println("[binding] without tls -> " + session.channelBinding());
            assertTrue("not-possible".equals(session.channelBinding()),
                    session.channelBinding());
        }
    }

    /**
     * And the other half of the promise: verify-full refuses a certificate
     * nobody vouches for. The container's is self-signed, so this has to fail -
     * a mode that authenticates and still accepts anything would be worse than
     * no mode at all.
     */
    @Test
    void verifyFullRefusesASelfSignedCertificate() throws Exception {
        Path secret = null;
        for (Path candidate : List.of(Path.of(".local-pgtls-password"),
                Path.of("..", ".local-pgtls-password"))) {
            if (Files.exists(candidate)) {
                secret = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(secret != null, "no TLS server configured");
        String host = System.getProperty("seclume.pgtls.host", "db.example.invalid");
        int port = Integer.getInteger("seclume.pgtls.port", 5433);
        requireReachable(host, port);

        PgSession.Settings verify = new PgSession.Settings(host, port, "seclume_test",
                "seclume_test",
                SecretProviders.of(java.util.Map.of("provider", "file", "path",
                        secret.toString())),
                "seclume", 5_000,
                space.seclume.internal.jdbc.HostList.of(host, port),
                space.seclume.internal.jdbc.ResultLimit.NONE, TlsMode.VERIFY_FULL);

        SQLException refused = org.junit.jupiter.api.Assertions.assertThrows(
                SQLException.class, () -> PgSession.open(verify).close());
        System.err.println("[tls] verify-full: " + refused.getMessage());
    }

    /** The same through the URL, which is how an application says it. */
    @Test
    void theUrlCarriesTheMode() throws Exception {
        Path secret = null;
        for (Path candidate : List.of(Path.of(".local-pgtls-password"),
                Path.of("..", ".local-pgtls-password"))) {
            if (Files.exists(candidate)) {
                secret = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(secret != null, "no TLS server configured");
        String url = "jdbc:seclume:postgresql://db.example.invalid:5433/seclume_test"
                + "?user=seclume_test&provider=file&path="
                + secret.toString().replace(java.io.File.separatorChar, '/')
                + "&tls=require";
        try (java.sql.Connection connection = java.sql.DriverManager.getConnection(url);
             java.sql.Statement statement = connection.createStatement();
             java.sql.ResultSet rows = statement.executeQuery("select 1")) {
            assertTrue(rows.next());
        }
    }

    /** An unknown mode is refused rather than quietly treated as off. */
    @Test
    void refusesAnUnknownMode() {
        org.junit.jupiter.api.Assertions.assertThrows(SQLException.class,
                () -> TlsMode.of("sortof"));
    }

    /** Without TLS the connection still stands - that is what off means. */
    @Test
    void worksWithoutTls() throws Exception {
        try (PgSession session = PgSession.open(settings(TlsMode.OFF))) {
            assertTrue(session.tlsDescription() == null, "off must not negotiate");
            session.execute("select 1");
        }
    }
}
