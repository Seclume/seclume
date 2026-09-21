package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.mysql.MySession;
import space.seclume.secret.SecretProviders;

/**
 * The MySQL driver on seclume's own TLS 1.3 stack.
 *
 * <p>The second server, and it is a different peer in every way that could
 * matter: MySQL's TLS is OpenSSL rather than the PostgreSQL build's, the
 * negotiation that precedes it is MySQL's own, and the login afterwards is
 * {@code caching_sha2_password} instead of SCRAM. A TLS client that works
 * against one server and not the other is common; that is what a second peer
 * is for.
 *
 * <p>What makes this the interesting one: inside TLS, MySQL sends the password
 * itself rather than going through the RSA detour that an unencrypted
 * connection needs. So the login here is only possible <em>because</em> the
 * channel is really encrypted - the server would refuse it otherwise. That is
 * a stronger statement than any assertion in this file.
 *
 * <p>Skipped where there is no server.
 */
@Timeout(120)
class LocalMyOwnTlsStackTest {

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
        } catch (IOException unreachable) {
            Assumptions.abort("no MySQL on " + HOST + ":" + PORT);
        }
    }

    private static MySession.Settings settings(TlsMode mode, TlsStack stack) throws SQLException {
        return new MySession.Settings(HOST, PORT, "seclume_test", "seclume_test",
                SecretProviders.of(Map.of("provider", "file", "path", password.toString())),
                "seclume", 5_000, false, HostList.of(HOST, PORT), ResultLimit.NONE, mode, stack);
    }

    @Test
    void carriesAWholeSessionOnOurOwnTls() throws Exception {
        try (MySession session = MySession.open(settings(TlsMode.REQUIRE, TlsStack.SECLUME))) {
            String tls = session.tlsDescription();
            System.err.println("[own stack] " + HOST + ":" + PORT + " -> " + tls);
            assertNotNull(tls, "tls=require connected without encryption");
            assertTrue(tls.startsWith("TLSv1.3 / TLS_AES_"), tls);
            // Both stacks agree on TLS 1.3 against this server, so without the
            // marker a silent fall back to JSSE would read as a pass.
            assertTrue(tls.endsWith(" (seclume)"),
                    "this connection was not carried by our own stack: " + tls);
            session.execute("select 1");
        }
    }

    /**
     * Without {@code allowPublicKeyRetrieval} and without a cached password,
     * this login only completes over a genuinely encrypted channel.
     */
    @Test
    void theLoginItselfDependsOnTheEncryption() throws Exception {
        try (MySession session = MySession.open(settings(TlsMode.REQUIRE, TlsStack.SECLUME))) {
            session.execute("select user()");
        }
    }

    /** Self-signed by the server at first start, so verify-full has to refuse it. */
    @Test
    void verifyFullRefusesTheSelfSignedCertificate() throws Exception {
        MySession.Settings verify = settings(TlsMode.VERIFY_FULL, TlsStack.SECLUME);
        SQLException refused = assertThrows(SQLException.class,
                () -> MySession.open(verify).close());
        System.err.println("[own stack] verify-full: " + refused.getMessage());
    }

    /** Both stacks, same server, and each says which one carried it. */
    @Test
    void bothStacksReachTheSameServer() throws Exception {
        for (TlsStack stack : TlsStack.values()) {
            try (MySession session = MySession.open(settings(TlsMode.REQUIRE, stack))) {
                String tls = session.tlsDescription();
                System.err.println("[" + stack + "] " + tls);
                assertNotNull(tls, stack + " did not encrypt");
                assertEquals(stack == TlsStack.SECLUME, tls.endsWith(" (seclume)"),
                        stack + " was asked for and " + tls + " answered");
                session.execute("select 1");
            }
        }
    }

    /** How an application actually asks for it. */
    @Test
    void theUrlCarriesTheStack() throws Exception {
        String url = "jdbc:seclume:mysql://" + HOST + ":" + PORT + "/seclume_test"
                + "?user=seclume_test&provider=file&path="
                + password.toString().replace(File.separatorChar, '/')
                + "&tls=require&tlsStack=seclume";
        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery("select 42")) {
            assertTrue(rows.next());
            assertEquals(42, rows.getInt(1));
        }
    }
}
