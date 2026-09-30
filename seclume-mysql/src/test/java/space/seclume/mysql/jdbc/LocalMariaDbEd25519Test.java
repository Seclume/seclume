package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
import org.junit.jupiter.api.io.TempDir;

import space.seclume.tck.NoSecretInHeap;

/**
 * MariaDB's logins by signature against a real server
 * ({@code seclume-mysql/proof/ed25519.sh}): {@code ed_user} through
 * {@code client_ed25519}, {@code parsec_user} through {@code parsec}. The
 * server's own account of the session is asserted, a wrong password is
 * refused, and the heap is searched for the password.
 *
 * <pre>
 *   seclume.mariadb.ed25519.host=db.example.invalid
 *   seclume.mariadb.ed25519.port=3309
 * </pre>
 * The two users' password is expected in {@code .local-mariadb-ed25519-password}.
 */
@Timeout(120)
class LocalMariaDbEd25519Test {

    private static final String HOST = System.getProperty("seclume.mariadb.ed25519.host",
            space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mariadb.ed25519.port", 3309);
    private static Path password;

    @BeforeAll
    static void findTheServer() {
        for (Path candidate : List.of(Path.of(".local-mariadb-ed25519-password"),
                Path.of("..", ".local-mariadb-ed25519-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mariadb-ed25519-password");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no MariaDB with ed25519 and parsec on " + HOST + ":" + PORT
                    + " - see seclume-mysql/proof/ed25519.sh");
        }
    }

    private static String url(String user, Path secret) {
        return "jdbc:seclume:mariadb://" + HOST + ":" + PORT + "/seclume?user=" + user
                + "&tls=disable&provider=file&path=" + secret.toString().replace('\\', '/');
    }

    @Test
    void clientEd25519LogsIn() throws Exception {
        assertLoggedIn("ed_user", "ed25519");
        NoSecretInHeap.assertAbsent(password);
    }

    @Test
    void parsecLogsIn() throws Exception {
        assertLoggedIn("parsec_user", "parsec");
        NoSecretInHeap.assertAbsent(password);
    }

    @Test
    void aWrongPasswordIsRefusedByBoth(@TempDir Path dir) throws Exception {
        Path wrong = dir.resolve("wrong");
        Files.writeString(wrong, "not-the-password");
        for (String user : List.of("ed_user", "parsec_user")) {
            SQLException refused = assertThrows(SQLException.class,
                    () -> DriverManager.getConnection(url(user, wrong)).close());
            assertTrue(refused.getMessage().contains("Access denied"), refused.getMessage());
        }
    }

    private static void assertLoggedIn(String user, String plugin) throws SQLException {
        try (Connection c = DriverManager.getConnection(url(user, password));
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery("select current_user(), json_value(priv, '$.plugin') "
                     + "from mysql.global_priv where concat(user, '@', host) = current_user()")) {
            assertTrue(r.next(), "the server does not show " + user + "'s own row");
            assertEquals(user + "@%", r.getString(1));
            assertEquals(plugin, r.getString(2));
        }
    }
}
