package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.tck.TestHosts;

/**
 * PostgreSQL 17's direct TLS: {@code tlsNegotiation=direct} starts the
 * handshake at once, with ALPN {@code postgresql}, and the session is
 * encrypted - on both stacks. A server before 17 does not know it, and the
 * connect fails rather than falling back unnoticed.
 *
 * <p>Needs a PostgreSQL 17 or later with TLS: {@code -Dseclume.pg17.port}
 * (and {@code .host}), the password in {@code .local-pgtls-password}.
 */
@Timeout(60)
class LocalDirectTlsTest {

    @ParameterizedTest
    @ValueSource(strings = {"seclume", "jsse"})
    void directTlsReachesAnEncryptedSession(String stack) throws Exception {
        String url = url(Integer.getInteger("seclume.pg17.port", 0),
                "&tls=require&tlsNegotiation=direct&tlsStack=" + stack);
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select ssl, current_setting('server_version_num')::int >= 170000 "
                             + "from pg_stat_ssl where pid = pg_backend_pid()")) {
            rows.next();
            assertEquals("t", rows.getString(1), "not encrypted");
            assertEquals("t", rows.getString(2), "not a PostgreSQL 17");
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"seclume"})
    void aServerBeforeSeventeenRefusesItAudibly(String stack) throws SQLException {
        String url = url(Integer.getInteger("seclume.pgtls.port", 5433),
                "&tls=require&tlsNegotiation=direct&tlsStack=" + stack);
        org.junit.jupiter.api.Assertions.assertTrue(SeclumeUrl.settings(url, null).directTls(),
                "the URL option did not reach the settings");
        assertThrows(SQLException.class, () -> DriverManager.getConnection(url).close());
    }

    private static String url(int port, String options) {
        Assumptions.assumeTrue(port > 0, "no PostgreSQL 17 configured (-Dseclume.pg17.port)");
        String host = System.getProperty("seclume.pg17.host", TestHosts.database());
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-pgtls-password"),
                Path.of("..", ".local-pgtls-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-pgtls-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException e) {
            Assumptions.abort("nothing on " + host + ":" + port);
        }
        return "jdbc:seclume:postgresql://" + host + ":" + port
                + "/seclume_test?user=seclume_test" + options + "&provider=file&path="
                + password.toString().replace('\\', '/');
    }
}
