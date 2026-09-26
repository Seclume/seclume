package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.tck.TestHosts;

/**
 * A plain update after a plain select, on one connection.
 *
 * <p>The simple protocol sends a RowDescription only for a statement that has
 * rows, and the session kept the last one it saw. So after
 * {@code select 1} - which is what a pool validates a connection with - a
 * plain {@code delete} looked like a query that had returned rows, and
 * {@code executeUpdate} refused it. Every test of the driver itself used
 * prepared statements or a fresh connection there; the Spring JDBC suite,
 * running {@code JdbcTemplate.update} on pooled connections, found it at once.
 */
class PlainUpdateAfterSelectTest {

    private static String url;

    @BeforeAll
    static void server() {
        String host = TestHosts.postgres();
        int port = TestHosts.postgresPort();
        Path password = null;
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no PostgreSQL password file");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no PostgreSQL on " + host + ":" + port);
        }
        url = "jdbc:seclume:postgresql://" + host + ":" + port + "/seclume_test"
                + "?user=seclume_test&tls=off&provider=file&path="
                + password.toString().replace(java.io.File.separatorChar, '/');
    }

    @Test
    void anUpdateAfterASelectIsAnUpdate() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement()) {
            statement.execute("create temporary table zl_after_select (x int)");
            try (ResultSet one = statement.executeQuery("select 1")) {
                one.next();
            }
            assertEquals(0, statement.executeUpdate("delete from zl_after_select"),
                    "a delete after a select");
            try (Statement other = connection.createStatement()) {
                other.executeQuery("select 2").close();
            }
            assertEquals(1, statement.executeUpdate("insert into zl_after_select values (1)"));
            assertFalse(statement.execute("update zl_after_select set x = 2"),
                    "execute reports rows for an update");
            assertEquals(1, statement.getUpdateCount());
        }
    }
}
