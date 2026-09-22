package space.seclume.oracle.jdbc;

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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * A connection that sees more statements than its cache holds survives.
 *
 * <p>The driver keeps a cursor per statement text because a cursor belongs to
 * the session and not to the {@code PreparedStatement} in front of it -
 * without that, a framework that builds a fresh statement object per call
 * makes the server parse afresh every time. The cache is bounded, as every
 * cache must be. <b>What was missing is the other half</b>: the entry that
 * falls out of it was forgotten and not closed, so the server kept the cursor
 * until the session ended and counted it against {@code open_cursors}.
 *
 * <p>So this test does the one thing that shows it: it runs far more distinct
 * statements on one connection than the server allows open cursors. Nothing
 * here asks the driver what it believes - the server decides, by either
 * answering or failing with {@code ORA-01000}.
 *
 * <p>It needs no privileges beyond `v$parameter`, which the test user has;
 * `v$open_cursor` and `v$mystat` it does not, which is why the proof is the
 * behaviour rather than a count.
 */
@Timeout(300)
class CursorReturnTest {

    private String url;

    @BeforeEach
    void findTheServer() throws Exception {
        String host = System.getProperty("seclume.oracle.host", TestHosts.database());
        Assumptions.assumeTrue(host != null, "no Oracle host configured");
        int port = Integer.getInteger("seclume.oracle.port", 1521);
        String service = System.getProperty("seclume.oracle.service", "FREEPDB1");
        String user = System.getProperty("seclume.oracle.user", "seclume_test");
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-oracle-password");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no Oracle on " + host + ":" + port);
        }
        url = "jdbc:seclume:oracle://" + host + ":" + port + "/" + service
                + "?user=" + user + "&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    @Test
    void moreDistinctStatementsThanTheServerAllowsCursors() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            int allowed = openCursors(connection);
            // Twice what the server allows, so a cursor that is never given
            // back cannot be absorbed by a generous setting.
            int statements = allowed * 2;

            try (Statement statement = connection.createStatement()) {
                for (int i = 1; i <= statements; i++) {
                    try (ResultSet rows = statement.executeQuery(
                            "select " + i + " as n from dual")) {
                        assertTrue(rows.next());
                    }
                }
            }

            // And it is still usable afterwards, which ORA-01000 would have
            // ended long before.
            try (Statement statement = connection.createStatement();
                    ResultSet rows = statement.executeQuery("select 1 from dual")) {
                assertTrue(rows.next());
            }
        }
    }

    /**
     * What the server allows - read rather than assumed.
     *
     * <p>The default is three hundred and this instance uses it, but a test
     * that hard-codes the number passes for the wrong reason on a server
     * configured generously: it would simply never reach the limit.
     */
    private static int openCursors(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery(
                        "select value from v$parameter where name = 'open_cursors'")) {
            Assumptions.assumeTrue(rows.next(), "cannot read open_cursors on this server");
            int allowed = rows.getInt(1);
            Assumptions.assumeTrue(allowed > 0 && allowed <= 5000,
                    "open_cursors is " + allowed + " - too large to reach in a test");
            return allowed;
        }
    }
}
