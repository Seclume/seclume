package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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

import space.seclume.internal.jdbc.ConnectionFacts;
import space.seclume.mysql.MySession;

/**
 * The seam a JDBC connection is taken apart at: {@code detach()} under it,
 * {@code facts()} beside it, {@code resume} on the other side. What is built
 * on the seam is not this library's; that the seam holds is.
 */
class LocalDetachSeamTest {

    private static String url;

    @BeforeAll
    static void server() {
        String host = System.getProperty("seclume.mysql.host", space.seclume.tck.TestHosts.database());
        int port = Integer.getInteger("seclume.mysql.port", 3307);
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mysql-password"), Path.of("..", ".local-mysql-password"))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mysql-password");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("nothing on " + host + ":" + port);
        }
        String path = password.toString().replace(java.io.File.separatorChar, '/');
        url = "jdbc:seclume:mysql://" + host + ":" + port + "/seclume_test"
                + "?user=seclume_test&allowPublicKeyRetrieval=true&tls=off"
                + "&provider=file&path=" + path;
    }

    /** The connection whose session was handed over says it is closed, in JDBC's words. */
    @Test
    void aConnectionWhoseSessionWasHandedOverIsClosed() throws Exception {
        Connection connection = DriverManager.getConnection(url);
        MySession.Detached detached = connection.unwrap(MySession.class).detach();
        try {
            assertTrue(connection.isClosed());
            SQLException refused = assertThrows(SQLException.class,
                    connection::createStatement);
            assertEquals("08003", refused.getSQLState());
        } finally {
            detached.stream().close();
        }
    }

    /**
     * {@code setAutoCommit(false)} and nothing after it: {@code autocommit=0}
     * waits for the next statement. {@code detach()} sends it rather than
     * leaving it behind in the object that gives the session up.
     */
    @Test
    void aWaitingSettingReachesTheServerBeforeTheHandOver() throws Exception {
        Connection connection = DriverManager.getConnection(url);
        connection.setAutoCommit(false);
        ConnectionFacts facts = connection.unwrap(MyConnection.class).facts();
        MySession.Detached detached = connection.unwrap(MySession.class).detach();
        try (Connection resumed = MyConnection.resume(MySession.resume(detached.stream(),
                detached.capabilities(), detached.connectionId()), facts)) {
            assertEquals("0", ask(resumed, "select @@autocommit"),
                    "autocommit=0 was left behind in the object that gave the session up");
            assertFalse(resumed.getAutoCommit());
            assertEquals(facts, resumed.unwrap(MyConnection.class).facts());
            resumed.rollback();
            resumed.setAutoCommit(true);
        }
    }

    private static String ask(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(sql)) {
            rows.next();
            return rows.getString(1);
        }
    }
}
