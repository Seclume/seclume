package space.seclume.sqlserver.jdbc;

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

import space.seclume.internal.jdbc.ConnectionFacts;
import space.seclume.sqlserver.tds.TdsSession;

/**
 * The seam a JDBC connection is taken apart at: {@code detach()} under it,
 * {@code facts()} beside it, {@code resume} on the other side. What is built
 * on the seam is not this library's; that the seam holds is.
 */
class LocalDetachSeamTest {

    private static String url;

    @BeforeAll
    static void server() {
        String host = System.getProperty("seclume.mssql.host", space.seclume.tck.TestHosts.database());
        int port = Integer.getInteger("seclume.mssql8.port", 1435);
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mssql-password"), Path.of("..", ".local-mssql-password"))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mssql-password");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("nothing on " + host + ":" + port);
        }
        String path = password.toString().replace(java.io.File.separatorChar, '/');
        url = "jdbc:seclume:sqlserver://" + host + ":" + port + "/master"
                + "?user=sa&tds=8.0&tlsStack=seclume&trustServerCertificate=true"
                + "&provider=file&path=" + path;
    }

    /** The connection whose session was handed over says it is closed, in JDBC's words. */
    @Test
    void aConnectionWhoseSessionWasHandedOverIsClosed() throws Exception {
        Connection connection = DriverManager.getConnection(url);
        TdsSession.Detached detached = connection.unwrap(TdsSession.class).detach();
        try {
            assertTrue(connection.isClosed());
            SQLException refused = assertThrows(SQLException.class,
                    connection::createStatement);
            assertEquals("08003", refused.getSQLState());
        } finally {
            detached.stream().close();
        }
    }

    /** What the connection knew about itself goes into facts() and back out of resume(). */
    @Test
    void factsCarryWhatTheConnectionKnew() throws Exception {
        Connection connection = DriverManager.getConnection(url);
        connection.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
        ConnectionFacts facts = connection.unwrap(TdsConnection.class).facts();
        assertEquals(Connection.TRANSACTION_REPEATABLE_READ, facts.isolation());
        TdsSession.Detached detached = connection.unwrap(TdsSession.class).detach();
        try (Connection resumed = TdsConnection.resume(TdsSession.resume(detached.stream(),
                detached.packetSize(), detached.database(), detached.serverName(),
                detached.serverVersion(), detached.tls()), facts)) {
            assertEquals(Connection.TRANSACTION_REPEATABLE_READ,
                    resumed.getTransactionIsolation());
            assertEquals(facts, resumed.unwrap(TdsConnection.class).facts());
            assertEquals("3", ask(resumed, "select transaction_isolation_level "
                    + "from sys.dm_exec_sessions where session_id = @@spid"));
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
