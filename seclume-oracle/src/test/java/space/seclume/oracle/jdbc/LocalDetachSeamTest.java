package space.seclume.oracle.jdbc;

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
import space.seclume.oracle.OracleSession;

/**
 * The seam a JDBC connection is taken apart at: {@code detach()} under it,
 * {@code facts()} beside it, {@code resume} on the other side. What is built
 * on the seam is not this library's; that the seam holds is.
 */
class LocalDetachSeamTest {

    private static String url;

    @BeforeAll
    static void server() {
        String host = System.getProperty("seclume.oracle.host", space.seclume.tck.TestHosts.database());
        int port = Integer.getInteger("seclume.oracle.port", 1521);
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-oracle-password"), Path.of("..", ".local-oracle-password"))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-oracle-password");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("nothing on " + host + ":" + port);
        }
        String path = password.toString().replace(java.io.File.separatorChar, '/');
        url = "jdbc:seclume:oracle://" + host + ":" + port + "/"
                + System.getProperty("seclume.oracle.service", "FREEPDB1")
                + "?user=seclume_test&provider=file&path=" + path;
    }

    /** The connection whose session was handed over says it is closed, in JDBC's words. */
    @Test
    void aConnectionWhoseSessionWasHandedOverIsClosed() throws Exception {
        Connection connection = DriverManager.getConnection(url);
        OracleSession.Detached detached = connection.unwrap(OracleSession.class).detach();
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
     * Auto-commit is a bit in every Oracle execute call, kept by the session
     * as well as by the connection. The resumed connection sets both - a
     * session left in auto-commit under a connection that is not would commit
     * every statement the connection believes is in a transaction.
     */
    @Test
    void aResumedConnectionOutsideAutoCommitDoesNotCommit() throws Exception {
        try (Connection setup = DriverManager.getConnection(url);
             Statement statement = setup.createStatement()) {
            statement.execute("begin execute immediate 'drop table zl_seam purge'; "
                    + "exception when others then null; end;");
            statement.execute("create table zl_seam (n number)");
        }
        Connection connection = DriverManager.getConnection(url);
        connection.setAutoCommit(false);
        ConnectionFacts facts = connection.unwrap(OraConnection.class).facts();
        OracleSession session = connection.unwrap(OracleSession.class);
        session.releaseCursors();
        OracleSession.Detached detached = session.detach();
        try (Connection resumed = OraConnection.resume(OracleSession.resume(detached.stream(),
                detached.protocolVersion(), detached.sequence(), detached.inTransaction()),
                facts)) {
            try (Statement statement = resumed.createStatement()) {
                statement.executeUpdate("insert into zl_seam values (1)");
            }
            try (Connection other = DriverManager.getConnection(url)) {
                assertEquals("0", ask(other, "select count(*) from zl_seam"),
                        "the insert was committed - the session was left in auto-commit");
            }
            resumed.rollback();
            resumed.setAutoCommit(true);
            try (Statement statement = resumed.createStatement()) {
                statement.execute("drop table zl_seam purge");
            }
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
