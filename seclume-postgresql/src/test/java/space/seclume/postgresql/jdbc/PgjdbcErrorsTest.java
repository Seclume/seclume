package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.tck.TestHosts;

/**
 * Two errors every pgjdbc user has met, that do not happen here - the
 * evidence behind MIGRATING.md.
 */
class PgjdbcErrorsTest {

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no " + TestHosts.postgresPasswordFile());
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(TestHosts.postgres(), TestHosts.postgresPort()),
                    2000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on " + TestHosts.postgres());
        }
        url = "jdbc:seclume:postgresql://" + TestHosts.postgres() + ":"
                + TestHosts.postgresPort() + "/seclume_test?user=seclume_test&tls=off"
                + "&provider=file&path=" + password.toString().replace('\\', '/');
    }

    /**
     * pgjdbc: "column "doc" is of type jsonb but expression is of type
     * character varying" - unless the URL says {@code stringtype=unspecified}.
     * Here the Parse leaves a string parameter's type to the server.
     */
    @Test
    void aStringGoesIntoJsonbAndUuidColumns() throws SQLException {
        String table = "pgjdbc_err_" + UUID.randomUUID().toString().substring(0, 8);
        try (Connection c = DriverManager.getConnection(url)) {
            execute(c, "create table " + table + " (id uuid, doc jsonb)");
            try {
                try (PreparedStatement s = c.prepareStatement(
                        "insert into " + table + " values (?, ?)")) {
                    s.setString(1, "00000000-0000-0000-0000-000000000001");
                    s.setString(2, "{\"a\": 1}");
                    assertEquals(1, s.executeUpdate());
                }
                try (Statement s = c.createStatement();
                     ResultSet rows = s.executeQuery("select doc ->> 'a' from " + table)) {
                    assertTrue(rows.next());
                    assertEquals("1", rows.getString(1));
                }
            } finally {
                execute(c, "drop table " + table);
            }
        }
    }

    /**
     * pgjdbc: "cached plan must not change result type" after a deployment
     * altered a table under a pooled connection's prepared statement. Here
     * the plan is replaced and the statement runs again, outside a
     * transaction.
     */
    @Test
    void aPreparedStatementSurvivesTheTableChangingUnderIt() throws SQLException {
        String table = "pgjdbc_err_" + UUID.randomUUID().toString().substring(0, 8);
        try (Connection c = DriverManager.getConnection(url)) {
            execute(c, "create table " + table + " (id int)");
            try {
                execute(c, "insert into " + table + " values (1)");
                try (PreparedStatement s = c.prepareStatement("select * from " + table)) {
                    for (int i = 0; i < 6; i++) {           // past any prepare threshold
                        try (ResultSet rows = s.executeQuery()) {
                            assertTrue(rows.next());
                        }
                    }
                    execute(c, "alter table " + table + " add column label text");
                    try (ResultSet rows = s.executeQuery()) {
                        assertTrue(rows.next());
                        assertEquals(2, rows.getMetaData().getColumnCount());
                    }
                }
            } finally {
                execute(c, "drop table " + table);
            }
        }
    }

    private static void execute(Connection c, String sql) throws SQLException {
        try (Statement s = c.createStatement()) {
            s.execute(sql);
        }
    }
}
