package space.seclume.oracle.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import org.junit.jupiter.api.Timeout;

import space.seclume.oracle.OracleSession;

/**
 * The same DDL twice on one connection - and it runs twice.
 *
 * <p>Oracle executes DDL when it parses it. The driver keeps a cursor per
 * statement text so that a repeated query is not parsed again - and it kept
 * one for DDL too. The second {@code create table} of the same text was then
 * an execution of a cursor that had already done its work: nothing happened,
 * nothing was reported. A test that drops and recreates its table per case
 * found it on a pooled connection; a repeated {@code truncate} would have
 * left every row where it was.
 */
@Timeout(120)
class LocalRepeatedDdlTest {

    private static final String HOST =
            System.getProperty("seclume.oracle.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.oracle.port", 1521);

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-oracle-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no Oracle on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:oracle://" + HOST + ":" + PORT + "/"
                + System.getProperty("seclume.oracle.service", "FREEPDB1")
                + "?user=seclume_test&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    @Test
    void aRepeatedCreateAndTruncateRunEveryTime() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            for (int round = 0; round < 3; round++) {
                statement.execute("begin execute immediate 'drop table zl_ddl_twice purge'; "
                        + "exception when others then null; end;");
                statement.execute("create table zl_ddl_twice (id number(10))");
                assertEquals(1, count(statement,
                        "select count(*) from user_tables where table_name = 'ZL_DDL_TWICE'"),
                        "round " + round + ": the create did not run");
                statement.executeUpdate("insert into zl_ddl_twice values (1)");
                statement.execute("truncate table zl_ddl_twice");
                assertEquals(0, count(statement, "select count(*) from zl_ddl_twice"),
                        "round " + round + ": the truncate did not run");
            }
            statement.execute("drop table zl_ddl_twice purge");
        }
    }

    @Test
    void whatCountsAsDefinition() {
        assertTrue(OracleSession.isDefinition("  create table t (x int)"));
        assertTrue(OracleSession.isDefinition("-- a comment\n/* another */ TRUNCATE TABLE t"));
        assertTrue(OracleSession.isDefinition("alter session set nls_date_format = 'YYYY'"));
        assertFalse(OracleSession.isDefinition("select 1 from dual"));
        assertFalse(OracleSession.isDefinition("begin execute immediate 'drop table t'; end;"));
        assertFalse(OracleSession.isDefinition("insert into created values (1)"));
    }

    private static int count(Statement statement, String sql) throws Exception {
        try (ResultSet rows = statement.executeQuery(sql)) {
            rows.next();
            return rows.getInt(1);
        }
    }
}
