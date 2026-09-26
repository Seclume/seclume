package space.seclume.sqlserver.jdbc;

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
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * ASCII text compared with a {@code varchar} column goes as {@code varchar},
 * so the column is not converted row by row - read off the plan the server
 * cached for the statement. The control, the same statement with
 * {@code varcharParameters=off}, shows the conversion that is gone.
 */
@Timeout(60)
class VarcharParametersTest {

    private static final String HOST =
            System.getProperty("seclume.mssql.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mssql.port", 1433);

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mssql-password"),
                Path.of("..", ".local-mssql-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mssql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no SQL Server on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:sqlserver://" + HOST + ":" + PORT + "/master"
                + "?user=sa&trustServerCertificate=true&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    @Test
    void asciiTextComparedWithVarcharIsNotConverted() throws Exception {
        String table = "seclume_vc_" + UUID.randomUUID().toString().substring(0, 8);
        try (Connection c = DriverManager.getConnection(url)) {
            execute(c, "create table " + table + " (code varchar(20) collate "
                    + "SQL_Latin1_General_CP1_CI_AS primary key, label nvarchar(20))");
            try {
                execute(c, "insert into " + table + " values ('abc', N'x'), ('Straße', N'ü')");
                VarcharParameters.forget();

                String asked = "select label from " + table + " where code = ? /* on */";
                assertEquals("x", label(c, asked, "abc"));
                assertEquals("x", label(c, asked, "ABC"), "the column's collation still decides");
                // Not ASCII: nvarchar as before, and still the right row.
                assertEquals("ü", label(c, asked, "Straße"));
                String plan = plans(c, "/* on */").stream()
                        .filter(one -> one.contains("@P0 varchar(8000)")).findFirst()
                        .orElseThrow(() -> new AssertionError("no plan with a varchar parameter"));
                assertFalse(plan.contains("CONVERT_IMPLICIT(nvarchar"),
                        "the column is still converted: " + plan);
                assertTrue(plan.contains("Index Seek"), "no seek: " + plan);
            } finally {
                execute(c, "drop table " + table);
            }
        }
    }

    @Test
    void offKeepsNvarcharAndTheConversionShowsIt() throws Exception {
        String table = "seclume_vc_" + UUID.randomUUID().toString().substring(0, 8);
        try (Connection c = DriverManager.getConnection(url + "&varcharParameters=off")) {
            execute(c, "create table " + table + " (code varchar(20) collate "
                    + "SQL_Latin1_General_CP1_CI_AS primary key, label nvarchar(20))");
            try {
                execute(c, "insert into " + table + " values ('abc', N'x')");
                String asked = "select label from " + table + " where code = ? /* off */";
                assertEquals("x", label(c, asked, "abc"));
                String plan = String.join("", plans(c, "/* off */"));
                assertTrue(plan.contains("CONVERT_IMPLICIT(nvarchar"),
                        "the control shows no conversion, so the test proves nothing: " + plan);
            } finally {
                execute(c, "drop table " + table);
            }
        }
    }

    @Test
    void nvarcharColumnsAndInTransactionsStayNvarchar() throws Exception {
        String table = "seclume_vc_" + UUID.randomUUID().toString().substring(0, 8);
        try (Connection c = DriverManager.getConnection(url)) {
            execute(c, "create table " + table + " (code nvarchar(20) primary key)");
            try {
                execute(c, "insert into " + table + " values (N'abc')");
                VarcharParameters.forget();
                c.setAutoCommit(false);
                try (PreparedStatement s = c.prepareStatement(
                        "select count(*) from " + table + " where code = ?")) {
                    s.setString(1, "abc");
                    try (ResultSet rows = s.executeQuery()) {
                        rows.next();
                        assertEquals(1, rows.getInt(1));
                    }
                }
                c.commit();
                c.setAutoCommit(true);
            } finally {
                execute(c, "drop table " + table);
            }
        }
    }

    private static String label(Connection c, String sql, String code) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(sql)) {
            s.setString(1, code);
            try (ResultSet rows = s.executeQuery()) {
                return rows.next() ? rows.getString(1) : null;
            }
        }
    }

    /** The cached plan of the statement whose text carries {@code marker}. */
    private static List<String> plans(Connection c, String marker) throws SQLException {
        try (Statement s = c.createStatement();
             ResultSet rows = s.executeQuery("select cast(qp.query_plan as nvarchar(max)) "
                     + "from sys.dm_exec_query_stats qs "
                     + "cross apply sys.dm_exec_sql_text(qs.sql_handle) st "
                     + "cross apply sys.dm_exec_query_plan(qs.plan_handle) qp "
                     + "where st.text like '%where code = @P0 " + marker.replace("'", "''")
                     + "%' and st.text not like '%dm_exec%'")) {
            List<String> all = new java.util.ArrayList<>();
            while (rows.next()) {
                all.add(rows.getString(1));
            }
            assertFalse(all.isEmpty(), "no cached plan for " + marker);
            return all;
        }
    }

    private static void execute(Connection c, String sql) throws SQLException {
        try (Statement s = c.createStatement()) {
            s.execute(sql);
        }
    }
}
