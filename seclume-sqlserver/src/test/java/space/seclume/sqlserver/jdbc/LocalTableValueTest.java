package space.seclume.sqlserver.jdbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.math.BigDecimal;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** Table-valued parameters against a real SQL Server. */
@Timeout(120)
class LocalTableValueTest {

    private static final String HOST =
            System.getProperty("seclume.mssql.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mssql.port", 1433);
    private static final UUID REF = UUID.fromString("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0");

    private static String url;
    private Connection connection;
    private String type;
    private String table;

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

    @BeforeEach
    void typeAndTable() throws SQLException {
        connection = DriverManager.getConnection(url);
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        type = "tvp_" + suffix;
        table = "tvp_target_" + suffix;
        // NOT NULL on the id, a varchar the text is converted into, and a
        // decimal narrower than the one the value goes as.
        execute("create type dbo." + type + " as table (id int not null primary key, "
                + "label nvarchar(60), code varchar(20), amount decimal(12,2), day date, "
                + "at datetime2, ref uniqueidentifier, flag bit, blob varbinary(100), "
                + "big bigint)");
        execute("create table " + table + " (id int, label nvarchar(60), code varchar(20), "
                + "amount decimal(12,2), day date, at datetime2, ref uniqueidentifier, "
                + "flag bit, blob varbinary(100), big bigint)");
    }

    @AfterEach
    void drop() throws SQLException {
        try {
            execute("drop table " + table);
            execute("drop type dbo." + type);
        } finally {
            connection.close();
        }
    }

    @Test
    void rowsOfEveryTypeArriveAsSent() throws Exception {
        List<Object[]> rows = new ArrayList<>();
        for (int i = 0; i < 10_000; i++) {
            rows.add(row(i));
        }
        try (PreparedStatement insert = connection.prepareStatement(
                "insert into " + table + " select * from ?")) {
            insert.setObject(1, TableValue.of("dbo." + type, rows));
            long start = System.nanoTime();
            assertEquals(10_000, insert.executeUpdate());
            System.out.println("  TVP of 10000 rows: "
                    + (System.nanoTime() - start) / 1_000_000 + " ms");
        }
        try (Statement s = connection.createStatement();
             ResultSet r = s.executeQuery("select * from " + table + " where id = 7")) {
            r.next();
            assertEquals("Grüße, \"quoted\" 'x' 7", r.getString("label"));
            assertEquals("C-7", r.getString("code"));
            assertEquals(new BigDecimal("7.25"), r.getBigDecimal("amount"));
            assertEquals(LocalDate.of(2026, 9, 25), r.getObject("day", LocalDate.class));
            assertEquals(LocalDateTime.of(2026, 9, 25, 18, 30, 7, 123_456_700),
                    r.getObject("at", LocalDateTime.class));
            assertEquals(REF, r.getObject("ref", UUID.class));
            assertEquals(false, r.getBoolean("flag"));
            assertArrayEquals(new byte[] {7, 0, (byte) 0xff}, r.getBytes("blob"));
            assertEquals(7L << 33, r.getLong("big"));
        }
        try (Statement s = connection.createStatement();
             ResultSet r = s.executeQuery("select label, amount, day, big from " + table
                     + " where id = 10")) {
            r.next();
            assertNull(r.getString(1));
            assertNull(r.getBigDecimal(2));
            assertNull(r.getObject(3));
            assertNull(r.getObject(4));
        }
    }

    @Test
    void aTableValueJoinsWithOtherParametersAndIsReusedWithTheStatement() throws Exception {
        try (PreparedStatement query = connection.prepareStatement(
                "select count(*), sum(amount) from ? where amount > ?")) {
            query.setObject(1, TableValue.of(type, List.of(row(1), row(2), row(3))));
            query.setBigDecimal(2, new BigDecimal("1.5"));
            try (ResultSet r = query.executeQuery()) {
                r.next();
                assertEquals(2, r.getInt(1));
                assertEquals(new BigDecimal("5.50"), r.getBigDecimal(2));
            }
            query.setObject(1, TableValue.of("[dbo].[" + type + "]", List.<Object[]>of(row(5))));
            try (ResultSet r = query.executeQuery()) {
                r.next();
                assertEquals(1, r.getInt(1));
            }
        }
    }

    @Test
    void anEmptyTableIsATableWithNoRows() throws Exception {
        try (PreparedStatement query = connection.prepareStatement("select count(*) from ?")) {
            query.setObject(1, TableValue.of(type, List.of()));
            try (ResultSet r = query.executeQuery()) {
                r.next();
                assertEquals(0, r.getInt(1));
            }
        }
    }

    @Test
    void aProcedureTakesItToo() throws Exception {
        String procedure = "tvp_count_" + type.substring(4);
        execute("create procedure " + procedure + " @lines dbo." + type
                + " readonly as select count(*) from @lines");
        try (CallableStatement call = connection.prepareCall("{call " + procedure + "(?)}")) {
            call.setObject(1, TableValue.of(type, List.of(row(1), row(2))));
            try (ResultSet r = call.executeQuery()) {
                r.next();
                assertEquals(2, r.getInt(1));
            }
        } finally {
            execute("drop procedure " + procedure);
        }
    }

    @Test
    void theServerStillHoldsTheTypesConstraints() throws Exception {
        try (PreparedStatement insert = connection.prepareStatement(
                "insert into " + table + " select * from ?")) {
            insert.setObject(1, TableValue.of(type, List.of(row(1), row(1))));
            SQLException refused = assertThrows(SQLException.class, insert::executeUpdate);
            assertEquals(2627, refused.getErrorCode(), refused.getMessage());
        }
        assertEquals("0", one("select count(*) from " + table));
    }

    @Test
    void aBadTypeNameOrARaggedRowIsRefusedBeforeAnythingIsSent() {
        for (String name : new String[] {"", "a.b.c", "x; drop table t", "[open", "a..b", "a."}) {
            SQLException refused = assertThrows(SQLException.class,
                    () -> TableValue.of(name, List.of()), name);
            assertEquals("42602", refused.getSQLState(), name);
        }
        SQLException ragged = assertThrows(SQLException.class,
                () -> TableValue.of(type, List.of(new Object[] {1, "a"}, new Object[] {2})));
        assertEquals("22023", ragged.getSQLState());
        SQLException mixed = assertThrows(SQLException.class,
                () -> TableValue.of(type, List.of(new Object[] {1}, new Object[] {"two"})));
        assertEquals("22005", mixed.getSQLState());
    }

    private static Object[] row(int i) {
        if (i % 10 == 0 && i > 0) {
            return new Object[] {i, null, "C-" + i, null, null, null, null, null, null, null};
        }
        return new Object[] {i, "Grüße, \"quoted\" 'x' " + i, "C-" + i,
                new BigDecimal(i % 1000 + ".25"), LocalDate.of(2026, 9, 25),
                LocalDateTime.of(2026, 9, 25, 18, 30, i % 60, 123_456_700), REF,
                i % 2 == 1 ? Boolean.FALSE : Boolean.TRUE,
                new byte[] {(byte) i, 0, (byte) 0xff}, (long) i << 33};
    }

    private String one(String sql) throws SQLException {
        try (Statement s = connection.createStatement(); ResultSet rows = s.executeQuery(sql)) {
            rows.next();
            return rows.getString(1);
        }
    }

    private void execute(String sql) throws SQLException {
        try (Statement s = connection.createStatement()) {
            s.execute(sql);
        }
    }
}
