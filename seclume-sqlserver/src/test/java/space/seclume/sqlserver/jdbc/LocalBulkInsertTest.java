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
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.IntStream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** {@code INSERT BULK} against a real SQL Server. */
@Timeout(120)
class LocalBulkInsertTest {

    private static final String HOST =
            System.getProperty("seclume.mssql.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mssql.port", 1433);
    private static final String[] COLUMNS =
            {"id", "label", "code", "amount", "day", "at", "ref", "flag", "blob"};
    private static final UUID REF = UUID.fromString("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0");

    private static String url;
    private Connection connection;
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
    void table() throws SQLException {
        connection = DriverManager.getConnection(url);
        table = "bulk_" + UUID.randomUUID().toString().substring(0, 8);
        execute("create table " + table + " (id int primary key, label nvarchar(60), "
                + "code varchar(20), amount decimal(12,2) check (amount >= 0), day date, "
                + "at datetime2, ref uniqueidentifier, flag bit, blob varbinary(100))");
    }

    @AfterEach
    void drop() throws SQLException {
        try {
            execute("drop table " + table);
        } finally {
            connection.close();
        }
    }

    @Test
    void aHundredThousandRowsOfEveryType() throws Exception {
        List<Object[]> rows = new ArrayList<>();
        for (int i = 0; i < 100_000; i++) {
            rows.add(row(i));
        }
        TdsConnection sql = connection.unwrap(TdsConnection.class);
        long start = System.nanoTime();
        long loaded = sql.bulkInsert(table, COLUMNS, rows);
        System.out.println("  INSERT BULK of 100000 rows: "
                + (System.nanoTime() - start) / 1_000_000 + " ms");
        assertEquals(100_000, loaded);
        assertEquals("100000", one("select count(*) from " + table));
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
        }
        try (Statement s = connection.createStatement();
             ResultSet r = s.executeQuery("select label, amount, day from " + table
                     + " where id = 10")) {
            r.next();
            assertNull(r.getString(1));
            assertNull(r.getBigDecimal(2));
            assertNull(r.getObject(3));
        }
    }

    @Test
    void aCheckConstraintIsChecked() throws Exception {
        Object[] negative = row(1);
        negative[3] = new BigDecimal("-1.00");
        TdsConnection sql = connection.unwrap(TdsConnection.class);
        SQLException refused = assertThrows(SQLException.class,
                () -> sql.bulkInsert(table, COLUMNS, List.of(row(0), negative)));
        assertEquals(547, refused.getErrorCode(), refused.getMessage());
        assertEquals("0", one("select count(*) from " + table));
    }

    @Test
    void aRowThatDoesNotFitIsRefusedAndNothingIsLoaded() throws Exception {
        List<Object[]> rows = new ArrayList<>();
        IntStream.range(0, 1500).forEach(i -> rows.add(row(i)));
        rows.get(1200)[0] = "not a number";
        TdsConnection sql = connection.unwrap(TdsConnection.class);
        SQLException refused = assertThrows(SQLException.class,
                () -> sql.bulkInsert(table, COLUMNS, rows));
        assertEquals("22005", refused.getSQLState(), refused.getMessage());
        assertEquals("0", one("select count(*) from " + table));
    }

    @Test
    void insideATransactionItRollsBackWithIt() throws Exception {
        connection.setAutoCommit(false);
        TdsConnection sql = connection.unwrap(TdsConnection.class);
        assertEquals(3, sql.bulkInsert(table, COLUMNS, List.of(row(0), row(1), row(2))));
        connection.rollback();
        connection.setAutoCommit(true);
        assertEquals("0", one("select count(*) from " + table));
    }

    private static Object[] row(int i) {
        if (i % 10 == 0 && i > 0) {
            return new Object[] {i, null, "C-" + i, null, null, null, null, null, null};
        }
        return new Object[] {i, "Grüße, \"quoted\" 'x' " + i, "C-" + i,
                new BigDecimal(i % 1000 + ".25"), LocalDate.of(2026, 9, 25),
                LocalDateTime.of(2026, 9, 25, 18, 30, i % 60, 123_456_700), REF,
                i % 2 == 1 ? Boolean.FALSE : Boolean.TRUE, new byte[] {(byte) i, 0, (byte) 0xff}};
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
