package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * {@code LOAD DATA LOCAL INFILE} fed from a stream - and never from a file the
 * server names. Needs {@code local_infile=ON} on the server; skipped otherwise.
 */
@Timeout(120)
class LocalLoadDataTest {

    private static String url;
    private Connection connection;
    private String table;

    @BeforeAll
    static void findTheServer() throws SQLException {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mysql-password"),
                Path.of("..", ".local-mysql-password"))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mysql-password");
        String host = TestHosts.database();
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, 3307), 2000);
        } catch (IOException e) {
            Assumptions.abort("no MySQL on " + host);
        }
        url = "jdbc:seclume:mysql://" + host + ":3307/seclume_test?user=seclume_test&tls=off"
                + "&allowPublicKeyRetrieval=true&provider=file&path="
                + password.toString().replace('\\', '/');
        try (Connection c = DriverManager.getConnection(url);
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery("select @@global.local_infile")) {
            r.next();
            Assumptions.assumeTrue(r.getInt(1) == 1, "local_infile is OFF on this server");
        }
    }

    @BeforeEach
    void table() throws SQLException {
        connection = DriverManager.getConnection(url + "&loadDataLocal=true");
        table = "load_" + UUID.randomUUID().toString().substring(0, 8);
        execute(connection, "create table " + table + " (id int primary key, label varchar(60))");
    }

    @AfterEach
    void drop() throws SQLException {
        try (Connection c = DriverManager.getConnection(url)) {
            execute(c, "drop table " + table);
        } finally {
            connection.close();
        }
    }

    @Test
    void aHundredThousandRowsFromAStream() throws Exception {
        MyConnection my = connection.unwrap(MyConnection.class);
        long start = System.nanoTime();
        long loaded = my.loadData("load data local infile 'rows.csv' into table " + table
                + " character set utf8mb4 fields terminated by ',' optionally enclosed by '\"'",
                csv(100_000));
        System.out.println("  LOAD DATA LOCAL of 100000 rows: "
                + (System.nanoTime() - start) / 1_000_000 + " ms");
        assertEquals(100_000, loaded);
        assertEquals("100000", one(connection, "select count(*) from " + table));
        assertEquals("Grüße, 7", one(connection, "select label from " + table + " where id = 7"));
    }

    /** The name in the statement is never opened - the server gets the stream. */
    @Test
    void theFileTheStatementNamesIsNotRead() throws Exception {
        MyConnection my = connection.unwrap(MyConnection.class);
        assertEquals(3, my.loadData("load data local infile '/etc/passwd' into table " + table
                + " character set utf8mb4 fields terminated by ',' optionally enclosed by '\"'",
                csv(3)));
        assertEquals("3", one(connection, "select count(*) from " + table));
    }

    /** A LOCAL INFILE request outside loadData gets an empty file - not the one it names. */
    @Test
    void aRequestOutsideLoadDataGetsNothing() throws Exception {
        Path existing = Path.of("pom.xml").toAbsolutePath();
        Assumptions.assumeTrue(Files.isReadable(existing));
        execute(connection, "load data local infile '" + existing.toString().replace('\\', '/')
                + "' into table " + table + " fields terminated by ','");
        assertEquals("0", one(connection, "select count(*) from " + table));
    }

    @Test
    void withoutTheOptionItIsRefused() throws Exception {
        try (Connection plain = DriverManager.getConnection(url)) {
            SQLException refused = assertThrows(SQLException.class, () -> plain.unwrap(
                    MyConnection.class).loadData("load data local infile 'x' into table "
                    + table, csv(1)));
            assertTrue(refused.getMessage().contains("loadDataLocal=true"), refused.getMessage());
            assertThrows(SQLException.class, () -> execute(plain,
                    "load data local infile 'x' into table " + table));
            assertEquals("1", one(plain, "select 1"));
        }
    }

    /** A stream that breaks closes the connection, and the server keeps none of it. */
    @Test
    void aStreamThatFailsLeavesNothingBehind() throws Exception {
        MyConnection my = connection.unwrap(MyConnection.class);
        InputStream breaking = new InputStream() {
            private final InputStream first = csv(2000);

            @Override
            public int read() {
                throw new UnsupportedOperationException();
            }

            @Override
            public int read(byte[] into, int offset, int length) throws IOException {
                int read = first.read(into, offset, length);
                if (read < 0) {
                    throw new IOException("the disk went away");
                }
                return read;
            }
        };
        SQLException failed = assertThrows(SQLException.class, () -> my.loadData(
                "load data local infile 'x' into table " + table
                        + " character set utf8mb4 fields terminated by ',' optionally enclosed by '\"'",
                breaking));
        StringBuilder chain = new StringBuilder();
        for (Throwable t = failed; t != null; t = t.getCause()) {
            chain.append(t.getMessage()).append(" / ");
        }
        assertTrue(chain.toString().contains("the disk went away"), chain.toString());
        try (Connection other = DriverManager.getConnection(url)) {
            for (int i = 0; i < 50 && !"0".equals(one(other, "select count(*) from " + table)); i++) {
                Thread.sleep(100);           // the server notices the closed connection
            }
            assertEquals("0", one(other, "select count(*) from " + table));
        }
    }

    private static InputStream csv(int rows) {
        StringBuilder text = new StringBuilder(rows * 20);
        for (int i = 0; i < rows; i++) {
            text.append(i).append(",\"Grüße, ").append(i).append("\"\n");
        }
        return new ByteArrayInputStream(text.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static String one(Connection c, String sql) throws SQLException {
        try (Statement s = c.createStatement(); ResultSet rows = s.executeQuery(sql)) {
            rows.next();
            return rows.getString(1);
        }
    }

    private static void execute(Connection c, String sql) throws SQLException {
        try (Statement s = c.createStatement()) {
            s.execute(sql);
        }
    }
}
