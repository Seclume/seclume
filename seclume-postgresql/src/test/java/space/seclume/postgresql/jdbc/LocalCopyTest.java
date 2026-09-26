package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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

/** {@code COPY FROM STDIN} and {@code COPY TO STDOUT} against a real server. */
@Timeout(120)
class LocalCopyTest {

    private static final int ROWS = 100_000;

    private static String url;
    private Connection connection;
    private String table;

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

    @BeforeEach
    void table() throws SQLException {
        connection = DriverManager.getConnection(url);
        table = "copy_" + UUID.randomUUID().toString().substring(0, 8);
        execute("create table " + table + " (id int primary key, label text, amount numeric(12,2))");
    }

    @AfterEach
    void drop() throws SQLException {
        try {
            execute("drop table if exists " + table);
        } finally {
            connection.close();
        }
    }

    @Test
    void aHundredThousandRowsInAndOut() throws Exception {
        PgConnection pg = connection.unwrap(PgConnection.class);
        long start = System.nanoTime();
        long copied = pg.copyIn("copy " + table + " from stdin (format csv)", csv(ROWS));
        long millis = (System.nanoTime() - start) / 1_000_000;
        System.out.println("  COPY of " + ROWS + " rows: " + millis + " ms");
        assertEquals(ROWS, copied);
        assertEquals(String.valueOf(ROWS), one("select count(*) from " + table));
        assertEquals("Grüße, \"quoted\" 7", one("select label from " + table + " where id = 7"));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertEquals(ROWS, pg.copyOut("copy (select * from " + table + " order by id) to stdout "
                + "(format csv)", out));
        String exported = out.toString(StandardCharsets.UTF_8);
        assertEquals(ROWS, exported.lines().count());
        assertTrue(exported.startsWith("0,\"Grüße, \"\"quoted\"\" 0\",0.00\n"),
                exported.substring(0, 60));
    }

    @Test
    void insideATransactionItRollsBackWithIt() throws Exception {
        PgConnection pg = connection.unwrap(PgConnection.class);
        connection.setAutoCommit(false);
        assertEquals(100, pg.copyIn("copy " + table + " from stdin (format csv)", csv(100)));
        connection.rollback();
        connection.setAutoCommit(true);
        assertEquals("0", one("select count(*) from " + table));
    }

    @Test
    void aStreamThatFailsCopiesNothingAndTheConnectionCarriesOn() throws Exception {
        PgConnection pg = connection.unwrap(PgConnection.class);
        InputStream breaking = new InputStream() {
            private final InputStream first = csv(1000);

            @Override
            public int read() throws IOException {
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
        SQLException failed = assertThrows(SQLException.class,
                () -> pg.copyIn("copy " + table + " from stdin (format csv)", breaking));
        assertTrue(failed.getMessage().contains("the disk went away"), failed.getMessage());
        assertEquals("0", one("select count(*) from " + table));
    }

    @Test
    void badDataIsTheServersErrorAndTheConnectionCarriesOn() throws Exception {
        PgConnection pg = connection.unwrap(PgConnection.class);
        SQLException refused = assertThrows(SQLException.class, () -> pg.copyIn(
                "copy " + table + " from stdin (format csv)",
                new ByteArrayInputStream("1,a,1.0\nnot-a-number,b,2\n".getBytes(StandardCharsets.UTF_8))));
        assertEquals("22P02", refused.getSQLState(), refused.getMessage());
        assertEquals("0", one("select count(*) from " + table));
    }

    @Test
    void aSinkThatFailsIsReportedAfterTheAnswerWasRead() throws Exception {
        PgConnection pg = connection.unwrap(PgConnection.class);
        pg.copyIn("copy " + table + " from stdin (format csv)", csv(5000));
        OutputStream full = new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                throw new IOException("no space left");
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                throw new IOException("no space left");
            }
        };
        SQLException failed = assertThrows(SQLException.class,
                () -> pg.copyOut("copy " + table + " to stdout", full));
        assertTrue(failed.getMessage().contains("no space left"), failed.getMessage());
        assertEquals("5000", one("select count(*) from " + table));
    }

    @Test
    void theWrongDirectionIsNamed() throws Exception {
        PgConnection pg = connection.unwrap(PgConnection.class);
        SQLException wrong = assertThrows(SQLException.class, () -> pg.copyOut(
                "copy " + table + " from stdin", new ByteArrayOutputStream()));
        assertTrue(wrong.getMessage().contains("use copyIn"), wrong.getMessage());
        assertEquals("0", one("select count(*) from " + table));
    }

    /** {@code rows} lines of CSV, each with a comma, quotes and an umlaut in its text. */
    private static InputStream csv(int rows) {
        StringBuilder text = new StringBuilder(rows * 40);
        for (int i = 0; i < rows; i++) {
            text.append(i).append(",\"Grüße, \"\"quoted\"\" ").append(i).append("\",")
                    .append(i % 1000).append(".00\n");
        }
        return new ByteArrayInputStream(text.toString().getBytes(StandardCharsets.UTF_8));
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
