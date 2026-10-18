package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Array;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.tck.TestHosts;

/**
 * An array of timestamptz values under timezones with minute or second offsets
 * (e.g. Asia/Kolkata +05:30, Asia/Kathmandu +05:45).
 */
class LocalTimestamptzArrayTest {

    private static String url;

    @BeforeAll
    static void server() {
        String host = TestHosts.postgres();
        int port = TestHosts.postgresPort();
        Path password = null;
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no PostgreSQL password file");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no PostgreSQL on " + host + ":" + port);
        }
        url = "jdbc:seclume:postgresql://" + host + ":" + port + "/seclume_test"
                + "?user=seclume_test&tls=off&provider=file&path="
                + password.toString().replace(java.io.File.separatorChar, '/');
    }

    @Test
    void kolkataOffsetHasMinutes() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("set timezone to 'Asia/Kolkata'");
            try (ResultSet rows = statement.executeQuery(
                    "select array['2024-01-31 12:00:00+05:30'::timestamptz] as arr")) {
                assertTrue(rows.next());
                String raw = rows.getString("arr");
                assertTrue(raw.contains("+05:30"), "PG formats Asia/Kolkata offset with colon");
                Array array = rows.getArray("arr");
                assertNotNull(array);
                Timestamp[] timestamps = (Timestamp[]) array.getArray();
                assertEquals(1, timestamps.length);
                assertNotNull(timestamps[0]);
            }
        }
    }

    @Test
    void kathmanduOffsetHas45Minutes() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("set timezone to 'Asia/Kathmandu'");
            try (ResultSet rows = statement.executeQuery(
                    "select array['2024-01-31 12:00:00+05:45'::timestamptz] as arr")) {
                assertTrue(rows.next());
                String raw = rows.getString("arr");
                assertTrue(raw.contains("+05:45"), "PG formats Asia/Kathmandu offset with colon");
                Array array = rows.getArray("arr");
                assertNotNull(array);
                Timestamp[] timestamps = (Timestamp[]) array.getArray();
                assertEquals(1, timestamps.length);
                assertNotNull(timestamps[0]);
            }
        }
    }

    @Test
    void historicalOffsetWithSeconds() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            // Paris before 1900 had LMT +00:09:21
            statement.execute("set timezone to 'Europe/Paris'");
            try (ResultSet rows = statement.executeQuery(
                    "select array['1890-01-01 12:00:00'::timestamptz] as arr")) {
                assertTrue(rows.next());
                String raw = rows.getString("arr");
                assertTrue(raw.contains("+00:09:21"), "PG formats historical Paris LMT offset with seconds");
                Array array = rows.getArray("arr");
                assertNotNull(array);
                Timestamp[] timestamps = (Timestamp[]) array.getArray();
                assertEquals(1, timestamps.length);
                assertNotNull(timestamps[0]);
            }
        }
    }
}
