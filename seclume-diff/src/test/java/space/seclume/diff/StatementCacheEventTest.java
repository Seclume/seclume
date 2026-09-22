package space.seclume.diff;

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
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

import space.seclume.tck.TestHosts;

/**
 * Whether the statement cache says anything, per driver.
 *
 * <p>{@code space.seclume.StatementCache} was raised by the PostgreSQL driver
 * and by no other, although three of the four keep plans. An operator reading
 * a recording would have concluded that the other drivers do not cache - the
 * worst kind of wrong, because the report looks complete.
 *
 * <p>The shape being measured is the one the cache exists for: a
 * <b>fresh statement object per call</b>, closed afterwards. That is what
 * Hibernate does, what {@code JdbcTemplate} does, and what almost every piece
 * of hand-written code does. The plan belongs to the connection, so the second
 * round has to be a hit although the object from the first is long gone.
 *
 * <p><b>SQL Server is in the list and expects nothing</b>, which is the point
 * of including it. It has no cache of compiled handles: a parameterised
 * statement goes through {@code sp_executesql}, text and all, and the server
 * caches the plan under that text - the same arrangement Microsoft's own
 * driver uses by default. There is therefore nothing here to report, and this
 * test is where the event goes if a handle cache is ever built.
 */
@Timeout(300)
class StatementCacheEventTest {

    private record Database(String name, String scheme, int port, String database, String user,
                            String passwordFile, String options, boolean caches) {

        String url(String host, int at, Path password) {
            return "jdbc:seclume:" + scheme + "://" + host + ":" + at + "/" + database
                    + "?user=" + user + options
                    + "&provider=file&path=" + password.toString().replace('\\', '/');
        }

        /** A select without a table, which Oracle alone refuses. */
        String selectOne() {
            return "oracle".equals(scheme) ? "select ? from dual" : "select ?";
        }
    }

    static List<Database> databases() {
        return List.of(
                new Database("PostgreSQL", "postgresql", 5432, "seclume_test", "seclume_test",
                        ".local-pg-password", "&tls=off", true),
                new Database("MySQL", "mysql", 3307, "seclume_test", "seclume_test",
                        ".local-mysql-password", "&tls=off", true),
                new Database("SQL Server", "sqlserver", 1433, "master", "sa",
                        ".local-mssql-password", "&trustServerCertificate=true", false),
                new Database("Oracle", "oracle", 1521, "FREEPDB1", "seclume_test",
                        ".local-oracle-password", "", true));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void theSecondRoundIsAHit(Database database, @TempDir Path directory) throws Exception {
        String host = hostOf(database);
        int port = portOf(database);
        Path password = passwordOf(database);
        reachable(host, port);
        Path file = directory.resolve("cache-" + database.scheme() + ".jfr");

        try (Recording recording = new Recording()) {
            recording.enable("space.seclume.StatementCache");
            recording.start();

            try (Connection connection = DriverManager.getConnection(
                    database.url(host, port, password))) {
                for (int round = 0; round < 2; round++) {
                    try (PreparedStatement statement =
                            connection.prepareStatement(database.selectOne())) {
                        statement.setString(1, "cache-probe");
                        try (ResultSet rows = statement.executeQuery()) {
                            assertTrue(rows.next());
                        }
                    }
                }
            }

            recording.stop();
            recording.dump(file);
        }

        List<RecordedEvent> lookups = RecordingFile.readAllEvents(file).stream()
                .filter(e -> e.getEventType().getName().equals("space.seclume.StatementCache"))
                .toList();

        if (!database.caches()) {
            assertEquals(0, lookups.size(),
                    "this driver has no cache of compiled statements - if one was built, "
                            + "the event belongs here and this expectation changes with it");
            return;
        }

        assertTrue(lookups.size() >= 2,
                "two lookups were made, " + lookups.size() + " were recorded");
        assertTrue(lookups.stream().anyMatch(e -> !e.getBoolean("hit")),
                "the first lookup cannot have found anything and should say so");
        assertTrue(lookups.stream().anyMatch(e -> e.getBoolean("hit")),
                "the second round did not find the plan the first one left - either the "
                        + "cache is per statement object rather than per connection, or the "
                        + "event says the wrong thing");

        // The fingerprint, not the text. The statement here has a bind
        // parameter and no literal, so this is the weaker half of the check -
        // JfrNoValuesTest is the one that hunts for values - but a cache
        // report listing statements by their text is exactly the report that
        // could not then be shared.
        assertTrue(lookups.stream().allMatch(e -> e.getString("fingerprint") != null
                        && e.getString("fingerprint").contains("?")),
                "a lookup was recorded without a masked statement: "
                        + lookups.stream().map(e -> e.getString("fingerprint")).toList());
    }

    private static String key(Database database) {
        return switch (database.scheme()) {
            case "postgresql" -> "pg";
            case "sqlserver" -> "mssql";
            default -> database.scheme();
        };
    }

    private static String hostOf(Database database) {
        String host = System.getProperty("seclume." + key(database) + ".host",
                TestHosts.database());
        Assumptions.assumeTrue(host != null, "no host configured for " + database.name());
        return host;
    }

    private static int portOf(Database database) {
        return Integer.getInteger("seclume." + key(database) + ".port", database.port());
    }

    private static Path passwordOf(Database database) {
        String named = System.getProperty("seclume." + key(database) + ".passwordFile",
                database.passwordFile());
        for (Path candidate : List.of(Path.of(named), Path.of("..", named))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.abort("no " + named);
        return null;
    }

    private static void reachable(String host, int port) {
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("nothing on " + host + ":" + port);
        }
    }
}
