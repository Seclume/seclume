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
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import space.seclume.internal.jdbc.HostQuality;
import space.seclume.tck.TestHosts;

/**
 * {@code hostSelection=quality} against the real thing - on all four.
 *
 * <p>The URL names a dead server first and the real one second, and the
 * connections are opened through {@link DriverManager}, which parses the URL
 * afresh every time. That is the case the measurement exists for: with
 * {@code ordered}, what a list remembers about the last server that worked
 * lives in that one parsed list and is gone by the next call, so every
 * connection pays for the dead head again. With {@code quality} what was
 * learned is the process's, and the second connection goes straight to the
 * server that answers.
 *
 * <p>The dead server is a closed port on loopback - refused at once, so the
 * test measures the choice and not a timeout. Each database and each mode
 * gets a port of its own, because the measurements are shared by the whole
 * process and one case must not inherit another's.
 */
@Timeout(300)
class HostSelectionTest {

    private record Database(String name, String scheme, int port, String database, String user,
                            String passwordFile, String options, int deadPort) {

        String url(String host, int at, Path password, int dead, String selection) {
            return "jdbc:seclume:" + scheme + "://127.0.0.1:" + dead + "," + host + ":" + at
                    + "/" + database + "?user=" + user + options
                    + "&connectTimeout=3000"
                    + (selection == null ? "" : "&hostSelection=" + selection)
                    + "&provider=file&path=" + password.toString().replace('\\', '/');
        }
    }

    static List<Database> databases() {
        return List.of(
                new Database("PostgreSQL", "postgresql", 5432, "seclume_test", "seclume_test",
                        ".local-pg-password", "&tls=off", 9),
                new Database("MySQL", "mysql", 3307, "seclume_test", "seclume_test",
                        ".local-mysql-password", "&tls=off", 11),
                new Database("SQL Server", "sqlserver", 1433, "master", "sa",
                        ".local-mssql-password", "&trustServerCertificate=true", 13),
                new Database("Oracle", "oracle", 1521, "FREEPDB1", "seclume_test",
                        ".local-oracle-password", "", 15));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void orderedPaysForTheDeadHeadEveryTimeQualityOnce(Database database) throws Exception {
        String host = hostOf(database);
        int port = portOf(database);
        Path password = passwordOf(database);
        reachable(host, port);
        int orderedDead = database.deadPort();
        int qualityDead = database.deadPort() + 1;
        Assumptions.assumeFalse(listening(orderedDead) || listening(qualityDead),
                "something listens on the port meant to be dead");

        for (int i = 0; i < 2; i++) {
            try (Connection connection = DriverManager.getConnection(
                    database.url(host, port, password, orderedDead, null))) {
                assertTrue(connection.isValid(5));
            }
        }
        assertEquals(2, failuresOf(orderedDead),
                "ordered, through DriverManager: both connections asked the dead server first");

        for (int i = 0; i < 2; i++) {
            try (Connection connection = DriverManager.getConnection(
                    database.url(host, port, password, qualityDead, "quality"))) {
                assertTrue(connection.isValid(5));
            }
        }
        assertEquals(1, failuresOf(qualityDead),
                "quality: the first connection learned the server was dead and the second "
                + "went straight past it - " + HostQuality.snapshot());

        HostQuality.Sample live = sampleOf(host, port);
        assertTrue(live.connectMillis() > 0 && live.samples() >= 4,
                "the server that answered was measured: " + live);
    }

    private static int failuresOf(int deadPort) {
        return sampleOf("127.0.0.1", deadPort).consecutiveFailures();
    }

    private static HostQuality.Sample sampleOf(String host, int port) {
        return HostQuality.snapshot().stream()
                .filter(sample -> sample.host().host().equals(host)
                        && sample.host().port() == port)
                .findFirst()
                .orElseThrow(() -> new AssertionError("nothing recorded for " + host + ":" + port
                        + " - " + HostQuality.snapshot()));
    }

    private static String key(Database database) {
        return switch (database.scheme()) {
            case "postgresql" -> "pg";
            case "sqlserver" -> "mssql";
            default -> database.scheme();
        };
    }

    private static String hostOf(Database database) {
        return System.getProperty("seclume." + key(database) + ".host", TestHosts.database());
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

    private static boolean listening(int port) {
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress("127.0.0.1", port), 500);
            return true;
        } catch (IOException closed) {
            return false;
        }
    }

    private static void reachable(String host, int port) {
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("nothing on " + host + ":" + port);
        }
    }
}
