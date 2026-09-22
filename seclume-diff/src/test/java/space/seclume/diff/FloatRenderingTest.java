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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * One rendering for a float, on all four databases.
 *
 * <p>The decision this pins, taken on 22.09.2026. A {@code real} holding
 * 1e20 read back with {@code getString} used to be {@code 1e+20} on
 * PostgreSQL and {@code 1.0E20} on the other three, because PostgreSQL sends
 * a float as characters and the other three send four or eight bytes. So
 * "pass the server's text through" was never a rule the project could keep -
 * only one protocol has a server text to pass on, and the consequence was
 * that the same value read back differently depending on where it came from.
 *
 * <p>Every driver now renders through {@link Float#toString} and
 * {@link Double#toString}, which is also the shortest text that reads back as
 * the same number. {@code numeric} and {@code decimal} are untouched: they are
 * exact decimals, their text is their value, and going through a
 * {@code double} to print one would be the single conversion that loses
 * something.
 *
 * <p>This test compares the four drivers <b>with each other</b> rather than
 * with a vendor. Where a vendor disagrees, that is recorded in its own
 * differential test with the reason - and pgjdbc, notably, disagrees with
 * itself: Java's rendering through a PreparedStatement and the server's
 * through a Statement.
 */
@Timeout(300)
class FloatRenderingTest {

    /**
     * The values where a server's rendering and Java's part company.
     *
     * <p>{@code -0.0f} is in the list and is <b>not</b> compared across
     * databases: Oracle stores it as {@code 0.0} in a {@code binary_float},
     * and its own driver reads back {@code 0.0} too - that is the server, not
     * a rendering. The per-driver invariant below still covers it, which is
     * the better place for it anyway.
     */
    private static final float[] VALUES = {1.1f, 0.1f, -0.0f, 1e20f, 1e-7f, 1234567.0f};

    /** Compared between databases - the values every server keeps unchanged. */
    private static final float[] SHARED = {1.1f, 0.1f, 1e20f, 1e-7f, 1234567.0f};

    private record Database(String name, String key, int port, String scheme, String database,
                            String user, String passwordFile, String options, String query) {
    }

    private static List<Database> databases() {
        return List.of(
                new Database("PostgreSQL", "pg", 5432, "postgresql", "seclume_test",
                        "seclume_test", ".local-pg-password", "&tls=off",
                        "select cast(? as real) as f, cast(? as double precision) as d"),
                new Database("MySQL", "mysql", 3307, "mysql", "seclume_test", "seclume_test",
                        ".local-mysql-password", "&tls=off&allowPublicKeyRetrieval=true",
                        "select cast(? as float) as f, cast(? as double) as d"),
                new Database("SQL Server", "mssql", 1433, "sqlserver", "master", "sa",
                        ".local-mssql-password", "&trustServerCertificate=true",
                        "select cast(? as real) as f, cast(? as float) as d"),
                new Database("Oracle", "oracle", 1521, "oracle", "FREEPDB1", "seclume_test",
                        ".local-oracle-password", "",
                        "select cast(? as binary_float) as f, "
                                + "cast(? as binary_double) as d from dual"));
    }

    @Test
    void everyDriverRendersTheSameFloatTheSameWay() throws Exception {
        Map<String, Map<Float, String>> rendered = new LinkedHashMap<>();
        for (Database database : databases()) {
            Map<Float, String> byValue = read(database);
            if (byValue != null) {
                rendered.put(database.name(), byValue);
            }
        }
        Assumptions.assumeTrue(rendered.size() >= 2,
                "fewer than two databases reachable, and this compares them with each other");

        String first = rendered.keySet().iterator().next();
        Map<Float, String> reference = rendered.get(first);
        List<String> differences = new ArrayList<>();
        for (Map.Entry<String, Map<Float, String>> one : rendered.entrySet()) {
            for (float value : SHARED) {
                String mine = one.getValue().get(value);
                String theirs = reference.get(value);
                if (!String.valueOf(mine).equals(String.valueOf(theirs))) {
                    differences.add(Float.toString(value) + ": " + one.getKey() + "=" + mine
                            + ", " + first + "=" + theirs);
                }
            }
        }
        assertTrue(differences.isEmpty(),
                () -> "the drivers render the same float differently:\n  "
                        + String.join("\n  ", differences));

        // And the rendering is Java's, not merely a shared one - otherwise
        // four drivers agreeing on the wrong thing would pass.
        for (float value : SHARED) {
            assertEquals(Float.toString(value), reference.get(value),
                    "the shared rendering is not Java's");
        }
    }

    /**
     * The invariant underneath the decision: the text is the text of the
     * number.
     *
     * <p>Whatever the server stored, {@code getString} on a float column has
     * to be the text of what {@code getFloat} returns for the same column.
     * That is what "one rendering" means where it can be checked without
     * assuming anything about the server - it holds even for a value the
     * server changed on the way in, which is exactly the case that broke the
     * comparison above.
     */
    @Test
    void theTextIsAlwaysTheTextOfTheNumber() throws Exception {
        List<String> differences = new ArrayList<>();
        int checked = 0;
        for (Database database : databases()) {
            Map<Float, String> asText = read(database);
            Map<Float, Float> asNumber = readNumbers(database);
            if (asText == null || asNumber == null) {
                continue;
            }
            checked++;
            for (float value : VALUES) {
                String expected = Float.toString(asNumber.get(value));
                if (!expected.equals(asText.get(value))) {
                    differences.add(database.name() + " " + value + ": getString="
                            + asText.get(value) + ", getFloat=" + asNumber.get(value));
                }
            }
        }
        Assumptions.assumeTrue(checked > 0, "no database reachable");
        assertTrue(differences.isEmpty(),
                () -> "getString does not render what getFloat returns:" + NEWLINE
                        + String.join(NEWLINE, differences));
    }

    private static final String NEWLINE = System.lineSeparator() + "  ";

    /** The same columns, read as numbers. */
    private static Map<Float, Float> readNumbers(Database database) throws Exception {
        String url = urlOf(database);
        if (url == null) {
            return null;
        }
        Map<Float, Float> byValue = new LinkedHashMap<>();
        try (Connection connection = DriverManager.getConnection(url);
                PreparedStatement statement = connection.prepareStatement(database.query())) {
            for (float value : VALUES) {
                statement.setFloat(1, value);
                statement.setDouble(2, value);
                try (ResultSet rows = statement.executeQuery()) {
                    rows.next();
                    byValue.put(value, rows.getFloat("f"));
                }
            }
        }
        return byValue;
    }

    /** Each value's float column as text, or null when the server is not there. */
    private static Map<Float, String> read(Database database) throws Exception {
        String url = urlOf(database);
        if (url == null) {
            return null;
        }
        Map<Float, String> byValue = new LinkedHashMap<>();
        try (Connection connection = DriverManager.getConnection(url);
                PreparedStatement statement = connection.prepareStatement(database.query())) {
            for (float value : VALUES) {
                statement.setFloat(1, value);
                statement.setDouble(2, value);
                try (ResultSet rows = statement.executeQuery()) {
                    rows.next();
                    byValue.put(value, rows.getString("f"));
                }
            }
        }
        return byValue;
    }

    /** The URL for this database, or null when it is not reachable from here. */
    private static String urlOf(Database database) {
        String host = System.getProperty("seclume." + database.key() + ".host",
                TestHosts.database());
        if (host == null) {
            return null;
        }
        int port = Integer.getInteger("seclume." + database.key() + ".port", database.port());
        String named = System.getProperty("seclume." + database.key() + ".passwordFile",
                database.passwordFile());
        Path file = null;
        for (Path candidate : List.of(Path.of(named), Path.of("..", named))) {
            if (Files.isReadable(candidate)) {
                file = candidate.toAbsolutePath().normalize();
            }
        }
        if (file == null) {
            return null;
        }
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            return null;
        }
        return "jdbc:seclume:" + database.scheme() + "://" + host + ":" + port + "/"
                + database.database() + "?user=" + database.user() + database.options()
                + "&provider=file&path="
                + file.toString().replace(java.io.File.separatorChar, '/');
    }
}
