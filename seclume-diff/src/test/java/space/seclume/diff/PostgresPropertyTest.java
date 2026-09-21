package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;
import java.util.Properties;
import java.util.Random;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * The same comparison as {@code PostgresDifferentialTest}, over generated values.
 *
 * <p>E1 asked "do the two drivers agree about the values I thought of". This
 * asks the harder half: <b>do they agree about the values I did not</b>. The
 * difference is not academic - the worst fault E1 turned up was a
 * {@code bigint unsigned} at the top of its range, and no hand-written corpus
 * contains 18446744073709551615 because nobody decides to try it.
 *
 * <p>The property is the same one: seclume and pgjdbc, same server, same
 * value, must say the same thing. What changes is where the values come from -
 * {@link Values} puts the boundaries in first and then draws at random around
 * them.
 *
 * <h2>Reproducing a failure</h2>
 *
 * <p>The seed is printed on every run and repeated in the failure message.
 * To replay one:
 *
 * <pre>
 *   ./mvnw -pl seclume-diff test -Dtest=PostgresPropertyTest -Dseclume.diff.seed=12345
 * </pre>
 *
 * <p>and {@code -Dseclume.diff.rows=500} widens the search when something is
 * suspected but not caught.
 */
@Timeout(600)
class PostgresPropertyTest {

    private static final String DATABASE = "seclume_test";
    private static final String USER = "seclume_test";

    private static String seclumeUrl;
    private static String vendorUrl;
    private static String password;
    private static long seed;
    private static int rows;

    @BeforeAll
    static void findTheServer() throws Exception {
        Path file = locatePasswordFile();
        Assumptions.assumeTrue(file != null,
                "no " + TestHosts.postgresPasswordFile() + " - skipping the property run");
        Assumptions.assumeTrue(reachable(), "no PostgreSQL on "
                + TestHosts.postgres() + ":" + TestHosts.postgresPort());

        seed = Long.getLong("seclume.diff.seed", System.nanoTime());
        rows = Integer.getInteger("seclume.diff.rows", 120);
        System.out.println("PostgresPropertyTest seed=" + seed + " rows=" + rows);

        seclumeUrl = "jdbc:seclume:postgresql://" + TestHosts.postgres() + ":"
                + TestHosts.postgresPort() + "/" + DATABASE + "?user=" + USER
                + "&provider=file&path=" + file.toString().replace('\\', '/');
        vendorUrl = "jdbc:postgresql://" + TestHosts.postgres() + ":"
                + TestHosts.postgresPort() + "/" + DATABASE;
        password = Files.readString(file).trim();
    }

    @AfterAll
    static void forgetIt() {
        password = null;
    }

    // ------------------------------------------------------------ the runs --

    @Test
    void generatedNumbersAgree() throws Exception {
        Random random = new Random(seed);
        run("prop_numbers", List.of(
                new Differential.Column("c_integer", "integer", Values.int32(rows, random)),
                new Differential.Column("c_bigint", "bigint", Values.int64(rows, random)),
                new Differential.Column("c_double", "double precision",
                        Values.float64(rows, random)),
                new Differential.Column("c_numeric", "numeric(20,6)",
                        Values.decimal(rows, random, 20, 6))));
    }

    @Test
    void generatedTextAgrees() throws Exception {
        Random random = new Random(seed + 1);
        run("prop_text", List.of(
                new Differential.Column("c_varchar", "varchar(64)",
                        Values.text(rows, random, 24)),
                new Differential.Column("c_text", "text", Values.text(rows, random, 64))));
    }

    @Test
    void generatedBinaryAgrees() throws Exception {
        Random random = new Random(seed + 2);
        run("prop_bytes", List.of(
                new Differential.Column("c_bytea", "bytea", Values.bytes(rows, random, 32))));
    }

    @Test
    void generatedTemporalsAgree() throws Exception {
        Random random = new Random(seed + 3);
        run("prop_time", List.of(
                new Differential.Column("c_date", "date", Values.dates(rows, random)),
                new Differential.Column("c_timestamp", "timestamp",
                        Values.timestamps(rows, random))));
    }

    // --------------------------------------------------------------- running --

    private void run(String table, List<Differential.Column> columns) throws Exception {
        try (Connection mine = seclume(); Connection theirs = vendor()) {
            Differential differential = new Differential(mine, theirs, table);
            PostgresDifferentialTest.allowTheKnownAndHonestDifferences(differential);
            differential.run(columns);

            List<Differential.Finding> findings = differential.findings();
            assertTrue(findings.isEmpty(),
                    () -> "seclume and pgjdbc disagree in " + findings.size()
                            + " place(s) - replay with -Dseclume.diff.seed=" + seed + ":\n  "
                            + String.join("\n  ", findings.stream().map(Object::toString)
                                    .toList()));
        }
    }

    private static Connection seclume() throws SQLException {
        return DriverManager.getConnection(seclumeUrl);
    }

    private static Connection vendor() throws SQLException {
        Properties properties = new Properties();
        properties.setProperty("user", USER);
        properties.setProperty("password", password);
        return DriverManager.getConnection(vendorUrl, properties);
    }

    private static Path locatePasswordFile() {
        String name = TestHosts.postgresPasswordFile();
        for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
            if (Files.isReadable(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private static boolean reachable() {
        try (java.net.Socket probe = new java.net.Socket()) {
            probe.connect(new java.net.InetSocketAddress(
                    TestHosts.postgres(), TestHosts.postgresPort()), 1000);
            return true;
        } catch (Exception unreachable) {
            return false;
        }
    }
}
