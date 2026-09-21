package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
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
 * Generated values through seclume and Connector/J, on the same MySQL.
 *
 * <p>The MySQL half of E2, and the one with more to find: of the eight
 * defects the hand-written differential run turned up, five were here, and
 * the worst of them - a {@code bigint unsigned} reading back as -1 - was a
 * value nobody would have written down.
 *
 * <p>Replay a failure with {@code -Dseclume.diff.seed=...}; the seed is in
 * the message and on standard output.
 */
@Timeout(600)
class MySqlPropertyTest {

    private static final String HOST = System.getProperty("seclume.mysql.host",
            TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mysql.port", 3307);
    private static final String DATABASE = "seclume_test";
    private static final String USER = "seclume_test";

    private static String seclumeUrl;
    private static String vendorUrl;
    private static String password;
    private static long seed;
    private static int rows;

    @BeforeAll
    static void findTheServer() throws Exception {
        Path file = locate();
        Assumptions.assumeTrue(file != null, "no .local-mysql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no MySQL on " + HOST + ":" + PORT);
        }
        seed = Long.getLong("seclume.diff.seed", System.nanoTime());
        rows = Integer.getInteger("seclume.diff.rows", 120);
        System.out.println("MySqlPropertyTest seed=" + seed + " rows=" + rows);

        seclumeUrl = "jdbc:seclume:mysql://" + HOST + ":" + PORT + "/" + DATABASE
                + "?user=" + USER + "&allowPublicKeyRetrieval=true&provider=file&path="
                + file.toString().replace('\\', '/');
        vendorUrl = "jdbc:mysql://" + HOST + ":" + PORT + "/" + DATABASE;
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
        run("prop_my_numbers", List.of(
                new Differential.Column("c_int", "int", Values.int32(rows, random)),
                new Differential.Column("c_bigint", "bigint", Values.int64(rows, random)),
                new Differential.Column("c_double", "double", Values.float64(rows, random)),
                new Differential.Column("c_decimal", "decimal(20,6)",
                        Values.decimal(rows, random, 20, 6))));
    }

    @Test
    void generatedTextAgrees() throws Exception {
        Random random = new Random(seed + 1);
        run("prop_my_text", List.of(
                new Differential.Column("c_varchar", "varchar(64)",
                        Values.text(rows, random, 24)),
                new Differential.Column("c_text", "text", Values.text(rows, random, 64))));
    }

    @Test
    void generatedBinaryAgrees() throws Exception {
        Random random = new Random(seed + 2);
        run("prop_my_bytes", List.of(
                new Differential.Column("c_varbinary", "varbinary(64)",
                        Values.bytes(rows, random, 32))));
    }

    @Test
    void generatedTemporalsAgree() throws Exception {
        Random random = new Random(seed + 3);
        run("prop_my_time", List.of(
                new Differential.Column("c_date", "date", Values.dates(rows, random)),
                new Differential.Column("c_datetime6", "datetime(6)",
                        Values.timestamps(rows, random))));
    }

    // --------------------------------------------------------------- running --

    private void run(String table, List<Differential.Column> columns) throws Exception {
        try (Connection mine = seclume(); Connection theirs = vendor()) {
            Differential differential = new Differential(mine, theirs, table);
            MySqlDifferentialTest.allowTheKnownAndHonestDifferences(differential);
            differential.run(columns);

            List<Differential.Finding> findings = differential.findings();
            assertTrue(findings.isEmpty(),
                    () -> "seclume and Connector/J disagree in " + findings.size()
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
        properties.setProperty("allowPublicKeyRetrieval", "true");
        properties.setProperty("useSSL", "false");
        return DriverManager.getConnection(vendorUrl, properties);
    }

    private static Path locate() {
        for (Path candidate : List.of(Path.of(".local-mysql-password"),
                Path.of("..", ".local-mysql-password"))) {
            if (Files.exists(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }
}
