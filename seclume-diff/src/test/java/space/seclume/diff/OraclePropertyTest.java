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
 * Generated values through seclume and ojdbc, on the same Oracle.
 *
 * <p>Two things about Oracle shape this corpus, and both are the database's
 * doing rather than either driver's:
 *
 * <ul>
 *   <li><b>An empty string is a null.</b> Writing {@code ''} into a
 *       {@code varchar2} stores a null and reads back as one. The generator
 *       produces empty strings and they stay in - what is being checked is
 *       that <b>both</b> drivers report the same thing, not that the value
 *       survives.
 *   <li><b>The bindable range of a double is smaller than the column.</b>
 *       ojdbc routes {@code setObject(Double)} through {@code NUMBER}
 *       whatever the target is, so the corpus is bounded to what the oracle
 *       can be asked - see {@link Values#float64(int, Random, double)}.
 * </ul>
 *
 * <p>The national text goes into {@code nvarchar2}, which is where the worst
 * fault this module has found lived: every value of every such column came
 * back corrupted, because AL16UTF16 was being decoded as UTF-8. That is
 * fixed, and this is the run that keeps it fixed.
 */
@Timeout(600)
class OraclePropertyTest {

    private static final String HOST =
            System.getProperty("seclume.oracle.host", TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.oracle.port", 1521);
    private static final String USER =
            System.getProperty("seclume.oracle.user", "seclume_test");
    private static final String SERVICE =
            System.getProperty("seclume.oracle.service", "FREEPDB1");

    /** What ojdbc will still bind into a binary_double - see the class comment. */
    private static final double BINDABLE = 1.0e120d;

    private static String seclumeUrl;
    private static String vendorUrl;
    private static String password;
    private static long seed;
    private static int rows;

    @BeforeAll
    static void findTheServer() throws Exception {
        Path file = locate();
        Assumptions.assumeTrue(file != null, "no .local-oracle-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no Oracle listener on " + HOST + ":" + PORT);
        }
        seed = Long.getLong("seclume.diff.seed", System.nanoTime());
        rows = Integer.getInteger("seclume.diff.rows", 120);
        System.out.println("OraclePropertyTest seed=" + seed + " rows=" + rows);

        seclumeUrl = "jdbc:seclume:oracle://" + HOST + ":" + PORT + "/" + SERVICE
                + "?user=" + USER + "&provider=file&path="
                + file.toString().replace('\\', '/');
        vendorUrl = "jdbc:oracle:thin:@//" + HOST + ":" + PORT + "/" + SERVICE;
        password = Files.readString(file).trim();
    }

    @AfterAll
    static void forgetIt() {
        password = null;
    }

    @Test
    void generatedNumbersAgree() throws Exception {
        Random random = new Random(seed);
        run("prop_ora_num", List.of(
                new Differential.Column("c_int", "number(10)", Values.int32(rows, random)),
                new Differential.Column("c_long", "number(19)", Values.int64(rows, random)),
                new Differential.Column("c_dec", "number(20,6)",
                        Values.decimal(rows, random, 20, 6)),
                new Differential.Column("c_double", "binary_double",
                        Values.float64(rows, random, BINDABLE))));
    }

    @Test
    void generatedTextAgrees() throws Exception {
        Random random = new Random(seed + 1);
        run("prop_ora_text", List.of(
                new Differential.Column("c_nvarchar", "nvarchar2(64)",
                        Values.text(rows, random, 24)),
                new Differential.Column("c_varchar", "varchar2(256)",
                        Values.text(rows, random, 64))));
    }

    @Test
    void generatedBinaryAgrees() throws Exception {
        Random random = new Random(seed + 2);
        run("prop_ora_bytes", List.of(
                new Differential.Column("c_raw", "raw(64)", Values.bytes(rows, random, 32))));
    }

    @Test
    void generatedTemporalsAgree() throws Exception {
        Random random = new Random(seed + 3);
        run("prop_ora_time", List.of(
                new Differential.Column("c_ts", "timestamp(6)",
                        Values.timestamps(rows, random))));
    }

    private void run(String table, List<Differential.Column> columns) throws Exception {
        try (Connection mine = seclume(); Connection theirs = vendor()) {
            Differential differential = new Differential(mine, theirs, table);
            OracleDifferentialTest.allowTheKnownAndHonestDifferences(differential);
            differential.run(columns);

            List<Differential.Finding> findings = differential.findings();
            assertTrue(findings.isEmpty(),
                    () -> "seclume and ojdbc disagree in " + findings.size()
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

    private static Path locate() {
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.exists(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }
}
