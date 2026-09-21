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
 * Generated values through seclume and mssql-jdbc, on the same SQL Server.
 *
 * <p>The hand-written run here found six defects, more than on any other
 * driver, so this is where a generated corpus has the best chance of finding
 * a seventh.
 *
 * <p>The text corpus goes into {@code nvarchar} rather than {@code varchar}
 * on purpose. A {@code varchar} is a single-byte code page: anything outside
 * it is replaced by the <i>server</i> before either driver sees it, so a
 * disagreement there would be about the collation and not about the two
 * codecs. {@code nvarchar} is UTF-16 and carries everything the generator
 * makes.
 *
 * <p>Replay a failure with {@code -Dseclume.diff.seed=...}.
 */
@Timeout(600)
class SqlServerPropertyTest {

    private static final String HOST =
            System.getProperty("seclume.mssql.host", TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mssql.port", 1433);
    private static final String USER = "sa";

    private static String seclumeUrl;
    private static String vendorUrl;
    private static String password;
    private static long seed;
    private static int rows;

    @BeforeAll
    static void findTheServer() throws Exception {
        Path file = locate();
        Assumptions.assumeTrue(file != null, "no .local-mssql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no SQL Server on " + HOST + ":" + PORT);
        }
        seed = Long.getLong("seclume.diff.seed", System.nanoTime());
        rows = Integer.getInteger("seclume.diff.rows", 120);
        System.out.println("SqlServerPropertyTest seed=" + seed + " rows=" + rows);

        seclumeUrl = "jdbc:seclume:sqlserver://" + HOST + ":" + PORT + "/master"
                + "?user=" + USER + "&trustServerCertificate=true&provider=file&path="
                + file.toString().replace('\\', '/');
        vendorUrl = "jdbc:sqlserver://" + HOST + ":" + PORT
                + ";databaseName=master;encrypt=true;trustServerCertificate=true";
        password = Files.readString(file).trim();
    }

    @AfterAll
    static void forgetIt() {
        password = null;
    }

    @Test
    void generatedNumbersAgree() throws Exception {
        Random random = new Random(seed);
        run("prop_ms_numbers", List.of(
                new Differential.Column("c_int", "int", Values.int32(rows, random)),
                new Differential.Column("c_bigint", "bigint", Values.int64(rows, random)),
                new Differential.Column("c_float", "float", Values.float64(rows, random)),
                new Differential.Column("c_decimal", "decimal(20,6)",
                        Values.decimal(rows, random, 20, 6))));
    }

    @Test
    void generatedTextAgrees() throws Exception {
        Random random = new Random(seed + 1);
        run("prop_ms_text", List.of(
                new Differential.Column("c_nvarchar", "nvarchar(64)",
                        Values.text(rows, random, 24)),
                new Differential.Column("c_nvarchar_long", "nvarchar(256)",
                        Values.text(rows, random, 64))));
    }

    @Test
    void generatedBinaryAgrees() throws Exception {
        Random random = new Random(seed + 2);
        run("prop_ms_bytes", List.of(
                new Differential.Column("c_varbinary", "varbinary(64)",
                        Values.bytes(rows, random, 32))));
    }

    @Test
    void generatedTemporalsAgree() throws Exception {
        Random random = new Random(seed + 3);
        run("prop_ms_time", List.of(
                new Differential.Column("c_date", "date", Values.dates(rows, random)),
                new Differential.Column("c_datetime2", "datetime2(6)",
                        Values.timestamps(rows, random))));
    }

    private void run(String table, List<Differential.Column> columns) throws Exception {
        try (Connection mine = seclume(); Connection theirs = vendor()) {
            Differential differential = new Differential(mine, theirs, table);
            SqlServerDifferentialTest.allowTheKnownAndHonestDifferences(differential);
            differential.run(columns);

            List<Differential.Finding> findings = differential.findings();
            assertTrue(findings.isEmpty(),
                    () -> "seclume and mssql-jdbc disagree in " + findings.size()
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
        for (Path candidate : List.of(Path.of(".local-mssql-password"),
                Path.of("..", ".local-mssql-password"))) {
            if (Files.exists(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }
}
