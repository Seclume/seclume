package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigDecimal;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Date;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * seclume against ojdbc, on the same Oracle, over the same values.
 *
 * <p>The fourth oracle and the one least like the others. Oracle has a single
 * numeric type - {@code NUMBER} carries integers, decimals and floats alike
 * and its precision is declared rather than implied by a width - its
 * {@code DATE} has a time of day in it, and an empty string is a null. None of
 * that has a counterpart in the other three, so none of the shared code has
 * been exercised on it.
 *
 * <p>The empty string is worth its own note: writing {@code ''} into a
 * {@code varchar2} stores a null, and reading it back gives null. That is
 * Oracle's own behaviour and not a driver's - the point of having it in the
 * corpus is that <b>both</b> drivers have to report it the same way.
 */
@Timeout(300)
class OracleDifferentialTest {

    private static final String HOST =
            System.getProperty("seclume.oracle.host", TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.oracle.port", 1521);
    private static final String USER =
            System.getProperty("seclume.oracle.user", "seclume_test");
    private static final String SERVICE =
            System.getProperty("seclume.oracle.service", "FREEPDB1");

    private static String seclumeUrl;
    private static String vendorUrl;
    private static String password;

    @BeforeAll
    static void findTheServer() throws Exception {
        Path file = locate();
        Assumptions.assumeTrue(file != null, "no .local-oracle-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no Oracle listener on " + HOST + ":" + PORT);
        }
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

    private static Connection seclume() throws SQLException {
        return DriverManager.getConnection(seclumeUrl);
    }

    private static Connection vendor() throws SQLException {
        Properties properties = new Properties();
        properties.setProperty("user", USER);
        properties.setProperty("password", password);
        return DriverManager.getConnection(vendorUrl, properties);
    }

    // ----------------------------------------------------------- the corpus --

    /**
     * {@code NUMBER}, in the three shapes it takes.
     *
     * <p>Declared without precision it is whatever was put in it, which is
     * where two drivers most easily disagree about what to hand back.
     */
    @Test
    void numbersAgree() throws Exception {
        run("diff_ora_num", List.of(
                Differential.Column.of("c_int", "number(10)",
                        0, -1, Integer.MIN_VALUE, Integer.MAX_VALUE, null),
                Differential.Column.of("c_long", "number(19)",
                        0L, -1L, Long.MIN_VALUE, Long.MAX_VALUE, null),
                Differential.Column.of("c_dec", "number(20,6)",
                        new BigDecimal("0.000000"), new BigDecimal("-1.500000"),
                        new BigDecimal("12345678901234.123456"), null),
                // The range stops at what ojdbc can bind, not at what the
                // column can hold. setObject on a Double routes through
                // NUMBER in ojdbc whatever the target type is, so anything
                // past about 1e125 throws IllegalArgumentException
                // "Overflow" before it reaches the server - even into a
                // binary_double, which holds it comfortably. seclume takes
                // Double.MAX_VALUE without complaint; there is simply no
                // oracle to check it against.
                Differential.Column.of("c_double", "binary_double",
                        0.0d, -0.0d, 1.0d / 3.0d, 1.0e120d, null),
                Differential.Column.of("c_float", "binary_float",
                        0.0f, -0.0f, 1.5f, null)));
    }

    @Test
    void textAgrees() throws Exception {
        run("diff_ora_text", List.of(
                Differential.Column.of("c_varchar", "varchar2(64)",
                        " ", "trailing ", "quote'double\"", null),
                Differential.Column.of("c_nvarchar", "nvarchar2(64)",
                        "grüß", "€ 中文", null),
                Differential.Column.of("c_char", "char(8)", "abc", "12345678", null)));
    }

    /**
     * {@code DATE} carries a time of day, which surprises everyone once.
     *
     * <p>So a {@code java.sql.Date} written into one and read back is not
     * obviously the same thing, and the two drivers have to agree about what
     * it became.
     */
    @Test
    void temporalsAgree() throws Exception {
        run("diff_ora_time", List.of(
                Differential.Column.of("c_date", "date",
                        Date.valueOf("2026-09-21"), Date.valueOf("1970-01-01"), null),
                Differential.Column.of("c_ts", "timestamp(6)",
                        Timestamp.valueOf("2026-09-21 12:00:00"),
                        Timestamp.valueOf("2026-09-21 12:00:00.123456"), null)));
    }

    @Test
    void binaryAgrees() throws Exception {
        run("diff_ora_bytes", List.of(
                Differential.Column.of("c_raw", "raw(32)",
                        new byte[] {0},
                        new byte[] {0, 1, 2, (byte) 0xff, (byte) 0x80}, null)));
    }

    // --------------------------------------------------------------- running --

    private void run(String table, List<Differential.Column> columns) throws Exception {
        try (Connection mine = seclume(); Connection theirs = vendor()) {
            Differential differential = new Differential(mine, theirs, table);
            allowTheKnownAndHonestDifferences(differential);
            differential.run(columns);

            List<Differential.Finding> findings = differential.findings();
            assertTrue(findings.isEmpty(),
                    () -> "seclume and ojdbc disagree in " + findings.size() + " place(s):\n  "
                            + String.join("\n  ", findings.stream().map(Object::toString)
                                    .toList()));
        }
    }

    /**
     * Written after the first run, never before it.
     *
     * <p>That run produced findings in seven classes. Five were seclume bugs
     * and are fixed, and the first of them is the worst thing this whole
     * module has turned up:
     *
     * <ul>
     *   <li><b>Every {@code NVARCHAR2} value came back corrupted.</b> Oracle
     *       sends the national types in AL16UTF16 and seclume decoded them as
     *       UTF-8, so "gr&uuml;&szlig;" arrived as {@code \u0000g\u0000r} and two
     *       replacement characters. The column had been saying which
     *       character set it was in since the driver was written; nothing
     *       asked it. Silent text corruption, on ordinary text.
     *   <li><b>{@code nvarchar2} was reported as {@code VARCHAR2}</b> -
     *       Oracle sends one wire type for both and only the character set
     *       separates them.
     *   <li><b>{@code getString} on a {@code raw} decoded the bytes as
     *       characters</b>, and {@code getObject} returned that string while
     *       {@code getColumnClassName} promised {@code [B}.
     *   <li><b>{@code getPrecision} was 0 for every date and timestamp</b>,
     *       and for a {@code raw}.
     *   <li><b>{@code getColumnClassName} answered String for everything
     *       that was not a number</b> - raw, date, timestamp, float, boolean
     *       alike.
     * </ul>
     *
     * <p>The two below are conventions, and both are places where ojdbc
     * answers with something only ojdbc can use.
     */
    static void allowTheKnownAndHonestDifferences(Differential differential) {
        differential
                .allow("c_date.precision",
                        "ojdbc answers 7 for a DATE and 0 for a TIMESTAMP - 7 being the "
                        + "internal byte length of an Oracle date, which is not a number of "
                        + "characters and not something a caller can lay out a column with. "
                        + "seclume answers the printed width, 19 and 26, which is what its "
                        + "other three drivers answer for the same shape of value.")
                .allow("c_ts.precision", "the same.")
                .allow("c_ts.columnClassName",
                        "ojdbc names oracle.sql.TIMESTAMP, its own class. seclume names "
                        + "java.sql.Timestamp, which is what it returns and what any other "
                        + "driver would name. Matching would mean promising a class that is "
                        + "not on the class path unless ojdbc is.")
                .allow("c_double.columnType",
                        "ojdbc answers 101 and 100 for binary_double and binary_float - "
                        + "OracleTypes constants, outside java.sql.Types. seclume answers "
                        + "DOUBLE and REAL. A caller switching on java.sql.Types sees nothing "
                        + "it recognises in the vendor codes.")
                .allow("c_float.columnType", "the same.");
    }

    static Path locate() {
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.exists(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }
}
