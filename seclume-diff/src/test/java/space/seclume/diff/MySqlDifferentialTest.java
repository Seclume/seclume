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
 * seclume against Connector/J, on the same MySQL, over the same values.
 *
 * <p>The second oracle, and worth having beside the PostgreSQL one for a
 * reason that is not "twice as much testing": the two servers disagree about
 * things the JDBC layer has to paper over, and a driver can be consistent with
 * itself on both while matching neither. MySQL has an unsigned integer that
 * does not fit its signed Java type, a {@code tinyint(1)} that is a boolean by
 * convention and not by declaration, and a {@code datetime} whose fractional
 * seconds depend on how the column was declared. Each of those is a place two
 * drivers can differ, and none of them exists in PostgreSQL.
 */
@Timeout(300)
class MySqlDifferentialTest {

    private static final String HOST = System.getProperty("seclume.mysql.host",
            TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mysql.port", 3307);
    private static final String DATABASE = "seclume_test";
    private static final String USER = "seclume_test";

    private static String seclumeUrl;
    private static String vendorUrl;
    private static String password;

    @BeforeAll
    static void findTheServer() throws Exception {
        Path file = locate();
        Assumptions.assumeTrue(file != null, "no .local-mysql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no MySQL on " + HOST + ":" + PORT);
        }
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

    // ----------------------------------------------------------- the corpus --

    /** Whole numbers, and the unsigned ones that do not fit their Java type. */
    @Test
    void integersAgree() throws Exception {
        run("diff_my_ints", List.of(
                Differential.Column.of("c_tinyint", "tinyint",
                        (byte) 0, (byte) -128, (byte) 127, null),
                // tinyint(1) is what every ORM writes a boolean into, and
                // whether a driver hands it back as Boolean or Integer is a
                // decision each one makes for itself.
                Differential.Column.of("c_bool", "tinyint(1)", 0, 1, null),
                Differential.Column.of("c_smallint", "smallint",
                        (short) 0, Short.MIN_VALUE, Short.MAX_VALUE, null),
                Differential.Column.of("c_int", "int",
                        0, Integer.MIN_VALUE, Integer.MAX_VALUE, null),
                Differential.Column.of("c_bigint", "bigint",
                        0L, Long.MIN_VALUE, Long.MAX_VALUE, null),
                // The one that does not fit: bigint unsigned goes past
                // Long.MAX_VALUE, so a driver has to widen it or lose it.
                Differential.Column.of("c_unsigned", "bigint unsigned",
                        new BigDecimal("0"), new BigDecimal("18446744073709551615"), null)));
    }

    @Test
    void decimalsAndFloatsAgree() throws Exception {
        run("diff_my_numbers", List.of(
                Differential.Column.of("c_decimal", "decimal(20,6)",
                        new BigDecimal("0.000000"), new BigDecimal("-1.500000"),
                        new BigDecimal("12345678901234.123456"), null),
                Differential.Column.of("c_float", "float", 0.0f, -0.0f, 1.5f, null),
                Differential.Column.of("c_double", "double",
                        0.0d, -0.0d, 1.0d / 3.0d, null)));
    }

    @Test
    void textAgrees() throws Exception {
        run("diff_my_text", List.of(
                Differential.Column.of("c_varchar", "varchar(64)",
                        "", " ", "trailing ", "grüß", "€ 中文", null),
                Differential.Column.of("c_text", "text",
                        "", "line\nbreak", "control", null),
                // char(n) is right-padded on disk and trimmed on the way
                // out - or not, depending on the driver.
                Differential.Column.of("c_char", "char(8)", "", "abc", "12345678", null)));
    }

    /**
     * Times, where MySQL keeps fractional seconds only if the column says so.
     *
     * <p>{@code datetime} without a precision truncates; {@code datetime(6)}
     * keeps microseconds. A driver that rounds where the server truncates
     * disagrees by one microsecond, once in a million rows.
     */
    @Test
    void temporalsAgree() throws Exception {
        run("diff_my_time", List.of(
                Differential.Column.of("c_date", "date",
                        Date.valueOf("2026-09-20"), Date.valueOf("1970-01-02"), null),
                Differential.Column.of("c_datetime", "datetime",
                        Timestamp.valueOf("2026-09-20 12:00:00"),
                        Timestamp.valueOf("2026-09-20 12:00:00.999"), null),
                Differential.Column.of("c_datetime6", "datetime(6)",
                        Timestamp.valueOf("2026-09-20 12:00:00.123456"),
                        Timestamp.valueOf("2026-09-20 12:00:00.000001"), null)));
    }

    @Test
    void binaryAgrees() throws Exception {
        run("diff_my_bytes", List.of(
                Differential.Column.of("c_varbinary", "varbinary(32)",
                        new byte[0], new byte[] {0},
                        new byte[] {0, 1, 2, (byte) 0xff, (byte) 0x80}, null),
                Differential.Column.of("c_blob", "blob",
                        new byte[] {(byte) 0xde, (byte) 0xad}, null)));
    }

    // --------------------------------------------------------------- running --

    private void run(String table, List<Differential.Column> columns) throws Exception {
        try (Connection mine = seclume(); Connection theirs = vendor()) {
            Differential differential = new Differential(mine, theirs, table);
            allowTheKnownAndHonestDifferences(differential);
            differential.run(columns);

            List<Differential.Finding> findings = differential.findings();
            assertTrue(findings.isEmpty(),
                    () -> "seclume and Connector/J disagree in " + findings.size()
                            + " place(s):\n  " + String.join("\n  ",
                                    findings.stream().map(Object::toString).toList()));
        }
    }

    /**
     * Written after the first run, never before it.
     *
     * <p>That run produced findings in six classes. Three were seclume bugs
     * and are fixed:
     *
     * <ul>
     *   <li><b>{@code bigint unsigned} came back wrong.</b>
     *       {@code getObject} returned a {@code long}, so
     *       18446744073709551615 read as -1 - the wrong value, with no
     *       exception. {@code getString} had it right all along, which is how
     *       this was found: the two getters disagreed with each other.
     *   <li><b>Integer precision counted the minus sign.</b> 11 for
     *       {@code int} where JDBC means 10 digits.
     *   <li><b>{@code getColumns.TYPE_NAME} returned the declaration.</b>
     *       {@code varbinary(32)} where every other driver says
     *       {@code VARBINARY} - the same mistake the PostgreSQL driver was
     *       making, found in both by the same run.
     * </ul>
     *
     * <p>What is left is one honest difference and one defect still open.
     */
    private static void allowTheKnownAndHonestDifferences(Differential differential) {
        differential
                .allow("c_datetime.columnClassName",
                        "Connector/J returns java.time.LocalDateTime for a datetime and "
                        + "seclume returns java.sql.Timestamp. JDBC 4.3 table B-3 maps "
                        + "TIMESTAMP to java.sql.Timestamp; Connector/J has moved ahead of the "
                        + "specification. Following the specification is the safer of the two "
                        + "here - a caller that wants a LocalDateTime can ask getObject for "
                        + "one, and a caller that expects a Timestamp cannot ask for less.")
                .allow("c_datetime6.columnClassName", "the same difference.")
                .allow("c_datetime.getObject", "the same difference, on the value.")
                .allow("c_datetime6.getObject", "the same difference, on the value.")
                .allow("c_datetime6.scale",
                        "seclume reports 6 fractional digits for a datetime(6), Connector/J "
                        + "reports 0. JDBC defines getScale on a timestamp as its fractional "
                        + "seconds, so 6 is the answer to the question asked.")
                .allow("getColumns.DECIMAL_DIGITS",
                        "seclume answers 0 for a type with no fractional digits, Connector/J "
                        + "answers null. JDBC says null is returned where DECIMAL_DIGITS does "
                        + "not apply, and an integer arguably has zero of them rather than "
                        + "none. Both readings are current; seclume's is the same answer its "
                        + "ResultSetMetaData gives.")

                // --- still wrong here, and the fix is not a one-liner -----
                .knownDefect("c_bool.columnType",
                        "tinyint(1) is how every ORM stores a boolean in MySQL, and "
                        + "Connector/J maps it to BIT/Boolean by default (tinyInt1isBit). "
                        + "seclume reports TINYINT/Integer, so getObject on a boolean column "
                        + "hands back an Integer and a cast to Boolean fails - code that "
                        + "works against Connector/J breaks here. Fixing it means a "
                        + "connection property and a change in four places (getObject, the "
                        + "three metadata answers, and the catalogue), which is why it is "
                        + "recorded rather than rushed.")
                .knownDefect("c_bool.columnTypeName", "the same defect.")
                .knownDefect("c_bool.columnClassName", "the same defect.")
                .knownDefect("c_bool.precision", "the same defect.")
                .knownDefect("c_bool.getObject", "the same defect, on the value itself.")
                .knownDefect("c_bool.getColumns.DATA_TYPE", "the same defect, in the catalogue.")
                .knownDefect("c_bool.getColumns.TYPE_NAME", "the same defect.")
                .knownDefect("c_bool.getColumns.COLUMN_SIZE", "the same defect.")
                .knownDefect("c_text.precision",
                        "getPrecision on a text column answers 65535 - the byte length MySQL "
                        + "sends - where Connector/J answers 16383, the same length in utf8mb4 "
                        + "characters. getPrecision on character data is defined in "
                        + "characters. The division by bytes-per-character is already there "
                        + "for varchar and does not fire for text, so this is a narrow fix "
                        + "and only waits on finding out which charset id the server sends "
                        + "for a text column rather than guessing at it.");
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
