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
 * seclume against mssql-jdbc, on the same SQL Server, over the same values.
 *
 * <p>The third oracle. TDS is the protocol least like the other two - the
 * types are sent with their own precision and scale in the row description
 * rather than inferred from a catalogue, {@code datetime} and
 * {@code datetime2} are different types with different resolutions, and
 * {@code nvarchar} is UTF-16 on the wire where {@code varchar} is not. Each of
 * those is somewhere a hand-written codec can be self-consistent and still
 * wrong.
 *
 * <p>{@code money}, {@code smalldatetime} and {@code uniqueidentifier} are in
 * the corpus because they have no counterpart in the other two databases and
 * therefore no shared code to have been exercised already.
 */
@Timeout(300)
class SqlServerDifferentialTest {

    private static final String HOST =
            System.getProperty("seclume.mssql.host", TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mssql.port", 1433);
    private static final String USER = "sa";

    private static String seclumeUrl;
    private static String vendorUrl;
    private static String password;

    @BeforeAll
    static void findTheServer() throws Exception {
        Path file = locate();
        Assumptions.assumeTrue(file != null, "no .local-mssql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no SQL Server on " + HOST + ":" + PORT);
        }
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

    static Connection seclume() throws SQLException {
        return DriverManager.getConnection(seclumeUrl);
    }

    static Connection vendor() throws SQLException {
        Properties properties = new Properties();
        properties.setProperty("user", USER);
        properties.setProperty("password", password);
        return DriverManager.getConnection(vendorUrl, properties);
    }

    // ----------------------------------------------------------- the corpus --

    @Test
    void integersAgree() throws Exception {
        run("diff_ms_ints", List.of(
                // tinyint is unsigned in SQL Server and signed nowhere else -
                // 0 to 255, so the Java byte it does not fit into is the
                // interesting part.
                Differential.Column.of("c_tinyint", "tinyint", 0, 1, 127, 255, null),
                Differential.Column.of("c_smallint", "smallint",
                        (short) 0, Short.MIN_VALUE, Short.MAX_VALUE, null),
                Differential.Column.of("c_int", "int",
                        0, Integer.MIN_VALUE, Integer.MAX_VALUE, null),
                Differential.Column.of("c_bigint", "bigint",
                        0L, Long.MIN_VALUE, Long.MAX_VALUE, null),
                Differential.Column.of("c_bit", "bit", true, false, null)));
    }

    @Test
    void decimalsAndFloatsAgree() throws Exception {
        run("diff_ms_numbers", List.of(
                Differential.Column.of("c_decimal", "decimal(20,6)",
                        new BigDecimal("0.000000"), new BigDecimal("-1.500000"),
                        new BigDecimal("12345678901234.123456"), null),
                // money has a fixed scale of four and is its own wire type.
                Differential.Column.of("c_money", "money",
                        new BigDecimal("0.0000"), new BigDecimal("-1.5000"),
                        new BigDecimal("922337203685477.5807"), null),
                Differential.Column.of("c_real", "real", 0.0f, -0.0f, 1.5f, null),
                Differential.Column.of("c_float", "float",
                        0.0d, -0.0d, 1.0d / 3.0d, null)));
    }

    @Test
    void textAgrees() throws Exception {
        run("diff_ms_text", List.of(
                Differential.Column.of("c_varchar", "varchar(64)",
                        "", " ", "trailing ", "quote'double\"", null),
                // nvarchar is UTF-16 on the wire and the only one of the two
                // that can carry anything outside the code page.
                Differential.Column.of("c_nvarchar", "nvarchar(64)",
                        "", "grüß", "€ 中文", "😀", null),
                Differential.Column.of("c_char", "char(8)", "", "abc", "12345678", null)));
    }

    @Test
    void temporalsAgree() throws Exception {
        run("diff_ms_time", List.of(
                Differential.Column.of("c_date", "date",
                        Date.valueOf("2026-09-21"), Date.valueOf("1970-01-01"), null),
                // datetime rounds to 1/300 of a second - a genuine oddity, and
                // a place two drivers can round differently.
                Differential.Column.of("c_datetime", "datetime",
                        Timestamp.valueOf("2026-09-21 12:00:00"),
                        Timestamp.valueOf("2026-09-21 12:00:00.003"), null),
                Differential.Column.of("c_datetime2", "datetime2(6)",
                        Timestamp.valueOf("2026-09-21 12:00:00"),
                        Timestamp.valueOf("2026-09-21 12:00:00.123456"), null)));
    }

    @Test
    void binaryAndGuidsAgree() throws Exception {
        run("diff_ms_bytes", List.of(
                Differential.Column.of("c_varbinary", "varbinary(32)",
                        new byte[0], new byte[] {0},
                        new byte[] {0, 1, 2, (byte) 0xff, (byte) 0x80}, null),
                // uniqueidentifier is stored in a mixed byte order that every
                // driver has to undo the same way, or the same row reads as
                // two different GUIDs.
                Differential.Column.of("c_guid", "uniqueidentifier",
                        "00000000-0000-0000-0000-000000000000",
                        "0F8FAD5B-D9CB-469F-A165-70867728950E", null)));
    }

    // --------------------------------------------------------------- running --

    private void run(String table, List<Differential.Column> columns) throws Exception {
        try (Connection mine = seclume(); Connection theirs = vendor()) {
            Differential differential = new Differential(mine, theirs, table);
            allowTheKnownAndHonestDifferences(differential);
            differential.run(columns);

            List<Differential.Finding> findings = differential.findings();
            assertTrue(findings.isEmpty(),
                    () -> "seclume and mssql-jdbc disagree in " + findings.size()
                            + " place(s):\n  " + String.join("\n  ",
                                    findings.stream().map(Object::toString).toList()));
        }
    }

    /**
     * Written after the first run, never before it.
     *
     * <p>That run produced findings in nine classes. Six were seclume bugs
     * and are fixed:
     *
     * <ul>
     *   <li><b>{@code getPrecision} answered with the wire width.</b> An
     *       {@code int} was 4 and a {@code bigint} 8, where JDBC means 10 and
     *       19 digits - wrong on seven types at once, which is what a
     *       systematic mistake looks like.
     *   <li><b>{@code getScale} was 0 for {@code money} and
     *       {@code datetime}</b>, which carry four and three decimal places
     *       that the wire never mentions.
     *   <li><b>{@code getString} on a {@code varbinary} decoded the bytes as
     *       characters</b> and returned mojibake. Hex now, as mssql-jdbc does.
     *   <li><b>A {@code uniqueidentifier} came back in lower case</b>, and a
     *       GUID that differs only in case still compares unequal.
     *   <li><b>{@code nvarchar} was reported as {@code Types.VARCHAR}</b>,
     *       losing the one fact that distinguishes a national type.
     *   <li><b>{@code getColumns} answered 0 for the size of a bit, a date
     *       and a uniqueidentifier</b> while {@code ResultSetMetaData}
     *       answered 1, 10 and 36 - the third driver with the same split
     *       between the catalogue and the result set.
     * </ul>
     *
     * <p>The three below are differences of convention.
     */
    static void allowTheKnownAndHonestDifferences(Differential differential) {
        differential
                .allow("getColumns.DECIMAL_DIGITS",
                        "seclume answers 0 where a type has no fractional digits, mssql-jdbc "
                        + "answers null. The same convention difference as on MySQL, and "
                        + "seclume is at least the same on both.")
                .allow("c_bit.columnType",
                        "seclume answers Types.BOOLEAN (16) for a bit column, mssql-jdbc "
                        + "answers Types.BIT (-7) - and so does pgjdbc for a PostgreSQL "
                        + "boolean. Both vendors keep the pre-JDBC-3 type; seclume reports "
                        + "BOOLEAN for a two-valued column in all four of its drivers. Being "
                        + "the same everywhere is worth more here than matching each vendor's "
                        + "own history, and the value itself - a Boolean - agrees.")
                .allow("c_bit.getColumns.DATA_TYPE", "the same decision, in the catalogue.")
                .allow("c_bit.getColumns.NUM_PREC_RADIX",
                        "seclume gives a bit no radix, mssql-jdbc gives it 10. A radix is a "
                        + "property of a number.")
                .allow("c_tinyint.columnClassName",
                        "mssql-jdbc answers java.lang.Short for tinyint and smallint; seclume "
                        + "answers Integer. JDBC 4.3 table B-3 maps both to Integer, and "
                        + "pgjdbc does the same - so here the two vendor oracles disagree "
                        + "with each other and the specification breaks the tie. Worth "
                        + "recording because the PostgreSQL run pushed seclume the other way "
                        + "on the same question: there seclume said Short and was wrong.")
                .allow("c_smallint.columnClassName", "the same.")
                .allow("c_datetime.getString",
                        "a datetime rounds to 1/300 of a second and seclume prints the three "
                        + "decimals the type has, mssql-jdbc prints Timestamp.toString, which "
                        + "gives one. The instant is the same in both.");
    }

    static Path locate() {
        for (Path candidate : List.of(Path.of(".local-mssql-password"),
                Path.of("..", ".local-mssql-password"))) {
            if (Files.exists(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }
}
