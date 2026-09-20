package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
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
 * seclume against pgjdbc, on the same PostgreSQL, over the same values.
 *
 * <p>Every value here is written by one driver and read by both, in both
 * directions - see {@link Differential} for why the crossed pairs are the ones
 * that matter. Anything the two drivers disagree about is reported with the
 * column, the value and both answers.
 *
 * <p>The corpus is deliberately made of the values nobody types into a test by
 * hand: a {@code numeric} with a scale that does not fit its declaration, an
 * empty string next to a null, a timestamp on a microsecond boundary, a byte
 * array containing a zero byte, text that is not Latin-1. Those are where
 * codecs differ, and they are exactly what a hand-written assertion never
 * covers because the author has to think of them first.
 */
@Timeout(300)
class PostgresDifferentialTest {

    private static final String DATABASE = "seclume_test";
    private static final String USER = "seclume_test";

    private static String seclumeUrl;
    private static String vendorUrl;
    private static String password;

    @BeforeAll
    static void findTheServer() throws Exception {
        Path file = locatePasswordFile();
        Assumptions.assumeTrue(file != null,
                "no " + TestHosts.postgresPasswordFile() + " - skipping the differential run");
        Assumptions.assumeTrue(reachable(), "no PostgreSQL on "
                + TestHosts.postgres() + ":" + TestHosts.postgresPort());

        seclumeUrl = "jdbc:seclume:postgresql://" + TestHosts.postgres() + ":"
                + TestHosts.postgresPort() + "/" + DATABASE + "?user=" + USER
                + "&provider=file&path=" + file.toString().replace('\\', '/');
        vendorUrl = "jdbc:postgresql://" + TestHosts.postgres() + ":"
                + TestHosts.postgresPort() + "/" + DATABASE;
        // pgjdbc has no way to take a password from a file, which is the whole
        // reason this library exists. In a test whose job is to compare
        // behaviour that is acceptable and worth stating: the vendor
        // connection is the measuring stick, not the thing being shipped.
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

    /** Numbers, and the places where two codecs stop agreeing. */
    @Test
    void numbersAgree() throws Exception {
        run("diff_numbers", List.of(
                Differential.Column.of("c_smallint", "smallint",
                        (short) 0, (short) -1, Short.MIN_VALUE, Short.MAX_VALUE, null),
                Differential.Column.of("c_integer", "integer",
                        0, -1, Integer.MIN_VALUE, Integer.MAX_VALUE, null),
                Differential.Column.of("c_bigint", "bigint",
                        0L, -1L, Long.MIN_VALUE, Long.MAX_VALUE, null),
                Differential.Column.of("c_numeric", "numeric(20,6)",
                        new BigDecimal("0.000000"),
                        new BigDecimal("-1.500000"),
                        new BigDecimal("12345678901234.123456"),
                        // A scale the column cannot hold: the server rounds,
                        // and the two drivers have to agree on what came back.
                        new BigDecimal("0.0000005"),
                        null),
                Differential.Column.of("c_real", "real",
                        0.0f, -0.0f, 1.5f, Float.MAX_VALUE, null),
                Differential.Column.of("c_double", "double precision",
                        0.0d, -0.0d, 1.0d / 3.0d, Double.MAX_VALUE, null)));
    }

    /** Text, including the parts of it that are not ASCII. */
    @Test
    void textAgrees() throws Exception {
        run("diff_text", List.of(
                Differential.Column.of("c_varchar", "varchar(64)",
                        "", " ", "trailing ", "grüß", "€ 中文",
                        "quote'and\"double", null),
                Differential.Column.of("c_text", "text",
                        "", "line\nbreak", "tab\there", "control", null, "x".repeat(64)),
                // char(n) is space-padded by the server, and how a driver
                // reports that padding is a classic disagreement.
                Differential.Column.of("c_char", "char(8)",
                        "", "abc", "12345678", null, "  ", null)));
    }

    /** Dates and times, where precision is where drivers part company. */
    @Test
    void temporalsAgree() throws Exception {
        run("diff_time", List.of(
                Differential.Column.of("c_date", "date",
                        Date.valueOf("2026-09-20"), Date.valueOf("1970-01-01"),
                        Date.valueOf("0001-01-02"), null),
                Differential.Column.of("c_timestamp", "timestamp",
                        Timestamp.valueOf("2026-09-20 12:00:00"),
                        Timestamp.valueOf("2026-09-20 12:00:00.123456"),
                        // One digit past what PostgreSQL stores: it rounds to
                        // microseconds, and both drivers must show the same.
                        Timestamp.valueOf("2026-09-20 12:00:00.1234567"),
                        Timestamp.valueOf("1970-01-01 00:00:00"),
                        null)));
    }

    /** Bytes and booleans, including the zero byte that ends a C string. */
    @Test
    void bytesAndBooleansAgree() throws Exception {
        run("diff_bytes", List.of(
                Differential.Column.of("c_bool", "boolean", true, false, null),
                Differential.Column.of("c_bytea", "bytea",
                        new byte[0],
                        new byte[] {0},
                        new byte[] {0, 1, 2, (byte) 0xff, (byte) 0x80},
                        null)));
    }

    // --------------------------------------------------------------- running --

    private void run(String table, List<Differential.Column> columns) throws Exception {
        try (Connection mine = seclume(); Connection theirs = vendor()) {
            Differential differential = new Differential(mine, theirs, table);
            allowTheKnownAndHonestDifferences(differential);
            differential.run(columns);

            List<Differential.Finding> findings = differential.findings();
            assertTrue(findings.isEmpty(),
                    () -> "seclume and pgjdbc disagree in " + findings.size() + " place(s):\n  "
                            + String.join("\n  ", findings.stream().map(Object::toString)
                                    .toList()));
        }
    }

    /**
     * Where the two may honestly differ, one entry at a time.
     *
     * <p>Written after the first run rather than before it: an allow-list
     * drawn up in advance is a way of not looking. That run produced findings
     * in six classes. Two were seclume bugs and were fixed — {@code getObject}
     * on a {@code smallint} returned a {@code Short} where JDBC 4.3 table B-3
     * and every other driver say {@code Integer}, and
     * {@code DatabaseMetaData.getColumns} computed sizes differently from
     * {@code ResultSetMetaData}, so the same driver gave two answers about the
     * same column. The four below are differences of convention, and each one
     * says which driver is doing what.
     */
    private static void allowTheKnownAndHonestDifferences(Differential differential) {
        differential
                .allow("c_bool.columnType",
                        "seclume answers Types.BOOLEAN (16), pgjdbc answers Types.BIT (-7). "
                        + "JDBC 4 maps a boolean column to BOOLEAN; pgjdbc keeps BIT for "
                        + "compatibility with code written before JDBC 3. seclume is right "
                        + "here and changing it to match would be adopting somebody else's "
                        + "backwards compatibility.")
                .allow("c_bool.getColumns.DATA_TYPE", "the same difference, in the catalogue.")
                .allow("isNullable",
                        "seclume answers columnNullableUnknown (2), pgjdbc answers "
                        + "columnNullable (1). PostgreSQL does not put nullability in the "
                        + "RowDescription, so pgjdbc finds it out with a catalogue query per "
                        + "result set. seclume does not make that round trip and says it does "
                        + "not know, which is what the constant is for. The catalogue, which "
                        + "is what Hibernate and Flyway actually read, answers correctly in "
                        + "both drivers - NULLABLE and IS_NULLABLE agree.")
                .allow("c_text.precision",
                        "an unbounded text column has no specified size. seclume answers 0 "
                        + "(not specified), pgjdbc answers Integer.MAX_VALUE (as long as you "
                        + "like). Both conventions are in use; seclume's is the same answer "
                        + "its own COLUMN_SIZE gives, which matters more than matching.")
                .allow("c_bytea.precision", "the same, for bytea.")
                .allow("c_text.getColumns.COLUMN_SIZE", "the same, in the catalogue.")
                .allow("c_bytea.getColumns.COLUMN_SIZE", "the same, for bytea.")
                .allow("c_real.scale",
                        "pgjdbc reports 8 and 17 decimal digits for real and double precision. "
                        + "JDBC says getScale returns 0 where a scale does not apply, and it "
                        + "does not apply to a binary floating point type. The precision both "
                        + "drivers report is the same 8 and 17.")
                .allow("c_double.scale", "the same, for double precision.")
                .allow("c_real.getColumns.DECIMAL_DIGITS", "the same, in the catalogue.")
                .allow("c_double.getColumns.DECIMAL_DIGITS", "the same, for double precision.")

                // The two below turned up only once the run started reading
                // every value through a PreparedStatement as well - the
                // binary protocol, decoded by different code. Both are
                // places where pgjdbc contradicts itself between its own two
                // protocols and seclume does not.
                .allow("c_bytea.getString",
                        "through a PreparedStatement pgjdbc answers getString on a bytea with "
                        + "\"[B@3af37506\" - the identity of the array, not its content. "
                        + "Through a Statement it answers the hex form, which is what seclume "
                        + "answers in both. This is not a difference of convention; it is one "
                        + "driver's binary path returning something no caller can use.")
                .allow("c_real.getString",
                        "pgjdbc renders Float.MAX_VALUE as \"3.4028235E38\" through a "
                        + "PreparedStatement and as \"3.4028235e+38\" through a Statement - "
                        + "Java's rendering in one protocol and the server's in the other. "
                        + "seclume gives the server's in both. Agreeing with itself matters "
                        + "more than agreeing with a driver that does not.")
                .allow("c_double.getString", "the same, for double precision.");
    }

    // --------------------------------------------------------------- fixtures --

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
