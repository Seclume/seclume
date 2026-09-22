package space.seclume.postgresql.jdbc;

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
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * The binary result format, and the two things that make it safe.
 *
 * <p>PostgreSQL will send a fixed-width value as its bytes rather than as a
 * run of digits, if the client asks per column in {@code Bind}. The saving is
 * real and small - an {@code int4} is four bytes instead of up to ten, and no
 * parse on the way in - and the risk is not small at all: <b>a value asked for
 * in binary and decoded as text is a wrong number, not an exception.</b> This
 * suite found that the hard way, with "column 1 is not an integer: *".
 *
 * <p>So two things are pinned here. The first is that it is actually used -
 * a green suite is entirely consistent with a switch that never fires, and
 * this whole feature would then be dead code that looks alive. The second is
 * that both formats give the same answers, checked value by value against the
 * same statement run with the format turned off.
 *
 * <p><b>The first execution is text by design.</b> The column types are not
 * known until the server has described them, and asking for binary on a type
 * this driver does not decode would be the wrong-number case. So the decision
 * is made from the second execution on - which is the shape that matters
 * anyway, because a framework prepares once and executes many times.
 */
@Timeout(180)
class BinaryResultsTest {

    /** Types the driver reads in binary, and one of each that does not. */
    private static final String SQL =
            "select cast(? as int4) as a, cast(? as int8) as b, cast(? as int2) as c, "
            + "cast(? as float8) as d, cast(? as float4) as e, cast(? as bool) as f, "
            + "cast(? as text) as g, cast(? as numeric) as h";

    private String url;

    @BeforeEach
    void findTheServer() throws Exception {
        String host = TestHosts.postgres();
        int port = TestHosts.postgresPort();
        Path password = null;
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no PostgreSQL password file");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no PostgreSQL on " + host + ":" + port);
        }
        url = "jdbc:seclume:postgresql://" + host + ":" + port + "/seclume_test"
                + "?user=seclume_test&tls=off&provider=file&path="
                + password.toString().replace(java.io.File.separatorChar, '/');
    }

    /**
     * It is on, and only for the types that can be decoded.
     *
     * <p>Read out of {@code ResultSetMetaData}, which reports the format the
     * server actually sent - not what was asked for. The two agree, and asking
     * the answer is what makes this a test rather than a restatement.
     */
    @Test
    void theSecondExecutionComesBackBinaryWhereItCan() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
                PreparedStatement statement = connection.prepareStatement(SQL)) {
            bind(statement);
            statement.executeQuery().close();          // the first is text: see the class comment
            bind(statement);
            try (ResultSet rows = statement.executeQuery()) {
                assertTrue(rows.next());
                List<String> formats = formats(connection, rows);
                assertEquals(List.of("a=binary", "b=binary", "c=binary", "d=binary",
                                "e=binary", "f=binary", "g=text", "h=text"), formats,
                        "either nothing was asked in binary, or something was asked for "
                        + "that this driver cannot decode");
            }
        }
    }

    /** And every value reads the same either way. */
    @Test
    void bothFormatsGiveTheSameValues() throws Exception {
        List<String> binary = readAll(true);
        List<String> text = readAll(false);
        assertEquals(text, binary,
                "the two formats disagree, which is the failure this feature can have that "
                + "produces no exception anywhere");
        assertTrue(binary.contains("a=-2147483648"), "the corpus lost its edge values: " + binary);
    }

    /**
     * The control that the switch is what decides it.
     *
     * <p>With it off the same statement comes back in text, second execution
     * and all. Without this the test above would be consistent with the server
     * having decided, or with the format never having been asked for.
     */
    @Test
    void withTheSwitchOffItStaysText() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            connection.unwrap(space.seclume.postgresql.PgSession.class).setBinaryResults(false);
            try (PreparedStatement statement = connection.prepareStatement(SQL)) {
                bind(statement);
                statement.executeQuery().close();
                bind(statement);
                try (ResultSet rows = statement.executeQuery()) {
                    assertTrue(rows.next());
                    for (String one : formats(connection, rows)) {
                        assertTrue(one.endsWith("=text"),
                                "a column came back binary with the switch off: " + one);
                    }
                }
            }
        }
    }

    private List<String> readAll(boolean binaryOn) throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            if (!binaryOn) {
                connection.unwrap(space.seclume.postgresql.PgSession.class)
                        .setBinaryResults(false);
            }
            try (PreparedStatement statement = connection.prepareStatement(SQL)) {
                bind(statement);
                statement.executeQuery().close();      // make the second one the binary one
                bind(statement);
                try (ResultSet rows = statement.executeQuery()) {
                    assertTrue(rows.next());
                    List<String> values = new ArrayList<>();
                    values.add("a=" + rows.getInt("a"));
                    values.add("b=" + rows.getLong("b"));
                    values.add("c=" + rows.getShort("c"));
                    values.add("d=" + rows.getDouble("d"));
                    values.add("e=" + rows.getFloat("e"));
                    values.add("f=" + rows.getBoolean("f"));
                    values.add("g=" + rows.getString("g"));
                    values.add("h=" + rows.getBigDecimal("h"));
                    // getString on every one of them too: that is the path that
                    // has to render the bytes rather than hand them over.
                    for (int i = 1; i <= 8; i++) {
                        values.add("s" + i + "=" + rows.getString(i));
                    }
                    return values;
                }
            }
        }
    }

    /** Edge values, because the middle of a range never catches a sign error. */
    private static void bind(PreparedStatement statement) throws Exception {
        statement.setInt(1, Integer.MIN_VALUE);
        statement.setLong(2, Long.MIN_VALUE);
        statement.setShort(3, (short) -1);
        statement.setDouble(4, 1.0d / 3.0d);
        statement.setFloat(5, -0.5f);
        statement.setBoolean(6, true);
        statement.setString(7, "text stays text");
        statement.setBigDecimal(8, new java.math.BigDecimal("12345.6789"));
    }

    /** Each column as {@code name=binary} or {@code name=text}. */
    private static List<String> formats(Connection connection, ResultSet rows) throws Exception {
        List<space.seclume.postgresql.PgSession.Field> fields =
                connection.unwrap(space.seclume.postgresql.PgSession.class).fields();
        List<String> out = new ArrayList<>();
        for (space.seclume.postgresql.PgSession.Field field : fields) {
            out.add(field.name() + "=" + (field.format() == 1 ? "binary" : "text"));
        }
        return out;
    }
}
