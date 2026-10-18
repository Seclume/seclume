package space.seclume.oracle.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigDecimal;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * A query run again on its cursor with the short call, which does not
 * describe the variables again - the server uses the description it has.
 *
 * <p>That is only right while the description is the same. Each case here
 * changes it between two executions of one statement - a number where text
 * was, a null, a text too long for the size before - and the
 * answer has to be the one the values ask for, not the one an old description
 * would read them as. And the short call has to be used where it can be, or
 * the speed it was built for is not there.
 */
@Timeout(120)
class LocalRunAgainTest {

    private static final String HOST =
            System.getProperty("seclume.oracle.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.oracle.port", 1521);

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-oracle-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no Oracle on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:oracle://" + HOST + ":" + PORT + "/"
                + System.getProperty("seclume.oracle.service", "FREEPDB1")
                + "?user=seclume_test&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    private static long shortCalls(Connection connection) throws SQLException {
        return connection.unwrap(OraConnection.class).session().shortCalls();
    }

    @Test
    void theSecondRunOfAPreparedQueryIsTheShortCall() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             PreparedStatement query = connection.prepareStatement(
                     "select ? + 1 from dual where 1 = ?")) {
            long before = shortCalls(connection);
            for (int n = 1; n <= 5; n++) {
                query.setInt(1, n);
                query.setInt(2, 1);
                assertEquals(n + 1, one(query).intValue());
            }
            assertEquals(4, shortCalls(connection) - before,
                    "the first run describes the variables, the four after it need not");
        }
    }

    @Test
    void aChangedDescriptionGoesOutInFull() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            try (Statement ddl = connection.createStatement()) {
                ddl.execute("begin execute immediate 'drop table zl_again'; "
                        + "exception when others then null; end;");
                ddl.execute("create table zl_again (n number(9), t varchar2(4000), c clob)");
                ddl.execute("insert into zl_again values (1, 'one', 'one')");
                ddl.execute("insert into zl_again values (2, 'two', 'two')");
                ddl.execute("insert into zl_again values (3, null, null)");
            }
            String longText = "x".repeat(3000);
            try (Statement ddl = connection.createStatement()) {
                ddl.execute("insert into zl_again values (4, '" + longText + "', null)");
            }
            try (PreparedStatement query = connection.prepareStatement(
                    "select count(*) from zl_again where n = ? or t = ?")) {
                // number, text
                query.setInt(1, 1);
                query.setString(2, "two");
                assertEquals(2, one(query).intValue());
                // the same shape, other values
                query.setInt(1, 3);
                query.setString(2, "one");
                assertEquals(2, one(query).intValue());
                // text where the number was
                query.setString(1, "2");
                query.setString(2, "zzz");
                assertEquals(1, one(query).intValue());
                // a null
                query.setNull(1, Types.INTEGER);
                query.setString(2, "one");
                assertEquals(1, one(query).intValue());
                // a text far wider than before
                query.setInt(1, 0);
                query.setString(2, longText);
                assertEquals(1, one(query).intValue());
                // and back to the first shape
                query.setBigDecimal(1, new BigDecimal("2"));
                query.setString(2, "one");
                assertEquals(2, one(query).intValue());
                query.setInt(1, 1);
                query.setString(2, "two");
                assertEquals(2, one(query).intValue());
            }
            // The widest text a column holds, then a short one, then wide again.
            String widest = "w".repeat(4000);
            try (PreparedStatement query = connection.prepareStatement(
                    "select count(*) from zl_again where t = ? or n = ?")) {
                query.setString(1, widest);
                query.setInt(2, 1);
                assertEquals(1, one(query).intValue());
                query.setString(1, "two");
                query.setInt(2, 0);
                assertEquals(1, one(query).intValue());
                query.setString(1, widest);
                query.setInt(2, 3);
                assertEquals(1, one(query).intValue());
                query.setString(1, longText);
                query.setInt(2, 3);
                assertEquals(2, one(query).intValue());
            }
            try (Statement ddl = connection.createStatement()) {
                ddl.execute("drop table zl_again purge");
            }
        }
    }

    /** A cursor that failed starts over in full, and gets the short call back after. */
    @Test
    void aFailureIsNotRunAgainOnTrust() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             PreparedStatement query = connection.prepareStatement(
                     "select 10 / ? from dual")) {
            query.setInt(1, 2);
            assertEquals(5, one(query).intValue());
            query.setInt(1, 0);
            SQLException divided = org.junit.jupiter.api.Assertions.assertThrows(
                    SQLException.class, () -> one(query));
            assertTrue(divided.getMessage().contains("ORA-01476"), divided.getMessage());
            long before = shortCalls(connection);
            query.setInt(1, 5);
            assertEquals(2, one(query).intValue());
            query.setInt(1, 10);
            assertEquals(1, one(query).intValue());
            assertFalse(shortCalls(connection) - before > 1,
                    "the run after a failure trusted the description the failure left");
        }
    }

    private static BigDecimal one(PreparedStatement query) throws SQLException {
        try (ResultSet rows = query.executeQuery()) {
            assertTrue(rows.next());
            BigDecimal value = rows.getBigDecimal(1);
            assertFalse(rows.next());
            return value;
        }
    }
}
