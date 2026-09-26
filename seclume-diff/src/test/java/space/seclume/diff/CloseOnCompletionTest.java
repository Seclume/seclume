package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * {@code closeOnCompletion()}, compared with the vendor's driver.
 *
 * <p>The statement is to close when its result closes - the one the
 * application closes, not the one the driver closes because the statement
 * runs again. Each case is a short story told through both drivers, and every
 * step's answer is compared: a statement that closed itself on its own next
 * execution would be as wrong as one that never closed at all.
 */
@Timeout(300)
class CloseOnCompletionTest {

    /** One database: URLs and a query of seven rows ({@code many} is unused here). */
    private record Target(String name, String ours, String vendor, String user, Path secret,
                          String seven, String many, int manyRows) {
    }

    @Test
    void postgresql() throws Exception {
        Path secret = TypeCatalogTest.locate(TestHosts.postgresPasswordFile());
        String host = TestHosts.postgres();
        int port = TestHosts.postgresPort();
        TypeCatalogTest.reachable(host, port, secret);
        compare(new Target("PostgreSQL",
                "jdbc:seclume:postgresql://" + host + ":" + port + "/seclume_test?user=seclume_test"
                        + "&tls=off",
                "jdbc:postgresql://" + host + ":" + port + "/seclume_test", "seclume_test", secret,
                "select g, 'row ' || g from generate_series(1, 7) g order by g",
                "select g from generate_series(1, 20000) g order by g", 20000));
    }

    @Test
    void mysql() throws Exception {
        int port = Integer.getInteger("seclume.mysql.port", 3307);
        Path secret = TypeCatalogTest.locate(".local-mysql-password");
        String host = System.getProperty("seclume.mysql.host", TestHosts.database());
        TypeCatalogTest.reachable(host, port, secret);
        String digits = "(select 0 i union all select 1 union all select 2 union all select 3 "
                + "union all select 4 union all select 5 union all select 6 union all select 7 "
                + "union all select 8 union all select 9)";
        compare(new Target("MySQL",
                "jdbc:seclume:mysql://" + host + ":" + port + "/seclume_test?user=seclume_test"
                        + "&tls=off&allowPublicKeyRetrieval=true",
                "jdbc:mysql://" + host + ":" + port
                        + "/seclume_test?allowPublicKeyRetrieval=true&sslMode=DISABLED",
                "seclume_test", secret,
                "select a.i + 1, concat('row ', a.i + 1) from " + digits + " a where a.i < 7 "
                        + "order by 1",
                "select a.i * 1000 + b.i * 100 + c.i * 10 + d.i + 1 n from " + digits + " a, "
                        + digits + " b, " + digits + " c, " + digits + " d order by n", 10000));
    }

    @Test
    void sqlServer() throws Exception {
        int port = Integer.getInteger("seclume.mssql.port", 1433);
        Path secret = TypeCatalogTest.locate(".local-mssql-password");
        String host = System.getProperty("seclume.mssql.host", TestHosts.database());
        TypeCatalogTest.reachable(host, port, secret);
        compare(new Target("SQL Server",
                "jdbc:seclume:sqlserver://" + host + ":" + port
                        + "/master?user=sa&trustServerCertificate=true",
                "jdbc:sqlserver://" + host + ":" + port
                        + ";databaseName=master;encrypt=true;trustServerCertificate=true",
                "sa", secret,
                "select n, concat('row ', n) from (values (1), (2), (3), (4), (5), (6), (7)) v(n) "
                        + "order by n",
                // Past the 16 384 rows after which a forward-only result pauses.
                "select top 20000 row_number() over (order by (select null)) n "
                        + "from sys.all_objects a cross join sys.all_objects b order by n",
                20000));
    }

    @Test
    void oracle() throws Exception {
        int port = Integer.getInteger("seclume.oracle.port", 1521);
        Path secret = TypeCatalogTest.locate(".local-oracle-password");
        String host = System.getProperty("seclume.oracle.host", TestHosts.database());
        TypeCatalogTest.reachable(host, port, secret);
        compare(new Target("Oracle",
                "jdbc:seclume:oracle://" + host + ":" + port + "/FREEPDB1?user=seclume_test",
                "jdbc:oracle:thin:@//" + host + ":" + port + "/FREEPDB1", "seclume_test", secret,
                "select level, 'row ' || level from dual connect by level <= 7 order by 1",
                "select level from dual connect by level <= 20000 order by 1", 20000));
    }

    private static void compare(Target target) throws Exception {
        Properties vendor = new Properties();
        vendor.setProperty("user", target.user());
        vendor.setProperty("password", Files.readString(target.secret()).trim());
        try (Connection ours = DriverManager.getConnection(target.ours() + "&provider=file&path="
                + TypeCatalogTest.slash(target.secret()));
             Connection theirs = DriverManager.getConnection(target.vendor(), vendor)) {
            assertEquals(stories(theirs, target.seven()), stories(ours, target.seven()),
                    target.name());
            // Running again closes the first result - and there the vendors part
            // ways: pgjdbc, ojdbc and mssql-jdbc count that as the completion and
            // close the statement under the second execution, which then fails;
            // Connector/J does not. seclume keeps it open on all four, which no
            // application that works with the vendor's driver can notice.
            for (boolean prepared : new boolean[] {false, true}) {
                System.out.println("  " + target.name() + (prepared ? " prepared" : " plain")
                        + ", run twice: vendor " + runTwice(theirs, target.seven(), prepared)
                        + ", seclume " + runTwice(ours, target.seven(), prepared));
                assertEquals("open, then closed with the second result",
                        runTwice(ours, target.seven(), prepared), target.name());
            }
        }
    }

    private static List<String> stories(Connection connection, String sql) throws SQLException {
        List<String> trace = new ArrayList<>();
        for (boolean prepared : new boolean[] {false, true}) {
            String kind = prepared ? "prepared: " : "plain: ";
            // 1. The result closes, and the statement with it.
            Statement one = statement(connection, sql, prepared);
            trace.add(kind + "flag before " + one.isCloseOnCompletion());
            one.closeOnCompletion();
            trace.add(kind + "flag after " + one.isCloseOnCompletion());
            ResultSet rows = query(one, sql, prepared);
            rows.next();
            trace.add(kind + "open while reading " + !one.isClosed());
            rows.close();
            trace.add(kind + "closed with its result " + one.isClosed());

            // 3. Read to the end without closing: still open.
            Statement three = statement(connection, sql, prepared);
            three.closeOnCompletion();
            ResultSet all = query(three, sql, prepared);
            while (all.next()) {
                all.getInt(1);
            }
            trace.add(kind + "open after the last row " + !three.isClosed());
            three.close();
            trace.add(kind + "result closed with the statement " + all.isClosed());

            // 4. Without the flag nothing happens.
            Statement four = statement(connection, sql, prepared);
            ResultSet plain = query(four, sql, prepared);
            plain.close();
            trace.add(kind + "without the flag still open " + !four.isClosed());
            four.close();
        }
        return trace;
    }

    private static String runTwice(Connection connection, String sql, boolean prepared)
            throws SQLException {
        Statement two = statement(connection, sql, prepared);
        two.closeOnCompletion();
        try {
            query(two, sql, prepared);
            ResultSet second = query(two, sql, prepared);
            String open = two.isClosed() ? "closed" : "open";
            second.close();
            return open + ", then " + (two.isClosed() ? "closed" : "open")
                    + " with the second result";
        } catch (SQLException refused) {
            return "the second execution refused: " + refused.getSQLState();
        } finally {
            two.close();
        }
    }

    private static Statement statement(Connection connection, String sql, boolean prepared)
            throws SQLException {
        return prepared ? connection.prepareStatement(sql) : connection.createStatement();
    }

    private static ResultSet query(Statement statement, String sql, boolean prepared)
            throws SQLException {
        return prepared ? ((PreparedStatement) statement).executeQuery()
                : statement.executeQuery(sql);
    }
}
