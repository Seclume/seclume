package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * {@code TYPE_SCROLL_INSENSITIVE}, moved over like the vendor's driver moves.
 *
 * <p>Hibernate's {@code scroll()} asks for it by default and reporting tools
 * open their queries with it; every one of the four vendor drivers has it.
 * The same walk - last, back, absolute from both ends, relative past either
 * end, before the first and after the last - runs through both drivers, over
 * a plain and a prepared statement, with a fetch size set and a transaction
 * open (which would make a forward-only result come in blocks), and over a
 * result larger than anything SQL Server's streaming holds back. Every return
 * value, row number and value read is compared.
 */
@Timeout(300)
class ScrollableResultTest {

    /** One database: URLs and the two queries, of seven rows and of many. */
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
            for (boolean prepared : new boolean[] {false, true}) {
                for (boolean blocks : new boolean[] {false, true}) {
                    String how = target.name() + (prepared ? ", prepared" : ", plain")
                            + (blocks ? ", fetch size 2 in a transaction" : "");
                    List<String> mine = walk(ours, target.seven(), prepared, blocks);
                    List<String> vendors = walk(theirs, target.seven(), prepared, blocks);
                    assertEquals(vendors, mine, how);
                }
            }
            // Many rows: the last one is the last one, and back from there.
            for (boolean prepared : new boolean[] {false, true}) {
                assertEquals(far(theirs, target.many(), prepared),
                        far(ours, target.many(), prepared), target.name() + " many rows");
                assertEquals(List.of("last " + target.manyRows(), "row " + target.manyRows(),
                        "back " + (target.manyRows() - 1), "absolute(-5000) "
                                + (target.manyRows() - 4999), "first 1"),
                        far(ours, target.many(), prepared), target.name() + " many rows");
            }
            // prepareCall with a type: it used to drop the type on the floor.
            try (java.sql.CallableStatement call = ours.prepareCall(target.seven(),
                    ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
                 ResultSet rows = call.executeQuery()) {
                assertEquals(ResultSet.TYPE_SCROLL_INSENSITIVE, rows.getType(), target.name());
                assertEquals(true, rows.last());
                assertEquals(7, rows.getRow());
                assertEquals(true, rows.absolute(3));
                assertEquals(3, rows.getInt(1));
            }
            // What is still refused, and refused before anything is opened.
            assertThrows(SQLFeatureNotSupportedException.class, () -> ours.createStatement(
                    ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.CONCUR_READ_ONLY));
            assertThrows(SQLFeatureNotSupportedException.class, () -> ours.createStatement(
                    ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE));
            // And a forward-only result still says so rather than guess.
            try (Statement statement = ours.createStatement();
                 ResultSet rows = statement.executeQuery(target.seven())) {
                assertEquals(ResultSet.TYPE_FORWARD_ONLY, rows.getType());
                rows.next();
                assertThrows(SQLFeatureNotSupportedException.class, rows::previous);
            }
        }
    }

    /** The walk over seven rows, as a list of what each step answered. */
    private static List<String> walk(Connection connection, String sql, boolean prepared,
                                     boolean blocks) throws SQLException {
        boolean autoCommit = connection.getAutoCommit();
        connection.setAutoCommit(!blocks);
        List<String> trace = new ArrayList<>();
        try (Statement statement = prepared
                ? connection.prepareStatement(sql, ResultSet.TYPE_SCROLL_INSENSITIVE,
                        ResultSet.CONCUR_READ_ONLY)
                : connection.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE,
                        ResultSet.CONCUR_READ_ONLY)) {
            if (blocks) {
                statement.setFetchSize(2);
            }
            try (ResultSet rows = prepared ? ((PreparedStatement) statement).executeQuery()
                    : statement.executeQuery(sql)) {
                trace.add("type " + rows.getType());
                trace.add("beforeFirst " + rows.isBeforeFirst());
                trace.add("next " + rows.next() + " " + at(rows));
                trace.add("next " + rows.next() + " " + at(rows));
                trace.add("last " + rows.last() + " " + at(rows) + " isLast " + rows.isLast());
                trace.add("previous " + rows.previous() + " " + at(rows));
                trace.add("absolute(2) " + rows.absolute(2) + " " + at(rows));
                trace.add("absolute(-2) " + rows.absolute(-2) + " " + at(rows));
                trace.add("relative(-3) " + rows.relative(-3) + " " + at(rows));
                trace.add("relative(1) " + rows.relative(1) + " " + at(rows));
                trace.add("first " + rows.first() + " " + at(rows) + " isFirst " + rows.isFirst());
                trace.add("previous " + rows.previous() + " row " + rows.getRow()
                        + " beforeFirst " + rows.isBeforeFirst());
                trace.add("next " + rows.next() + " " + at(rows));
                trace.add("relative(10) " + rows.relative(10) + " row " + rows.getRow()
                        + " afterLast " + rows.isAfterLast());
                trace.add("previous " + rows.previous() + " " + at(rows));
                rows.afterLast();
                trace.add("afterLast row " + rows.getRow() + " " + rows.isAfterLast());
                trace.add("next " + rows.next());
                rows.beforeFirst();
                trace.add("beforeFirst row " + rows.getRow() + " " + rows.isBeforeFirst());
                trace.add("absolute(9) " + rows.absolute(9) + " afterLast " + rows.isAfterLast());
                trace.add("absolute(-9) " + rows.absolute(-9) + " beforeFirst "
                        + rows.isBeforeFirst());
                trace.add("absolute(7) " + rows.absolute(7) + " " + at(rows));
                int count = 0;
                rows.beforeFirst();
                while (rows.next()) {
                    count++;
                }
                trace.add("again " + count);
            }
        } finally {
            if (blocks) {
                connection.rollback();
            }
            connection.setAutoCommit(autoCommit);
        }
        return trace;
    }

    private static String at(ResultSet rows) throws SQLException {
        return "row " + rows.getRow() + " = " + rows.getInt(1) + "/" + rows.getString(2);
    }

    /** The far end of a large result, and back. */
    private static List<String> far(Connection connection, String sql, boolean prepared)
            throws SQLException {
        List<String> trace = new ArrayList<>();
        try (Statement statement = prepared
                ? connection.prepareStatement(sql, ResultSet.TYPE_SCROLL_INSENSITIVE,
                        ResultSet.CONCUR_READ_ONLY)
                : connection.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE,
                        ResultSet.CONCUR_READ_ONLY);
             ResultSet rows = prepared ? ((PreparedStatement) statement).executeQuery()
                     : statement.executeQuery(sql)) {
            rows.last();
            trace.add("last " + rows.getInt(1));
            trace.add("row " + rows.getRow());
            rows.previous();
            trace.add("back " + rows.getInt(1));
            rows.absolute(-5000);
            trace.add("absolute(-5000) " + rows.getInt(1));
            rows.first();
            trace.add("first " + rows.getInt(1));
        }
        return trace;
    }
}
