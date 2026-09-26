package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.Executors;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * {@code setNetworkTimeout}, compared with the vendor's driver.
 *
 * <p>HikariCP sets it around every validation and close, and an application
 * sets it so that a server that stops answering costs a known time rather than
 * a thread for ever. The value set is the value read; a statement that waits
 * longer than it fails within about that time and leaves the connection
 * closed - it cannot know how much of the answer is still on its way - and a
 * timeout of zero waits as long as it takes.
 */
// Alone: it measures how long things take, and a busy machine lies about that.
@org.junit.jupiter.api.parallel.Isolated
@Timeout(300)
class NetworkTimeoutTest {

    /**
     * The timeout set, against a statement that sleeps two seconds. Short on
     * purpose: the class runs alone, so every second of waiting here is a
     * second of the whole build (it was 1.5 s against 4 s - 31 s in all).
     */
    private static final int TIMEOUT = 600;

    /** One database: URLs, and in {@code seven} seven rows. */
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

    private static final java.util.Map<String, String> SLEEP = java.util.Map.of(
            "PostgreSQL", "select pg_sleep(2)", "MySQL", "select sleep(2)",
            "SQL Server", "waitfor delay '00:00:02'",
            "Oracle", "begin dbms_session.sleep(2); end;");

    private static void compare(Target target) throws Exception {
        Properties vendor = new Properties();
        vendor.setProperty("user", target.user());
        vendor.setProperty("password", Files.readString(target.secret()).trim());
        String ours = target.ours() + "&provider=file&path=" + TypeCatalogTest.slash(target.secret());
        String sleep = SLEEP.get(target.name());
        List<String> mine;
        List<String> vendors;
        try (Connection connection = DriverManager.getConnection(ours)) {
            mine = story(connection, sleep);
        }
        try (Connection connection = DriverManager.getConnection(target.vendor(), vendor)) {
            vendors = story(connection, sleep);
        }
        System.out.println("  " + target.name() + " vendor  " + vendors);
        System.out.println("  " + target.name() + " seclume " + mine);
        assertEquals(vendors, mine, target.name());
        // And zero waits: the same sleep on a fresh connection, to the end.
        try (Connection connection = DriverManager.getConnection(ours);
             Statement statement = connection.createStatement()) {
            connection.setNetworkTimeout(Executors.newSingleThreadExecutor(), TIMEOUT);
            connection.setNetworkTimeout(Executors.newSingleThreadExecutor(), 0);
            long start = System.nanoTime();
            statement.execute(sleep);
            assertTrue((System.nanoTime() - start) / 1_000_000 >= 1800,
                    "zero did not wait for the answer");
        }
    }

    private static List<String> story(Connection connection, String sleep) throws SQLException {
        List<String> trace = new ArrayList<>();
        trace.add("default " + connection.getNetworkTimeout());
        connection.setNetworkTimeout(Executors.newSingleThreadExecutor(), TIMEOUT);
        // Connector/J applies it through the executor, a moment later.
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        trace.add("set " + connection.getNetworkTimeout());
        Statement statement = connection.createStatement();
        statement.execute("select 1" + (sleep.startsWith("begin") ? " from dual" : ""));
        trace.add("a quick statement is not disturbed");
        long start = System.nanoTime();
        try {
            statement.execute(sleep);
            trace.add("the sleep finished");
        } catch (SQLException expected) {
            long millis = (System.nanoTime() - start) / 1_000_000;
            trace.add("failed " + (millis >= TIMEOUT - 100 && millis < 1800 ? "near the timeout"
                    : "after " + millis + " ms"));
        }
        try {
            statement.close();
        } catch (SQLException onAClosedConnection) {
            // ojdbc refuses even that; what matters is the connection.
        }
        trace.add("closed afterwards " + connection.isClosed());
        trace.add("valid afterwards " + connection.isValid(2));
        return trace;
    }
}
