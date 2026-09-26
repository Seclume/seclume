package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ParameterMetaData;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * {@code getParameterMetaData().getParameterCount()} against the vendor's
 * driver - with question marks in strings, identifiers and comments that are
 * not parameters - and the mode of a prepared statement's parameters.
 */
@Timeout(300)
class ParameterCountTest {

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
        String from = target.name().equals("Oracle") ? " from dual" : "";
        String[] texts = {
            "select 1" + from,
            "select ?" + from,
            "select ?, ?, ?" + from,
            "select '?', ? /* ? */" + from,
            "select ? -- ?" + (char) 10 + from,
        };
        try (Connection ours = DriverManager.getConnection(target.ours() + "&provider=file&path="
                + TypeCatalogTest.slash(target.secret()));
             Connection theirs = DriverManager.getConnection(target.vendor(), vendor)) {
            List<String> mine = new ArrayList<>();
            List<String> vendors = new ArrayList<>();
            for (String sql : texts) {
                String own = count(ours, sql);
                String theirsSays = count(theirs, sql);
                org.junit.jupiter.api.Assertions.assertFalse(own.startsWith("refused"),
                        target.name() + ": " + sql + " - " + own);
                // mssql-jdbc asks the server to describe the parameters and
                // refuses when it cannot say a type - "select ?" is enough.
                // The count needs no description, so seclume answers there.
                if (!theirsSays.startsWith("refused")) {
                    mine.add(own);
                    vendors.add(theirsSays);
                }
            }
            System.out.println("  " + target.name() + " vendor  " + vendors);
            System.out.println("  " + target.name() + " seclume " + mine);
            assertEquals(vendors, mine, target.name());
        }
    }

    private static String count(Connection connection, String sql) {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            ParameterMetaData parameters = statement.getParameterMetaData();
            int count = parameters.getParameterCount();
            return count + (count > 0 && parameters.getParameterMode(1)
                    == ParameterMetaData.parameterModeIn ? " in" : "");
        } catch (Exception e) {
            return "refused: " + e.getClass().getSimpleName();
        }
    }
}
