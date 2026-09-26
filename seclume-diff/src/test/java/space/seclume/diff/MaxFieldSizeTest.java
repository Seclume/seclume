package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * {@code setMaxFieldSize}: a text and a binary column cut to the limit
 * through {@code getString}, {@code getBytes} and {@code getObject}, a number
 * left alone - what JDBC says, on all four.
 *
 * <p>The vendors do not agree, and that is why the expectation is written out
 * rather than taken from them. pgjdbc cuts characters, as seclume does.
 * Connector/J and mssql-jdbc take the limit and cut nothing here. ojdbc cuts
 * the UTF-8 bytes - through the middle of a character - and cuts the digits of
 * a NUMBER too, so that 123456789 reads as 123456700. Only pgjdbc is compared;
 * the others are printed.
 */
@Timeout(300)
class MaxFieldSizeTest {

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

    private static final Map<String, String> QUERY = Map.of(
            "PostgreSQL", "select cast('Grüße aus Wien' as varchar(40)), "
                    + "cast('\\x010203040506070809' as bytea), 123456789",
            "MySQL", "select cast('Grüße aus Wien' as char(40)), x'010203040506070809', 123456789",
            "SQL Server", "select cast(N'Grüße aus Wien' as nvarchar(40)), "
                    + "0x010203040506070809, 123456789",
            "Oracle", "select cast('Grüße aus Wien' as varchar2(40)), "
                    + "hextoraw('010203040506070809'), 123456789 from dual");

    private static void compare(Target target) throws Exception {
        Properties vendor = new Properties();
        vendor.setProperty("user", target.user());
        vendor.setProperty("password", Files.readString(target.secret()).trim());
        try (Connection ours = DriverManager.getConnection(target.ours() + "&provider=file&path="
                + TypeCatalogTest.slash(target.secret()));
             Connection theirs = DriverManager.getConnection(target.vendor(), vendor)) {
            List<String> mine = read(ours, QUERY.get(target.name()));
            List<String> vendors = read(theirs, QUERY.get(target.name()));
            System.out.println("  " + target.name() + " vendor  " + vendors);
            System.out.println("  " + target.name() + " seclume " + mine);
            assertEquals(List.of("limit 5", "Grüße", "Grüße", "0102030405", "0102030405",
                    "123456789"), mine, target.name());
            if (target.name().equals("PostgreSQL")) {
                assertEquals(vendors, mine, target.name());
            }
        }
    }

    private static List<String> read(Connection connection, String sql) throws Exception {
        List<String> values = new ArrayList<>();
        try (Statement statement = connection.createStatement()) {
            statement.setMaxFieldSize(5);
            values.add("limit " + statement.getMaxFieldSize());
            try (ResultSet rows = statement.executeQuery(sql)) {
                rows.next();
                values.add(rows.getString(1));
                values.add(String.valueOf(rows.getObject(1)));
                values.add(HexFormat.of().formatHex(rows.getBytes(2)));
                Object binary = rows.getObject(2);
                values.add(binary instanceof byte[] bytes ? HexFormat.of().formatHex(bytes)
                        : String.valueOf(binary));
                values.add(rows.getString(3));
            }
        }
        return values;
    }
}
