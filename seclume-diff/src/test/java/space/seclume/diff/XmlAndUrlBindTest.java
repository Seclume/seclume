package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLXML;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * {@code createSQLXML}, {@code setSQLXML}, {@code setURL} and the setters of
 * types seclume cannot write, given {@code null}.
 *
 * <p>A row written through seclume and the same row written through the
 * vendor's driver, both read back through the vendor's: the XML column holds
 * the same document, the text column the same URL, and a null bound through
 * any setter - {@code setArray}, {@code setRowId}, {@code setRef},
 * {@code setSQLXML}, {@code setURL} - is a NULL, as JDBC says for every setter.
 */
@Timeout(300)
class XmlAndUrlBindTest {

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

    private static final Map<String, String[]> TABLES = Map.of(
            "PostgreSQL", new String[] {"drop table if exists zl_xmlbind",
                "create table zl_xmlbind (id int, x xml, u varchar(200), n varchar(10))"},
            "MySQL", new String[] {"drop table if exists zl_xmlbind",
                "create table zl_xmlbind (id int, x text, u varchar(200), n varchar(10))"},
            "SQL Server", new String[] {"drop table if exists zl_xmlbind",
                "create table zl_xmlbind (id int, x xml, u varchar(200), n varchar(10))"},
            "Oracle", new String[] {"begin execute immediate 'drop table zl_xmlbind purge'; "
                    + "exception when others then null; end;",
                "create table zl_xmlbind (id number(10), x xmltype, u varchar2(200), "
                        + "n varchar2(10))"});

    private static void compare(Target target) throws Exception {
        Properties vendor = new Properties();
        vendor.setProperty("user", target.user());
        vendor.setProperty("password", Files.readString(target.secret()).trim());
        try (Connection ours = DriverManager.getConnection(target.ours() + "&provider=file&path="
                + TypeCatalogTest.slash(target.secret()));
             // pgjdbc sends setString as varchar, which an xml column refuses;
             // its own switch for untyped strings makes the reference possible.
             Connection theirs = DriverManager.getConnection(target.vendor()
                     + (target.name().equals("PostgreSQL") ? "?stringtype=unspecified" : ""),
                     vendor)) {
            try (Statement statement = theirs.createStatement()) {
                for (String sql : TABLES.get(target.name())) {
                    statement.execute(sql);
                }
            }
            write(ours, 1, true);
            // The reference: the same values as plain text through the vendor's
            // driver - pgjdbc and mssql-jdbc have no setURL at all, and ojdbc's
            // createSQLXML needs Oracle's XDB jar.
            write(theirs, 2, false);
            List<String> mine = read(theirs, 1, target);
            List<String> vendors = read(theirs, 2, target);
            System.out.println("  " + target.name() + " vendor  " + vendors);
            System.out.println("  " + target.name() + " seclume " + mine);
            assertEquals(vendors, mine, target.name());
            // And what seclume reads back of both.
            assertEquals(read(ours, 2, target), read(ours, 1, target), target.name());
            try (Statement statement = theirs.createStatement()) {
                statement.execute(TABLES.get(target.name())[0]);
            }
        }
    }

    private static final String DOCUMENT = "<order id=\"7\"><item>Grüße €</item></order>";
    private static final String URL = "https://seclume.space/a?b=c";

    private static void write(Connection connection, int id, boolean typed) throws Exception {
        try (PreparedStatement insert = connection.prepareStatement(
                "insert into zl_xmlbind (id, x, u, n) values (?, ?, ?, ?)")) {
            insert.setInt(1, id);
            if (typed) {
                SQLXML xml = connection.createSQLXML();
                try (java.io.Writer writer = xml.setCharacterStream()) {
                    writer.write(DOCUMENT);
                }
                insert.setSQLXML(2, xml);
                insert.setURL(3, java.net.URI.create(URL).toURL());
            } else {
                insert.setString(2, DOCUMENT);
                insert.setString(3, URL);
            }
            insert.setString(4, "x");
            insert.executeUpdate();
            // The nulls: through every setter JDBC says takes one.
            insert.setInt(1, id + 10);
            if (typed) {
                insert.setSQLXML(2, null);
                insert.setURL(3, null);
                insert.setArray(4, null);
                insert.setRowId(4, null);
                insert.setRef(4, null);
            } else {
                insert.setString(2, null);
                insert.setString(3, null);
                insert.setString(4, null);
            }
            insert.executeUpdate();
        }
        if (!connection.getAutoCommit()) {
            connection.commit();
        }
    }

    private static List<String> read(Connection connection, int id, Target target)
            throws SQLException {
        List<String> values = new ArrayList<>();
        String xml = target.name().equals("Oracle") ? "t.x.getStringVal()" : "x";
        for (int row : new int[] {id, id + 10}) {
            try (PreparedStatement select = connection.prepareStatement("select " + xml
                    + ", u, n from zl_xmlbind t where id = ?")) {
                select.setInt(1, row);
                try (ResultSet rows = select.executeQuery()) {
                    rows.next();
                    values.add(normal(rows.getString(1)) + " | " + rows.getString(2) + " | "
                            + rows.getString(3));
                }
            }
        }
        return values;
    }

    /** Oracle pretty-prints what it stored; the document is what is compared. */
    private static String normal(String xml) {
        return xml == null ? null : xml.replaceAll(">\s+<", "><").strip();
    }
}
