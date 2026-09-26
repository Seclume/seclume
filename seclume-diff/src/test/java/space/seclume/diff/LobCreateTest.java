package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.OutputStream;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
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
 * {@code createClob} and {@code createBlob}, written into piece by piece and
 * bound: the same edits through seclume and through the vendor's driver, and
 * the rows compared as the vendor's driver reads them back.
 *
 * <p>MySQL and SQL Server keep a LOB as a value, so the LOB is the client's
 * until it is bound; Oracle's is a temporary LOB on the server. PostgreSQL is
 * not here: its CLOB is a large object, a column of its own kind.
 */
@Timeout(300)
class LobCreateTest {

    private record Target(String name, String ours, String vendor, String user, Path secret,
                          String seven, String many, int manyRows) {
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
            "MySQL", new String[] {"drop table if exists zl_lobcreate",
                "create table zl_lobcreate (id int, c longtext, b longblob)"},
            "SQL Server", new String[] {"drop table if exists zl_lobcreate",
                "create table zl_lobcreate (id int, c nvarchar(max), b varbinary(max))"},
            "Oracle", new String[] {"begin execute immediate 'drop table zl_lobcreate purge'; "
                    + "exception when others then null; end;",
                "create table zl_lobcreate (id number(10), c clob, b blob)"});

    private static void compare(Target target) throws Exception {
        Properties vendor = new Properties();
        vendor.setProperty("user", target.user());
        vendor.setProperty("password", Files.readString(target.secret()).trim());
        try (Connection ours = DriverManager.getConnection(target.ours() + "&provider=file&path="
                + TypeCatalogTest.slash(target.secret()));
             Connection theirs = DriverManager.getConnection(target.vendor(), vendor)) {
            try (Statement statement = theirs.createStatement()) {
                for (String sql : TABLES.get(target.name())) {
                    statement.execute(sql);
                }
            }
            write(ours, 1);
            write(theirs, 2);
            List<String> mine = read(theirs, 1);
            List<String> vendors = read(theirs, 2);
            System.out.println("  " + target.name() + " vendor  " + vendors);
            System.out.println("  " + target.name() + " seclume " + mine);
            assertEquals(vendors, mine, target.name());
            try (Statement statement = theirs.createStatement()) {
                statement.execute(TABLES.get(target.name())[0]);
            }
        }
    }

    /** The same edits on both: write, overwrite in the middle, append by stream. */
    private static void write(Connection connection, int id) throws Exception {
        Clob clob = connection.createClob();
        clob.setString(1, "Grüße aus Wien");
        clob.setString(8, "AUS");
        try (Writer tail = clob.setCharacterStream(clob.length() + 1)) {
            tail.write(" - €");
        }
        Blob blob = connection.createBlob();
        blob.setBytes(1, new byte[] {1, 2, 3, 4, 5});
        blob.setBytes(2, new byte[] {9, 9});
        try (OutputStream tail = blob.setBinaryStream(blob.length() + 1)) {
            tail.write(new byte[] {7, 8});
        }
        try (PreparedStatement insert = connection.prepareStatement(
                "insert into zl_lobcreate (id, c, b) values (?, ?, ?)")) {
            insert.setInt(1, id);
            insert.setClob(2, clob);
            insert.setBlob(3, blob);
            insert.executeUpdate();
        }
        if (!connection.getAutoCommit()) {
            connection.commit();
        }
        clob.free();
        blob.free();
    }

    private static List<String> read(Connection connection, int id) throws Exception {
        List<String> values = new ArrayList<>();
        try (PreparedStatement select = connection.prepareStatement(
                "select c, b from zl_lobcreate where id = ?")) {
            select.setInt(1, id);
            try (ResultSet rows = select.executeQuery()) {
                rows.next();
                values.add(rows.getString(1));
                values.add(HexFormat.of().formatHex(rows.getBytes(2)));
            }
        }
        return values;
    }
}
