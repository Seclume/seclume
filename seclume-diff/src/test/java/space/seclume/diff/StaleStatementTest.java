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
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * The same statement text, and a table that changed under it.
 *
 * <p>Every driver here keeps something per text: Oracle the cursor and its
 * column description, PostgreSQL a named statement, MySQL a server-side
 * prepare. When another session drops and re-creates the table, or adds a
 * column, what was kept describes a table that is gone. The type catalog ran
 * into it on Oracle - "select v from t" over a table re-created per type
 * failed with ORA-00932 on the type after each - and a migration that runs
 * while an application is up meets it the same way.
 *
 * <p>Each case: read through a Statement and a PreparedStatement, change the
 * table from the vendor's connection, read the same text again. The answer
 * has to be the new table's.
 */
@Timeout(300)
class StaleStatementTest {

    private static final String TABLE = "seclume_stale";

    @Test
    void postgresql() throws Exception {
        Path secret = TypeCatalogTest.locate(TestHosts.postgresPasswordFile());
        String host = TestHosts.postgres();
        int port = TestHosts.postgresPort();
        TypeCatalogTest.reachable(host, port, secret);
        run(secret, "jdbc:seclume:postgresql://" + host + ":" + port
                        + "/seclume_test?user=seclume_test&tls=off",
                "jdbc:postgresql://" + host + ":" + port + "/seclume_test", "seclume_test",
                "integer", "varchar(20)", new String[][] {{"text", "'abc'"},
                        {"date", "date '2024-01-02'"}, {"bytea", "'\\xab'"},
                        {"boolean", "true"}, {"numeric(5,1)", "1.5"},
                        {"timestamptz", "'2024-01-02 03:04:05+00'"}, {"integer", "7"}});
    }

    @Test
    void mysql() throws Exception {
        int port = Integer.getInteger("seclume.mysql.port", 3307);
        Path secret = TypeCatalogTest.locate(".local-mysql-password");
        String host = System.getProperty("seclume.mysql.host", TestHosts.database());
        TypeCatalogTest.reachable(host, port, secret);
        run(secret, "jdbc:seclume:mysql://" + host + ":" + port
                        + "/seclume_test?user=seclume_test&tls=off&allowPublicKeyRetrieval=true",
                "jdbc:mysql://" + host + ":" + port
                        + "/seclume_test?allowPublicKeyRetrieval=true&sslMode=DISABLED",
                "seclume_test", "int", "varchar(20)", new String[][] {{"date", "'2024-01-02'"},
                        {"blob", "x'ab'"}, {"bit(1)", "b'1'"}, {"datetime(3)", "'2024-01-02 03:04:05.5'"},
                        {"json", "'[1]'"}, {"year", "2024"}, {"int", "7"}});
    }

    @Test
    void sqlServer() throws Exception {
        int port = Integer.getInteger("seclume.mssql.port", 1433);
        Path secret = TypeCatalogTest.locate(".local-mssql-password");
        String host = System.getProperty("seclume.mssql.host", TestHosts.database());
        TypeCatalogTest.reachable(host, port, secret);
        run(secret, "jdbc:seclume:sqlserver://" + host + ":" + port
                        + "/master?user=sa&trustServerCertificate=true",
                "jdbc:sqlserver://" + host + ":" + port
                        + ";databaseName=master;encrypt=true;trustServerCertificate=true",
                "sa", "int", "varchar(20)", new String[][] {{"date", "'2024-01-02'"},
                        {"varbinary(4)", "0xab"}, {"bit", "1"}, {"datetime2", "'2024-01-02 03:04:05.5'"},
                        {"xml", "'<a/>'"}, {"geometry", "geometry::Point(1, 2, 0)"},
                        {"nvarchar(max)", "N'abc'"}, {"int", "7"}});
    }

    @Test
    void oracle() throws Exception {
        int port = Integer.getInteger("seclume.oracle.port", 1521);
        Path secret = TypeCatalogTest.locate(".local-oracle-password");
        String host = System.getProperty("seclume.oracle.host", TestHosts.database());
        TypeCatalogTest.reachable(host, port, secret);
        run(secret, "jdbc:seclume:oracle://" + host + ":" + port
                        + "/FREEPDB1?user=seclume_test",
                "jdbc:oracle:thin:@//" + host + ":" + port + "/FREEPDB1", "seclume_test",
                "number(10)", "varchar2(20)", new String[][] {{"long raw", "hextoraw('ab')"},
                        {"date", "date '2024-01-02'"}, {"long", "'x'"},
                        {"timestamp", "timestamp '2024-01-02 03:04:05.5'"},
                        {"clob", "to_clob('c')"}, {"boolean", "true"}, {"raw(4)", "hextoraw('ab')"},
                        {"timestamp with time zone", "timestamp '2024-01-02 03:04:05 +02:00'"},
                        {"number(10)", "7"}});
    }

    private static void run(Path secret, String ours, String vendorUrl, String user,
            String number, String text, String[][] chain) throws Exception {
        Properties vendor = new Properties();
        vendor.setProperty("user", user);
        vendor.setProperty("password", Files.readString(secret).trim());
        try (Connection theirs = DriverManager.getConnection(vendorUrl, vendor);
             Connection mine = DriverManager.getConnection(ours + "&provider=file&path="
                     + TypeCatalogTest.slash(secret))) {
            String one = "select v from " + TABLE + " where id = 1";
            String all = "select * from " + TABLE + " where id = 1";
            try {
                ddl(theirs, "create table " + TABLE + " (id int, v " + number + ")",
                        "insert into " + TABLE + " values (1, 7)");
                read(mine, one, "7", 1);
                read(mine, all, "7", 2);

                // Dropped and re-created with another type in the same column.
                ddl(theirs, "drop table " + TABLE,
                        "create table " + TABLE + " (id int, v " + text + ")",
                        "insert into " + TABLE + " values (1, 'abc')");
                read(mine, one, "abc", 1);
                read(mine, all, "abc", 2);

                // A column added: select * has one more now.
                ddl(theirs, "alter table " + TABLE + " add w int",
                        "update " + TABLE + " set w = 5");
                read(mine, all, "abc", 3);

                // A chain of types in the one column, each read like the vendor
                // reads it - the catalog met the stale cursor on Oracle going
                // from LONG RAW to DATE, not from NUMBER to VARCHAR2.
                for (String[] next : chain) {
                    ddl(theirs, "drop table " + TABLE,
                            "create table " + TABLE + " (id int, v " + next[0] + ")",
                            "insert into " + TABLE + " (id, v) values (1, " + next[1] + ")");
                    String expected;
                    try (Statement statement = theirs.createStatement();
                         ResultSet rows = statement.executeQuery(one)) {
                        rows.next();
                        expected = rows.getString(1);
                    }
                    read(mine, one, expected, 1);
                }
            } finally {
                try (Statement statement = theirs.createStatement()) {
                    statement.execute("drop table " + TABLE);
                } catch (SQLException gone) {
                    // never created
                }
            }
        }
    }

    private static void ddl(Connection connection, String... statements) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            for (String sql : statements) {
                statement.execute(sql);
            }
        }
    }

    /** The text through a Statement and twice through a PreparedStatement. */
    private static void read(Connection connection, String sql, String value, int columns)
            throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(sql)) {
            check(rows, sql + " (Statement)", value, columns);
        }
        for (int i = 0; i < 2; i++) {
            try (PreparedStatement statement = connection.prepareStatement(sql);
                 ResultSet rows = statement.executeQuery()) {
                check(rows, sql + " (PreparedStatement)", value, columns);
            }
        }
    }

    private static void check(ResultSet rows, String what, String value, int columns)
            throws SQLException {
        rows.next();
        assertEquals(columns, rows.getMetaData().getColumnCount(), what + ": columns");
        int v = rows.getMetaData().getColumnCount() == 1 ? 1 : 2;
        assertEquals(value, rows.getString(v), what + ": value");
    }
}
