package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * The errors an application branches on, raised through seclume and through
 * the vendor's driver, and compared.
 *
 * <p>Nobody reads the message of a unique violation; they read its SQLState,
 * its vendor code or its class. Spring's exception translation turns
 * {@code 23505} or ORA-00001 into a {@code DuplicateKeyException}, Hibernate
 * turns a code into a {@code ConstraintViolationException}, a retry loop looks
 * for {@code 40001} or a deadlock code. A driver that raises the right error
 * with another state, another code or another class breaks all of that without
 * a single failing test in the application - so every one is compared here:
 * SQLState, vendor code, and the {@code SQLException} subclass.
 */
@Timeout(300)
class ErrorCatalogTest {

    /** One database: its URLs, the table the cases work on, and the cases. */
    private record Target(String name, String ours, String vendor, String user, Path secret,
                          List<String> setup, Map<String, String> cases, List<String> cleanup) {
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
                List.of("drop table if exists zl_err_child", "drop table if exists zl_err",
                        "create table zl_err (id int primary key, name varchar(5) not null, "
                                + "n int check (n >= 0))",
                        "create table zl_err_child (id int references zl_err(id))",
                        "insert into zl_err values (1, 'a', 1)",
                        "insert into zl_err_child values (1)"),
                cases(Map.of(
                        "unique", "insert into zl_err values (1, 'b', 1)",
                        "foreign key", "insert into zl_err_child values (99)",
                        "not null", "insert into zl_err values (2, null, 1)",
                        "check", "insert into zl_err values (3, 'c', -1)",
                        "too long", "insert into zl_err values (4, 'toolong', 1)",
                        "division by zero", "select 1 / 0",
                        "syntax", "selec 1",
                        "no such table", "select * from zl_no_such_table",
                        "no such column", "select no_such_column from zl_err",
                        "numeric overflow", "select cast(99999 as smallint)"),
                        Map.of("bad cast", "select cast('abc' as int)",
                                "delete parent", "delete from zl_err where id = 1",
                                "unknown role", "set role pg_monitor_nonexistent")),
                List.of("drop table if exists zl_err_child", "drop table if exists zl_err")));
    }

    @Test
    void mysql() throws Exception {
        int port = Integer.getInteger("seclume.mysql.port", 3307);
        Path secret = TypeCatalogTest.locate(".local-mysql-password");
        String host = System.getProperty("seclume.mysql.host", TestHosts.database());
        TypeCatalogTest.reachable(host, port, secret);
        compare(new Target("MySQL",
                "jdbc:seclume:mysql://" + host + ":" + port + "/seclume_test?user=seclume_test"
                        + "&tls=off&allowPublicKeyRetrieval=true",
                "jdbc:mysql://" + host + ":" + port
                        + "/seclume_test?allowPublicKeyRetrieval=true&sslMode=DISABLED",
                "seclume_test", secret,
                List.of("drop table if exists zl_err_child", "drop table if exists zl_err",
                        "create table zl_err (id int primary key, name varchar(5) not null, "
                                + "n int check (n >= 0)) engine=InnoDB",
                        "create table zl_err_child (id int, foreign key (id) references "
                                + "zl_err(id)) engine=InnoDB",
                        "insert into zl_err values (1, 'a', 1)",
                        "insert into zl_err_child values (1)"),
                cases(Map.of(
                        "unique", "insert into zl_err values (1, 'b', 1)",
                        "foreign key", "insert into zl_err_child values (99)",
                        "not null", "insert into zl_err values (2, null, 1)",
                        "check", "insert into zl_err values (3, 'c', -1)",
                        "too long", "insert into zl_err values (4, 'toolong', 1)",
                        "division by zero", "insert into zl_err values (5, 'd', 1 / 0)",
                        "syntax", "selec 1",
                        "no such table", "select * from zl_no_such_table",
                        "no such column", "select no_such_column from zl_err",
                        "numeric overflow", "insert into zl_err values (99999999999, 'e', 1)"),
                        Map.of("bad cast", "insert into zl_err values ('abc', 'f', 1)",
                                "delete parent", "delete from zl_err where id = 1")),
                List.of("drop table if exists zl_err_child", "drop table if exists zl_err")));
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
                List.of("drop table if exists zl_err_child", "drop table if exists zl_err",
                        "create table zl_err (id int primary key, name varchar(5) not null, "
                                + "n int check (n >= 0))",
                        "create table zl_err_child (id int references zl_err(id))",
                        "insert into zl_err values (1, 'a', 1)",
                        "insert into zl_err_child values (1)"),
                cases(Map.of(
                        "unique", "insert into zl_err values (1, 'b', 1)",
                        "foreign key", "insert into zl_err_child values (99)",
                        "not null", "insert into zl_err values (2, null, 1)",
                        "check", "insert into zl_err values (3, 'c', -1)",
                        "too long", "insert into zl_err values (4, 'toolong', 1)",
                        "division by zero", "select 1 / 0",
                        "syntax", "selec 1",
                        "no such table", "select * from zl_no_such_table",
                        "no such column", "select no_such_column from zl_err",
                        "numeric overflow", "select cast(99999 as smallint)"),
                        Map.of("bad cast", "select cast('abc' as int)",
                                "delete parent", "delete from zl_err where id = 1",
                                "raiserror", "raiserror('mine', 16, 1)")),
                List.of("drop table if exists zl_err_child", "drop table if exists zl_err")));
    }

    @Test
    void oracle() throws Exception {
        int port = Integer.getInteger("seclume.oracle.port", 1521);
        Path secret = TypeCatalogTest.locate(".local-oracle-password");
        String host = System.getProperty("seclume.oracle.host", TestHosts.database());
        TypeCatalogTest.reachable(host, port, secret);
        String drop = "begin execute immediate 'drop table %s purge'; "
                + "exception when others then null; end;";
        compare(new Target("Oracle",
                "jdbc:seclume:oracle://" + host + ":" + port + "/FREEPDB1?user=seclume_test",
                "jdbc:oracle:thin:@//" + host + ":" + port + "/FREEPDB1", "seclume_test", secret,
                List.of(String.format(drop, "zl_err_child"), String.format(drop, "zl_err"),
                        "create table zl_err (id number(10) primary key, name varchar2(5) "
                                + "not null, n number(10) check (n >= 0))",
                        "create table zl_err_child (id number(10) references zl_err(id))",
                        "insert into zl_err values (1, 'a', 1)",
                        "insert into zl_err_child values (1)"),
                cases(Map.of(
                        "unique", "insert into zl_err values (1, 'b', 1)",
                        "foreign key", "insert into zl_err_child values (99)",
                        "not null", "insert into zl_err values (2, null, 1)",
                        "check", "insert into zl_err values (3, 'c', -1)",
                        "too long", "insert into zl_err values (4, 'toolong', 1)",
                        "division by zero", "select 1 / 0 from dual",
                        "syntax", "selec 1 from dual",
                        "no such table", "select * from zl_no_such_table",
                        "no such column", "select no_such_column from zl_err",
                        "numeric overflow", "insert into zl_err values (99999999999, 'e', 1)"),
                        Map.of("bad cast", "select to_number('abc') from dual",
                                "delete parent", "delete from zl_err where id = 1",
                                "raise_application_error",
                                "begin raise_application_error(-20001, 'mine'); end;")),
                List.of(String.format(drop, "zl_err_child"), String.format(drop, "zl_err"))));
    }

    private static Map<String, String> cases(Map<String, String> first,
            Map<String, String> more) {
        Map<String, String> all = new LinkedHashMap<>(new java.util.TreeMap<>(first));
        all.putAll(new java.util.TreeMap<>(more));
        return all;
    }

    private static void compare(Target target) throws Exception {
        Properties vendor = new Properties();
        vendor.setProperty("user", target.user());
        vendor.setProperty("password", Files.readString(target.secret()).trim());
        List<String> findings = new ArrayList<>();
        StringBuilder report = new StringBuilder("\n==== " + target.name() + " errors\n");
        try (Connection ours = DriverManager.getConnection(target.ours() + "&provider=file&path="
                + TypeCatalogTest.slash(target.secret()));
             Connection theirs = DriverManager.getConnection(target.vendor(), vendor)) {
            run(theirs, target.setup());
            for (Map.Entry<String, String> one : target.cases().entrySet()) {
                String mine = raise(ours, one.getValue());
                String vendors = raise(theirs, one.getValue());
                boolean same = mine.equals(vendors);
                report.append(String.format("  %-24s %s%s%n", one.getKey(), vendors,
                        same ? "" : "   <- seclume: " + mine));
                if (!same) {
                    findings.add(one.getKey() + ": seclume " + mine + ", vendor " + vendors);
                }
                // Still usable after it: a refused statement is an ordinary event.
                try (Statement statement = ours.createStatement()) {
                    statement.execute(target.name().equals("Oracle") ? "select 1 from dual"
                            : "select 1");
                } catch (SQLException broken) {
                    findings.add(one.getKey() + ": the connection broke after it: " + broken);
                }
            }
            run(theirs, target.cleanup());
        }
        System.out.println(report);
        assertTrue(findings.isEmpty(), target.name() + ": " + findings.size()
                + " errors raised differently:\n" + String.join("\n", findings));
    }

    /**
     * SQLState, vendor code and class of the error the statement raises.
     *
     * <p>Every result is read to the end: mssql-jdbc raises an error that
     * follows the column description - a division by zero in a select - only
     * when the row is reached, so stopping at {@code execute} would compare an
     * error with none. The class is the nearest one in {@code java.sql}: that
     * is what an application can catch without the vendor's jar.
     */
    private static String raise(Connection connection, String sql) {
        try (Statement statement = connection.createStatement()) {
            boolean rows = statement.execute(sql);
            while (true) {
                if (rows) {
                    try (java.sql.ResultSet result = statement.getResultSet()) {
                        while (result.next()) {
                            result.getObject(1);
                        }
                    }
                } else if (statement.getUpdateCount() == -1) {
                    break;
                }
                rows = statement.getMoreResults();
            }
            if (!connection.getAutoCommit()) {
                connection.rollback();
            }
            return "no error";
        } catch (SQLException e) {
            Class<?> type = e.getClass();
            while (!type.getPackageName().equals("java.sql")) {
                type = type.getSuperclass();
            }
            return "state " + e.getSQLState() + ", code " + e.getErrorCode() + ", "
                    + type.getSimpleName();
        }
    }

    private static void run(Connection connection, List<String> statements) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            for (String sql : statements) {
                statement.execute(sql);
            }
        }
    }
}
