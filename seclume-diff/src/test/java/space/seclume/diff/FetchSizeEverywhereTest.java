package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;


import java.io.IOException;
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
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import space.seclume.tck.TestHosts;

/**
 * A fetch size on every statement - as a framework sets it - on all four.
 *
 * <p>Spring's {@code JdbcTemplate.setFetchSize}, Hibernate's
 * {@code hibernate.jdbc.fetch_size} and MyBatis' {@code defaultFetchSize}
 * put it on every statement, writes included. SQL Server opened a
 * server-side cursor for any prepared statement with a fetch size, and a
 * cursor over an insert or update is refused (error 16938): every write
 * failed. This holds the other three to the same, with and without bind
 * values, inside a transaction and under auto-commit - and a query with bind
 * values still reads every row.
 */
@Timeout(300)
class FetchSizeEverywhereTest {

    private record Database(String name, String scheme, int port, String database, String user,
                            String passwordFile, String options, String create) {

        String url(String host, int at, Path password) {
            return "jdbc:seclume:" + scheme + "://" + host + ":" + at + "/" + database
                    + "?user=" + user + options
                    + "&provider=file&path=" + password.toString().replace(java.io.File.separatorChar, '/');
        }
    }

    static List<Database> databases() {
        return List.of(
                new Database("PostgreSQL", "postgresql", 5432, "seclume_test", "seclume_test",
                        ".local-pg-password", "&tls=off", "create table zl_fetch_writes (n int)"),
                new Database("MySQL", "mysql", 3307, "seclume_test", "seclume_test",
                        ".local-mysql-password", "&tls=off", "create table zl_fetch_writes (n int)"),
                new Database("SQL Server", "sqlserver", 1433, "master", "sa",
                        ".local-mssql-password", "&trustServerCertificate=true",
                        "create table zl_fetch_writes (n int)"),
                new Database("Oracle", "oracle", 1521, "FREEPDB1", "seclume_test",
                        ".local-oracle-password", "", "create table zl_fetch_writes (n number(10))"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void writesAndBoundQueriesWorkWithAFetchSize(Database database) throws Exception {
        String host = hostOf(database);
        int port = portOf(database);
        Path password = passwordOf(database);
        reachable(host, port);
        try (Connection connection = DriverManager.getConnection(
                database.url(host, port, password))) {
            try (Statement statement = connection.createStatement()) {
                try {
                    statement.execute("drop table zl_fetch_writes");
                } catch (SQLException absent) {
                    // not there, which is what was wanted
                }
                statement.execute(database.create());
            }
            for (boolean autoCommit : new boolean[] {true, false}) {
                connection.setAutoCommit(autoCommit);
                String mode = autoCommit ? "auto-commit" : "transaction";
                try (PreparedStatement insert = connection.prepareStatement(
                             "insert into zl_fetch_writes values (?)");
                     PreparedStatement plain = connection.prepareStatement(
                             "insert into zl_fetch_writes values (0)");
                     PreparedStatement update = connection.prepareStatement(
                             "update zl_fetch_writes set n = n + 1 where n >= ?");
                     PreparedStatement delete = connection.prepareStatement(
                             "delete from zl_fetch_writes where n > ?");
                     PreparedStatement query = connection.prepareStatement(
                             "select n from zl_fetch_writes where n >= ? order by n")) {
                    for (PreparedStatement each : List.of(insert, plain, update, delete, query)) {
                        each.setFetchSize(3);
                    }
                    for (int i = 1; i <= 10; i++) {
                        insert.setInt(1, i);
                        assertEquals(1, insert.executeUpdate(), mode + ": insert " + i);
                    }
                    assertEquals(1, plain.executeUpdate(), mode + ": plain insert");
                    update.setInt(1, 0);
                    assertEquals(11, update.executeUpdate(), mode + ": update");
                    query.setInt(1, 2);
                    int seen = 0;
                    try (ResultSet rows = query.executeQuery()) {
                        while (rows.next()) {
                            seen++;
                            assertEquals(seen + 1, rows.getInt(1), mode + ": order");
                        }
                    }
                    assertEquals(10, seen, mode + ": rows of a bound query in blocks of three");
                    delete.setInt(1, -1);
                    assertEquals(11, delete.executeUpdate(), mode + ": delete");
                }
                if (!autoCommit) {
                    connection.commit();
                }
            }
            connection.setAutoCommit(true);
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table zl_fetch_writes");
            }
        }
    }

    private static String key(Database database) {
        return switch (database.scheme()) {
            case "postgresql" -> "pg";
            case "sqlserver" -> "mssql";
            default -> database.scheme();
        };
    }

    private static String hostOf(Database database) {
        return System.getProperty("seclume." + key(database) + ".host", TestHosts.database());
    }

    private static int portOf(Database database) {
        return Integer.getInteger("seclume." + key(database) + ".port", database.port());
    }

    private static Path passwordOf(Database database) {
        String named = System.getProperty("seclume." + key(database) + ".passwordFile",
                database.passwordFile());
        for (Path candidate : List.of(Path.of(named), Path.of("..", named))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.abort("no " + named);
        return null;
    }

    private static boolean listening(int port) {
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress("127.0.0.1", port), 500);
            return true;
        } catch (IOException closed) {
            return false;
        }
    }

    private static void reachable(String host, int port) {
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("nothing on " + host + ":" + port);
        }
    }
}
