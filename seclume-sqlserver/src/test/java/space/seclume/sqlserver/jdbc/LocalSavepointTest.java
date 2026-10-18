package space.seclume.sqlserver.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Savepoint;
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * A savepoint as the first thing after {@code setAutoCommit(false)}.
 *
 * <p>With implicit transactions a transaction begins with the next statement
 * that needs one, and {@code SAVE TRAN} is not such a statement: the server
 * answered 628, "no active transaction". Found by R2DBC's test kit, whose
 * {@code createSavepoint} on a fresh connection is exactly this.
 */
@Timeout(120)
class LocalSavepointTest {

    private static final String HOST =
            System.getProperty("seclume.mssql.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mssql.port", 1433);

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mssql-password"),
                Path.of("..", ".local-mssql-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mssql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no SQL Server on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:sqlserver://" + HOST + ":" + PORT + "/master"
                + "?user=sa&trustServerCertificate=true&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    private static int one(Statement statement, String sql) throws Exception {
        try (ResultSet rows = statement.executeQuery(sql)) {
            assertTrue(rows.next());
            return rows.getInt(1);
        }
    }

    @Test
    void aSavepointFirstBeginsTheTransactionAndOneLevelOfIt() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("create table #zl_save (n int)");
            connection.setAutoCommit(false);
            Savepoint first = connection.setSavepoint("first");
            assertEquals(1, one(statement, "select @@trancount"),
                    "one transaction, not one inside another that commit leaves open");
            statement.executeUpdate("insert into #zl_save values (1)");
            connection.rollback(first);
            statement.executeUpdate("insert into #zl_save values (2)");
            connection.commit();
            assertEquals(0, one(statement, "select @@trancount"), "the commit left a level open");
            assertEquals(2, one(statement, "select sum(n) from #zl_save"));
        }
    }

    @Test
    void aSavepointInsideARunningTransactionIsAsBefore() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("create table #zl_save2 (n int)");
            connection.setAutoCommit(false);
            statement.executeUpdate("insert into #zl_save2 values (1)");
            Savepoint middle = connection.setSavepoint("middle");
            statement.executeUpdate("insert into #zl_save2 values (10)");
            connection.rollback(middle);
            connection.commit();
            assertEquals(0, one(statement, "select @@trancount"));
            assertEquals(1, one(statement, "select sum(n) from #zl_save2"));
        }
    }
}
