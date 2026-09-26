package space.seclume.mysql.jdbc;

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
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Settings that wait for the next statement - all of them, and before every
 * kind of statement.
 *
 * <p>Two defects, both found by the Spring suites. The waiting setting was
 * one string, and each new one replaced the last: Spring prepares a
 * transaction with setReadOnly, setTransactionIsolation and
 * setAutoCommit(false), so only {@code autocommit=0} ever reached the server.
 * And the settings rode with executions but not with COM_STMT_PREPARE - so
 * after a read-only transaction the next UPDATE was prepared in a session that
 * was still read-only, and MySQL refused it at prepare time with 1792.
 */
@Timeout(60)
class LocalDeferredSettingsTest {

    private static final String HOST =
            System.getProperty("seclume.mysql.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mysql.port", 3307);

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mysql-password"),
                Path.of("..", ".local-mysql-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mysql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no MySQL on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:mysql://" + HOST + ":" + PORT + "/seclume_test"
                + "?user=seclume_test&allowPublicKeyRetrieval=true&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    /** All three, in Spring's order - and the server says so. */
    @Test
    void readOnlyAndIsolationReachTheServerTogether() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            connection.setReadOnly(true);
            connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            connection.setAutoCommit(false);
            try (Statement statement = connection.createStatement();
                 ResultSet row = statement.executeQuery("select @@transaction_read_only, "
                         + "@@transaction_isolation, @@autocommit")) {
                row.next();
                assertEquals(1, row.getInt(1), "read-only did not reach the server");
                assertEquals("SERIALIZABLE", row.getString(2));
                assertEquals(0, row.getInt(3));
            }
            connection.commit();
            connection.setAutoCommit(true);
            connection.setReadOnly(false);
            connection.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
        }
    }

    /** The UPDATE after a read-only transaction is prepared in a writable session. */
    @Test
    void anUpdateIsPreparedAfterAReadOnlyTransaction() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement plain = connection.createStatement()) {
            plain.execute("drop table if exists zl_after_read_only");
            plain.execute("create table zl_after_read_only (id int primary key, v int)");
            plain.execute("insert into zl_after_read_only values (1, 1)");

            connection.setReadOnly(true);
            connection.setAutoCommit(false);
            try (PreparedStatement read = connection.prepareStatement(
                    "select v from zl_after_read_only where id = ?")) {
                read.setInt(1, 1);
                read.executeQuery().close();
            }
            connection.commit();
            connection.setAutoCommit(true);
            connection.setReadOnly(false);

            connection.setAutoCommit(false);
            try (PreparedStatement update = connection.prepareStatement(
                    "update zl_after_read_only set v = ? where id = ?")) {
                update.setInt(1, 2);
                update.setInt(2, 1);
                assertEquals(1, update.executeUpdate());
            }
            connection.commit();
            connection.setAutoCommit(true);
            plain.execute("drop table zl_after_read_only");
        }
    }
}
