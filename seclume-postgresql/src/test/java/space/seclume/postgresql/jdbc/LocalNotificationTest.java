package space.seclume.postgresql.jdbc;

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
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.postgresql.PgNotification;
import space.seclume.tck.TestHosts;

/**
 * LISTEN / NOTIFY: what the server sends a listening connection reaches the
 * application - in order, with channel, payload and sender, while waiting,
 * and without the asking starting a transaction.
 */
@Timeout(60)
class LocalNotificationTest {

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no " + TestHosts.postgresPasswordFile());
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(TestHosts.postgres(),
                    TestHosts.postgresPort()), 1000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on " + TestHosts.postgres());
        }
        url = "jdbc:seclume:postgresql://" + TestHosts.postgres() + ":"
                + TestHosts.postgresPort() + "/seclume_test?user=seclume_test&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    @Test
    void notificationsArriveInOrderWithWhoSentThem() throws Exception {
        try (Connection listener = DriverManager.getConnection(url);
             Connection sender = DriverManager.getConnection(url)) {
            PgConnection pg = listener.unwrap(PgConnection.class);
            execute(listener, "listen seclume_orders");
            String senderPid = ask(sender, "select pg_backend_pid()");
            execute(sender, "notify seclume_orders, 'first'");
            execute(sender, "select pg_notify('seclume_orders', 'second')");

            List<PgNotification> arrived = pg.notifications();
            assertEquals(2, arrived.size(), "arrived: " + arrived);
            assertEquals("first", arrived.get(0).payload());
            assertEquals("second", arrived.get(1).payload());
            assertEquals("seclume_orders", arrived.get(0).channel());
            assertEquals(senderPid, String.valueOf(arrived.get(0).processId()));
            assertTrue(pg.notifications().isEmpty(), "taken twice");
        }
    }

    @Test
    void waitingEndsWhenOneArrives() throws Exception {
        try (Connection listener = DriverManager.getConnection(url);
             Connection sender = DriverManager.getConnection(url)) {
            PgConnection pg = listener.unwrap(PgConnection.class);
            execute(listener, "listen seclume_late");
            CompletableFuture<Void> later = CompletableFuture.runAsync(() -> {
                try {
                    Thread.sleep(300);
                    execute(sender, "notify seclume_late, 'now'");
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            });
            long start = System.nanoTime();
            List<PgNotification> arrived = pg.notifications(Duration.ofSeconds(20));
            long millis = (System.nanoTime() - start) / 1_000_000;
            later.join();
            assertEquals(1, arrived.size());
            assertEquals("now", arrived.get(0).payload());
            assertTrue(millis < 5_000, "the wait went on after it arrived: " + millis + " ms");
        }
    }

    @Test
    void askingStartsNoTransactionAndNothingWaitsForNothing() throws Exception {
        try (Connection listener = DriverManager.getConnection(url);
             Connection observer = DriverManager.getConnection(url)) {
            PgConnection pg = listener.unwrap(PgConnection.class);
            execute(listener, "listen seclume_quiet");
            String pid = ask(listener, "select pg_backend_pid()");
            listener.setAutoCommit(false);
            List<PgNotification> none = pg.notifications(Duration.ofMillis(200));
            assertTrue(none.isEmpty());
            assertEquals("idle", ask(observer, "select state from pg_stat_activity where pid = "
                    + pid), "asking for notifications opened a transaction");
            listener.setAutoCommit(true);
        }
    }

    private static void execute(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private static String ask(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(sql)) {
            return rows.next() ? rows.getString(1) : null;
        }
    }
}
