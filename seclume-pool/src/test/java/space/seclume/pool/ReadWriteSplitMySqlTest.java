package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.io.PrintWriter;
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
import java.util.UUID;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * Read-your-writes on MySQL, through GTIDs: a real MySQL 8.4 primary and its
 * GTID replica - {@code -Dseclume.myrepl.primary=3310 -Dseclume.myrepl.replica=3311},
 * the password (the same for root and seclume_test) in {@code .local-myrepl-password}.
 * The replica's applier is stopped where a test needs it behind.
 */
@Timeout(60)
class ReadWriteSplitMySqlTest {

    private static String primaryUrl;
    private static String replicaUrl;
    private static String replicaRootUrl;
    private String table;

    @BeforeAll
    static void findTheServers() {
        int primary = Integer.getInteger("seclume.myrepl.primary", 0);
        int replica = Integer.getInteger("seclume.myrepl.replica", 0);
        Assumptions.assumeTrue(primary > 0 && replica > 0, "no MySQL primary and replica configured");
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-myrepl-password"),
                Path.of("..", ".local-myrepl-password"))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-myrepl-password");
        String host = System.getProperty("seclume.myrepl.host", TestHosts.database());
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, primary), 2000);
        } catch (IOException e) {
            Assumptions.abort("no primary on " + host + ":" + primary);
        }
        String options = "&tls=off&allowPublicKeyRetrieval=true&provider=file&path="
                + password.toString().replace('\\', '/');
        primaryUrl = "jdbc:seclume:mysql://" + host + ":" + primary + "/seclume_test?user=seclume_test" + options;
        replicaUrl = "jdbc:seclume:mysql://" + host + ":" + replica + "/seclume_test?user=seclume_test" + options;
        replicaRootUrl = "jdbc:seclume:mysql://" + host + ":" + replica + "/seclume_test?user=root" + options;
    }

    @BeforeEach
    void table() throws Exception {
        table = "rw_" + UUID.randomUUID().toString().substring(0, 8);
        try (Connection c = DriverManager.getConnection(primaryUrl)) {
            execute(c, "create table " + table + " (id int primary key)");
        }
        try (Connection c = DriverManager.getConnection(replicaUrl)) {
            for (int i = 0; i < 100; i++) {
                if ("1".equals(one(c, "select count(*) from information_schema.tables "
                        + "where table_schema = 'seclume_test' and table_name = '" + table + "'"))) {
                    return;
                }
                Thread.sleep(50);
            }
        }
        throw new AssertionError("the replica never got the table");
    }

    @AfterEach
    void drop() throws Exception {
        applier(true);
        try (Connection c = DriverManager.getConnection(primaryUrl)) {
            execute(c, "drop table if exists " + table);
        }
    }

    /** The control: without read-your-writes the own write is not on the replica yet. */
    @Test
    void withoutReadYourWritesTheOwnWriteIsNotThere() throws Exception {
        ReadWriteSplit split = new ReadWriteSplit(new UrlSource(primaryUrl), new UrlSource(replicaUrl));
        applier(false);
        insert(split);
        assertEquals("0", readOnlyCount(split));
    }

    @Test
    void readYourWritesFallsBackToThePrimaryWhileTheReplicaIsBehind() throws Exception {
        ReadWriteSplit split = new ReadWriteSplit(new UrlSource(primaryUrl), new UrlSource(replicaUrl))
                .readYourWrites(Duration.ofMillis(300));
        applier(false);
        insert(split);
        assertEquals("1", readOnlyCount(split));
        assertEquals(1, split.counts()[2], "the read did not fall back");
    }

    @Test
    void readYourWritesWaitsForTheReplicaToCatchUp() throws Exception {
        ReadWriteSplit split = new ReadWriteSplit(new UrlSource(primaryUrl), new UrlSource(replicaUrl))
                .readYourWrites(Duration.ofSeconds(5));
        applier(false);
        insert(split);
        Thread resume = Thread.ofVirtual().start(() -> {
            try {
                Thread.sleep(300);
                applier(true);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        assertEquals("1", readOnlyCount(split));
        resume.join();
        assertArrayEquals(new long[] {1, 1, 0}, split.counts(), "the read did not wait for the replica");
    }

    private void insert(ReadWriteSplit split) throws SQLException {
        try (Connection c = split.getConnection()) {
            execute(c, "insert into " + table + " values (1)");
        }
    }

    private String readOnlyCount(ReadWriteSplit split) throws SQLException {
        try (Connection c = split.getConnection()) {
            c.setReadOnly(true);
            return one(c, "select count(*) from " + table);
        }
    }

    /** Starts or stops the replica's applier - the replica keeps receiving, it stops applying. */
    private static void applier(boolean on) throws SQLException {
        try (Connection c = DriverManager.getConnection(replicaRootUrl)) {
            execute(c, on ? "start replica sql_thread" : "stop replica sql_thread");
        }
    }

    private static String one(Connection c, String sql) throws SQLException {
        try (Statement s = c.createStatement(); ResultSet rows = s.executeQuery(sql)) {
            rows.next();
            return rows.getString(1);
        }
    }

    private static void execute(Connection c, String sql) throws SQLException {
        try (Statement s = c.createStatement()) {
            s.execute(sql);
        }
    }

    /** A pool wants a {@code DataSource}; a driver wants a URL. */
    private record UrlSource(String url) implements DataSource {

        @Override
        public Connection getConnection() throws SQLException {
            return DriverManager.getConnection(url);
        }

        @Override
        public Connection getConnection(String user, String password) throws SQLException {
            return getConnection();
        }

        @Override
        public PrintWriter getLogWriter() {
            return null;
        }

        @Override
        public void setLogWriter(PrintWriter out) {
        }

        @Override
        public void setLoginTimeout(int seconds) {
        }

        @Override
        public int getLoginTimeout() {
            return 0;
        }

        @Override
        public Logger getParentLogger() {
            return Logger.getLogger("seclume.test");
        }

        @Override
        public <T> T unwrap(Class<T> type) throws SQLException {
            throw new SQLException("not a wrapper for " + type);
        }

        @Override
        public boolean isWrapperFor(Class<?> type) {
            return false;
        }
    }
}
