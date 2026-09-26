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
 * Against a real PostgreSQL primary and its streaming replica:
 * {@code -Dseclume.pgrepl.primary=5440 -Dseclume.pgrepl.replica=5441}, the
 * password in {@code .local-pgrepl-password}. Replay on the replica is paused
 * where a test needs it behind, so that "not yet replicated" is certain rather
 * than a race.
 */
@Timeout(60)
class ReadWriteSplitTest {

    private static String primaryUrl;
    private static String replicaUrl;
    private String table;

    @BeforeAll
    static void findTheServers() {
        int primary = Integer.getInteger("seclume.pgrepl.primary", 0);
        int replica = Integer.getInteger("seclume.pgrepl.replica", 0);
        Assumptions.assumeTrue(primary > 0 && replica > 0, "no primary and replica configured");
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-pgrepl-password"),
                Path.of("..", ".local-pgrepl-password"))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-pgrepl-password");
        String host = System.getProperty("seclume.pgrepl.host", TestHosts.database());
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, primary), 2000);
        } catch (IOException e) {
            Assumptions.abort("no primary on " + host + ":" + primary);
        }
        String tail = "/seclume_test?user=seclume_test&tls=off&provider=file&path="
                + password.toString().replace('\\', '/');
        primaryUrl = "jdbc:seclume:postgresql://" + host + ":" + primary + tail;
        replicaUrl = "jdbc:seclume:postgresql://" + host + ":" + replica + tail;
    }

    @BeforeEach
    void table() throws Exception {
        table = "rw_" + UUID.randomUUID().toString().substring(0, 8);
        try (Connection c = DriverManager.getConnection(primaryUrl)) {
            execute(c, "create table " + table + " (id int)");
        }
        waitForReplica();
    }

    @AfterEach
    void drop() throws Exception {
        replay(true);
        try (Connection c = DriverManager.getConnection(primaryUrl)) {
            execute(c, "drop table if exists " + table);
        }
    }

    @Test
    void readOnlyGoesToTheReplicaAndEverythingElseToThePrimary() throws Exception {
        ReadWriteSplit split = new ReadWriteSplit(new UrlSource(primaryUrl),
                new UrlSource(replicaUrl));
        try (Connection c = split.getConnection()) {
            assertEquals("f", one(c, "select pg_is_in_recovery()"));
        }
        // Spring's order: readOnly and the transaction first, the statement after.
        try (Connection c = split.getConnection()) {
            c.setReadOnly(true);
            c.setAutoCommit(false);
            assertEquals("t", one(c, "select pg_is_in_recovery()"));
            c.commit();
        }
        // Taken and given back without a statement: nothing opened at all.
        split.getConnection().close();
        assertArrayEquals(new long[] {1, 1, 0}, split.counts());
    }

    /** The control: without read-your-writes, a row the replica has not replayed is missing. */
    @Test
    void withoutReadYourWritesTheOwnWriteIsNotThere() throws Exception {
        ReadWriteSplit split = new ReadWriteSplit(new UrlSource(primaryUrl),
                new UrlSource(replicaUrl));
        replay(false);
        insert(split);
        assertEquals("0", readOnlyCount(split));
    }

    @Test
    void readYourWritesFallsBackToThePrimaryWhileTheReplicaIsBehind() throws Exception {
        ReadWriteSplit split = new ReadWriteSplit(new UrlSource(primaryUrl),
                new UrlSource(replicaUrl)).readYourWrites(Duration.ofMillis(300));
        replay(false);
        insert(split);
        assertEquals("1", readOnlyCount(split));
        assertEquals(1, split.counts()[2], "the read did not fall back");
    }

    @Test
    void readYourWritesWaitsForTheReplicaToCatchUp() throws Exception {
        ReadWriteSplit split = new ReadWriteSplit(new UrlSource(primaryUrl),
                new UrlSource(replicaUrl)).readYourWrites(Duration.ofSeconds(5));
        replay(false);
        insert(split);
        Thread resume = Thread.ofVirtual().start(() -> {
            try {
                Thread.sleep(300);
                replay(true);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        assertEquals("1", readOnlyCount(split));
        resume.join();
        assertArrayEquals(new long[] {1, 1, 0}, split.counts(), "the read did not wait for the replica");
    }

    @Test
    void aCommittedTransactionIsNotedToo() throws Exception {
        ReadWriteSplit split = new ReadWriteSplit(new UrlSource(primaryUrl),
                new UrlSource(replicaUrl)).readYourWrites(Duration.ofMillis(300));
        replay(false);
        try (Connection c = split.getConnection()) {
            c.setAutoCommit(false);
            execute(c, "insert into " + table + " values (1)");
            c.commit();
        }
        assertEquals("1", readOnlyCount(split));
        assertEquals(1, split.counts()[2]);
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

    /** Pauses or resumes replay on the replica. */
    private static void replay(boolean on) throws SQLException {
        try (Connection c = DriverManager.getConnection(replicaUrl)) {
            one(c, on ? "select pg_wal_replay_resume()" : "select pg_wal_replay_pause()");
        }
    }

    private void waitForReplica() throws Exception {
        try (Connection c = DriverManager.getConnection(replicaUrl)) {
            for (int i = 0; i < 100; i++) {
                if ("t".equals(one(c, "select to_regclass('" + table + "') is not null"))) {
                    return;
                }
                Thread.sleep(50);
            }
        }
        throw new AssertionError("the replica never got the table");
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
