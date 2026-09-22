package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * A connection out of the pool knows which schema it is on - the shape that
 * actually failed.
 *
 * <p><b>E7, and what is known about it.</b> Two full reactor runs on
 * 21.09.2026 failed in Flyway with <i>"Unable to determine the original schema
 * for the connection"</i>, which is MySQL answering {@code NULL} to
 * {@code select database()}. It has never been reproduced: not in six runs of
 * the failing test, not in four runs of its whole module, and not in any
 * reactor run on 22.09.
 *
 * <p>Five mechanisms were worked through on 22.09 and each is ruled out, which
 * is worth writing down because it is where the next attempt starts:
 *
 * <ul>
 *   <li><b>The database was dropped.</b> MySQL answers {@code NULL} to
 *       {@code DATABASE()} when the current one has gone. No test in this
 *       repository creates or drops a database.</li>
 *   <li><b>The pool restored a wrong catalog.</b> It only reapplies one that
 *       the borrower set itself, and only when rebuilding a broken
 *       connection.</li>
 *   <li><b>An answer belonging to something else.</b> This is the failure the
 *       Oracle driver had - a call sent while earlier answers are outstanding.
 *       MySQL's {@code query} flushes the pipeline and any pending session
 *       setting first.</li>
 *   <li><b>The login packet.</b> The database is written only under
 *       {@code CONNECT_WITH_DB}, and the buffer position is advanced for every
 *       authentication plugin - the one place where a wrong length would have
 *       written the database over the auth response.</li>
 *   <li><b>An undrained result.</b> A server-side cursor is closed by
 *       {@code closeCursorIfOpen}, and without a fetch size the driver reads
 *       the whole answer before {@code executeQuery} returns.</li>
 * </ul>
 *
 * <p>So this is not a reproduction. It is the assertion put where the failure
 * was: <b>through the pool</b>, both the way Flyway asks and the way the
 * driver answers from its own belief, on connections borrowed and returned
 * concurrently. If it comes back, it fails here with both values printed
 * rather than inside a migration tool's error message.
 */
@Timeout(300)
class SchemaSurvivesThePoolTest {

    private static final int THREADS = 8;
    private static final int ROUNDS = 25;
    private static final String DATABASE = "seclume_test";

    @Test
    void everyBorrowedConnectionKnowsItsSchema() throws Exception {
        String host = System.getProperty("seclume.mysql.host", TestHosts.database());
        Assumptions.assumeTrue(host != null, "no MySQL host configured");
        int port = Integer.getInteger("seclume.mysql.port", 3307);
        String named = System.getProperty("seclume.mysql.passwordFile", ".local-mysql-password");
        Path password = null;
        for (Path candidate : List.of(Path.of(named), Path.of("..", named))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no " + named);
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no MySQL on " + host + ":" + port);
        }

        String url = "jdbc:seclume:mysql://" + host + ":" + port + "/" + DATABASE
                + "?user=seclume_test&tls=off&allowPublicKeyRetrieval=true"
                + "&provider=file&path="
                + password.toString().replace(java.io.File.separatorChar, '/');

        PoolSettings settings = new PoolSettings();
        settings.setName("schema");
        // Fewer connections than threads, so every one of them is borrowed,
        // returned and borrowed again by somebody else - which is the state
        // the failing run was in.
        settings.setMaximumPoolSize(3);
        settings.setConnectionTimeout(Duration.ofSeconds(10));

        List<String> wrong = new CopyOnWriteArrayList<>();
        try (SeclumePool pool = new SeclumePool(new UrlSource(url), settings)) {
            CountDownLatch startTogether = new CountDownLatch(1);
            CountDownLatch finished = new CountDownLatch(THREADS);
            for (int thread = 0; thread < THREADS; thread++) {
                int id = thread;
                Thread.ofVirtual().start(() -> {
                    try {
                        startTogether.await();
                        for (int round = 0; round < ROUNDS; round++) {
                            check(pool, id, round, wrong);
                        }
                    } catch (Exception trouble) {
                        wrong.add("thread " + id + " threw " + trouble);
                    } finally {
                        finished.countDown();
                    }
                });
            }
            startTogether.countDown();
            assertTrue(finished.await(240, TimeUnit.SECONDS), "the threads did not finish");
        }
        assertEquals(List.of(), wrong,
                "a pooled connection did not know its schema - the intermittent this test "
                + "was written for, and the five mechanisms in the class comment are the "
                + "ones already ruled out");
    }

    private static void check(SeclumePool pool, int id, int round, List<String> wrong)
            throws SQLException {
        try (Connection connection = pool.getConnection()) {
            // The way Flyway asks.
            try (Statement statement = connection.createStatement();
                    ResultSet rows = statement.executeQuery("select database()")) {
                if (!rows.next()) {
                    wrong.add(where(id, round) + "select database() returned no row");
                    return;
                }
                String said = rows.getString(1);
                if (!DATABASE.equals(said)) {
                    wrong.add(where(id, round) + "select database() said " + said);
                }
            }
            // The way the driver answers out of its own belief.
            String believed = connection.getCatalog();
            if (!DATABASE.equals(believed)) {
                wrong.add(where(id, round) + "getCatalog said " + believed);
            }
            // And a statement afterwards, because a connection that has lost
            // its schema fails here rather than at the question above.
            try (Statement statement = connection.createStatement();
                    ResultSet rows = statement.executeQuery(
                            "select count(*) from information_schema.tables "
                            + "where table_schema = database()")) {
                assertTrue(rows.next());
            }
        }
    }

    private static String where(int id, int round) {
        return "thread " + id + " round " + round + ": ";
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
