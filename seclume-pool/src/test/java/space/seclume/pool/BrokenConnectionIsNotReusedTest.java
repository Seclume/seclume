package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.List;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.BreakableRelay;
import space.seclume.tck.TestHosts;

/**
 * A connection that died under a statement does not go out again.
 *
 * <p>Found by the chaos benchmark, and it is the kind of defect that only a
 * chaos run produces: every ordinary test either checks the connection on the
 * way out (and then this cannot happen) or lets a whole second pass between
 * requests (and then it cannot happen either). Under load, with the default
 * validation window of half a second, it happened on every request.
 *
 * <p><b>The mechanism.</b> A statement runs on the driver's own object, not
 * through the pool - so when the connection dies mid-statement the pool is
 * never told. The connection comes back unmarked, and the next checkout hands
 * it out unchecked because it was returned a moment ago. The application then
 * gets the same failure again, and again, for as long as requests keep
 * arriving faster than the validation window. A database that went away for
 * two seconds takes the pool with it until the traffic stops.
 *
 * <p>The failure is produced with a relay that <b>swallows the answers</b>:
 * the request reaches the server, the answer never comes back. Cutting the
 * connection outright would not do it - that usually kills the request first,
 * and then every connection is visibly dead rather than quietly so.
 */
@Timeout(180)
class BrokenConnectionIsNotReusedTest {

    @Test
    void afterAStatementDiesTheConnectionIsNotHandedOutAgain() throws Exception {
        String host = TestHosts.postgres();
        int port = TestHosts.postgresPort();
        Path password = null;
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no PostgreSQL password file");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no PostgreSQL on " + host + ":" + port);
        }

        try (BreakableRelay relay = BreakableRelay.to(host, port)) {
            String url = "jdbc:seclume:postgresql://127.0.0.1:" + relay.port()
                    + "/seclume_test?user=seclume_test&tls=off&provider=file&path="
                    + password.toString().replace('\\', '/');

            PoolSettings settings = new PoolSettings();
            settings.setName("broken-reuse");
            settings.setMaximumPoolSize(1);
            settings.setConnectionTimeout(Duration.ofSeconds(5));
            // The default window, deliberately: this is about what happens in
            // production, where a connection returned a moment ago goes out
            // again without being asked whether it is still there.

            try (SeclumePool pool = new SeclumePool(new UrlSource(url), settings)) {
                // One healthy request, so the pool holds a real connection.
                try (Connection connection = pool.getConnection();
                        Statement statement = connection.createStatement()) {
                    statement.execute("select 1");
                }

                // From here the server's answers are thrown away: the request
                // lands, the answer never returns.
                relay.swallowAnswers();

                SQLException first = assertThrows(SQLException.class, () -> {
                    try (Connection connection = pool.getConnection();
                            PreparedStatement statement = connection.prepareStatement(
                                    "select 1")) {
                        statement.executeQuery().close();
                    }
                });
                assertTrue(String.valueOf(first.getSQLState()).startsWith("08"),
                        "expected a connection failure, got " + first.getSQLState());

                // The point: the next request must not be handed the same dead
                // connection. It may fail - there is nothing healthy to reach -
                // but it has to fail while trying to build a new one, not while
                // using the broken one.
                SQLException second = assertThrows(SQLException.class, () -> {
                    try (Connection connection = pool.getConnection();
                            PreparedStatement statement = connection.prepareStatement(
                                    "select 1")) {
                        statement.executeQuery().close();
                    }
                });
                assertTrue(String.valueOf(second.getMessage()).contains("could not be reached")
                                || String.valueOf(second.getMessage()).contains("timed out")
                                || String.valueOf(second.getMessage()).contains("startup")
                                || String.valueOf(second.getMessage()).contains("handshake"),
                        "the pool handed out the dead connection again: " + second.getMessage()
                                + " (state " + second.getSQLState() + ")");
            }
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
