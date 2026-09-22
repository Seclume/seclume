package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
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
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Failover without a cluster: a server goes away and the application keeps
 * working - and the exact point at which it does not.
 *
 * <p>The two halves exist already and are tested apart. {@code HostList} takes
 * the next server when one cannot be reached; the pool replaces a connection
 * that is no longer good. What was never shown is <b>the two together against
 * a real server</b>, which is the only form in which they are a feature: a
 * database that goes away under a running application.
 *
 * <p><b>How a server is made to go away.</b> The driver is pointed at a list
 * of two - a relay in this process, and the real server behind it. The first
 * connection goes through the relay; then the relay is cut, taking the socket
 * with it, and only the second entry is left. A rollout in miniature, and it
 * needs no second database.
 *
 * <p><b>The second test is the one that has to stay.</b> A statement that was
 * running when the server went away fails, and the failure reaches the
 * application. That is deliberate: the pool replaces a connection when it can
 * establish that nothing was lost, and a statement in flight is precisely the
 * case where it cannot. Quietly running it again is how a booking happens
 * twice - a worse failure than the one being avoided, and one that would look
 * like a green test.
 *
 * <p>So the honest summary of failover without a cluster is: <b>the next
 * request works, this one fails.</b> For a web application with a connection
 * per request that is the whole of what is wanted; for a long-running job it
 * is a retry the job has to do itself, because only the job knows whether its
 * work can be repeated.
 *
 * <p>Both run against all four databases, because "the pool is
 * driver-independent" is an argument and not evidence.
 */
@Timeout(240)
class FailoverWithoutClusterTest {

    /** What one database needs to be asked these two questions. */
    private record Database(String name, String scheme, int port, String database, String user,
                            String passwordFile, String options, String sessionId) {

        /** {@code jdbc:seclume:<scheme>://<hosts>/<database>?...} */
        String url(String hosts, Path password) {
            return "jdbc:seclume:" + scheme + "://" + hosts + "/" + database
                    + "?user=" + user + options
                    + "&provider=file&path=" + password.toString().replace('\\', '/');
        }
    }

    static List<Database> databases() {
        return List.of(
                new Database("PostgreSQL", "postgresql", 5432, "seclume_test", "seclume_test",
                        ".local-pg-password", "&tls=off", "select pg_backend_pid()"),
                new Database("MySQL", "mysql", 3307, "seclume_test", "seclume_test",
                        ".local-mysql-password", "&tls=off", "select connection_id()"),
                // trustServerCertificate: the container makes its own
                // certificate and nobody signed it. Deliberate, and named.
                new Database("SQL Server", "sqlserver", 1433, "master", "sa",
                        ".local-mssql-password", "&trustServerCertificate=true",
                        "select @@spid"),
                new Database("Oracle", "oracle", 1521, "FREEPDB1", "seclume_test",
                        ".local-oracle-password", "",
                        "select sys_context('userenv', 'sid') from dual"));
    }

    /**
     * The next request works: a server that went away is left behind.
     *
     * <p><b>What counts as evidence here took two attempts.</b> The obvious
     * assertion - the session id changed - is worthless on two of the four:
     * SQL Server and Oracle hand the number of a session that just died
     * straight to the next one, so it comes back identical and the test
     * fails while the pool is doing exactly the right thing. What is asked
     * instead is asked of things that cannot be recycled: the relay saw no
     * second connection, so nothing was sent to the server that is gone, and
     * the pool opened a connection it did not have before.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void theNextRequestLandsOnTheServerThatIsStillThere(Database database) throws Exception {
        String host = hostOf(database);
        int port = portOf(database);
        Path password = passwordOf(database);
        reachable(host, port);

        try (Front front = Front.to(host, port)) {
            String both = "127.0.0.1:" + front.port() + "," + host + ":" + port;
            try (SeclumePool pool = pool(database.url(both, password),
                    "failover-" + database.scheme())) {
                try (Connection connection = pool.getConnection()) {
                    assertEquals("1", ask(connection, oneOf(database)));
                }
                assertEquals(1, front.connections(),
                        "the first connection should have gone through the relay");
                assertEquals(1, pool.statistics().created(), "one connection so far");

                // The server goes away while its connection sits in the pool -
                // a rollout, a firewall that forgets the socket, a restart.
                front.cut();

                try (Connection connection = pool.getConnection()) {
                    assertEquals("1", ask(connection, oneOf(database)),
                            "the next request should have landed on the other server");
                    assertNotNull(ask(connection, database.sessionId()),
                            "and it is a working session, not a handle that only looks open");
                }

                assertEquals(2, pool.statistics().created(),
                        "the dead connection should have been replaced, not handed back");
                assertEquals(1, front.connections(),
                        "nothing should have been sent to the server that went away");
            }
        }
    }

    /**
     * This request fails - and that is the design, not a gap.
     *
     * <p>A statement that was running when the server went away cannot be
     * repeated by anybody but the application: the pool does not know whether
     * the server had already done the work. So the failure goes through, with
     * the SQLState that says it was the connection, and the application
     * decides. Pinned against all four servers because it is the promise that
     * is easiest to break by accident - a well-meaning retry somewhere in the
     * middle would make every one of these tests pass and turn one interrupted
     * insert into two rows.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void aStatementThatWasRunningFailsRatherThanBeingRepeated(Database database)
            throws Exception {
        String host = hostOf(database);
        int port = portOf(database);
        Path password = passwordOf(database);
        reachable(host, port);

        try (Front front = Front.to(host, port)) {
            String both = "127.0.0.1:" + front.port() + "," + host + ":" + port;
            try (SeclumePool pool = pool(database.url(both, password),
                    "failover-open-" + database.scheme())) {
                try (Connection connection = pool.getConnection()) {
                    ask(connection, database.sessionId());
                    front.cut();

                    SQLException told = assertThrows(SQLException.class,
                            () -> ask(connection, database.sessionId()),
                            "a statement interrupted by a failure must not be repeated quietly");
                    assertTrue(told.getSQLState() != null && told.getSQLState().startsWith("08"),
                            "the failure should say it was the connection, got "
                                    + told.getSQLState() + ": " + told.getMessage());
                }

                // And the pool is not poisoned by it: the next request works.
                try (Connection connection = pool.getConnection()) {
                    assertEquals("1", ask(connection, oneOf(database)));
                }
            }
        }
    }

    // ---- the rig -----------------------------------------------------------

    private static SeclumePool pool(String url, String name) {
        PoolSettings settings = new PoolSettings();
        settings.setName(name);
        settings.setMaximumPoolSize(2);
        settings.setConnectionTimeout(Duration.ofSeconds(10));
        // Every checkout is checked. The default skips the check for half a
        // second after the last use - right in production, where the round
        // trip would otherwise cost more than the pool itself, and wrong here:
        // a test that hands a connection back and takes it again within
        // microseconds would be measuring the clock rather than the pool.
        // (The production consequence of that window is real and deliberate:
        // a connection returned 100 ms before its server went away does go
        // out unchecked, and the application sees the failure.)
        settings.setValidationBypassWindow(Duration.ofNanos(1));
        return new SeclumePool(new UrlSource(url), settings);
    }

    private static String ask(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement();
                ResultSet answer = statement.executeQuery(sql)) {
            return answer.next() ? String.valueOf(answer.getString(1)) : null;
        }
    }

    /** {@code select 1} where the database allows it, and from dual where not. */
    private static String oneOf(Database database) {
        return "oracle".equals(database.scheme()) ? "select 1 from dual" : "select 1";
    }

    /** The port this machine runs it on - 5433 for PostgreSQL here, say. */
    private static int portOf(Database database) {
        return Integer.getInteger("seclume." + key(database) + ".port", database.port());
    }

    private static String hostOf(Database database) {
        String host = System.getProperty("seclume." + key(database) + ".host",
                space.seclume.tck.TestHosts.database());
        Assumptions.assumeTrue(host != null, "no host configured for " + database.name());
        return host;
    }

    private static String key(Database database) {
        return switch (database.scheme()) {
            case "postgresql" -> "pg";
            case "sqlserver" -> "mssql";
            default -> database.scheme();
        };
    }

    /**
     * The password file this machine uses, which is not always the obvious
     * one: the PostgreSQL here is the TLS instance and has its own.
     */
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

    private static void reachable(String host, int port) {
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("nothing on " + host + ":" + port);
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

    /**
     * A server that can be taken away.
     *
     * <p>Bytes in both directions and nothing else - it has to be transparent
     * to four protocols including one that is TLS from the first byte, so it
     * must not have an opinion about any of them. {@link #cut()} is the whole
     * point: the listener closes and every socket it is relaying is dropped,
     * which is what a server going away looks like from inside a driver.
     */
    private static final class Front implements AutoCloseable {

        private final ServerSocket listener;
        private final String host;
        private final int port;
        private final List<Socket> open = new CopyOnWriteArrayList<>();
        private volatile boolean stopped;
        private volatile int connections;

        private Front(ServerSocket listener, String host, int port) {
            this.listener = listener;
            this.host = host;
            this.port = port;
            Thread.ofVirtual().name("front-accept").start(this::accept);
        }

        static Front to(String host, int port) throws IOException {
            ServerSocket listener = new ServerSocket();
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            return new Front(listener, host, port);
        }

        int port() {
            return listener.getLocalPort();
        }

        int connections() {
            return connections;
        }

        private void accept() {
            while (!stopped) {
                Socket from;
                try {
                    from = listener.accept();
                } catch (IOException closed) {
                    return;
                }
                connections++;
                open.add(from);
                Socket to = new Socket();
                try {
                    to.connect(new InetSocketAddress(host, port), 5_000);
                } catch (IOException unreachable) {
                    close(from);
                    continue;
                }
                open.add(to);
                pump(from, to);
                pump(to, from);
            }
        }

        private void pump(Socket from, Socket to) {
            Thread.ofVirtual().name("front-pump").start(() -> {
                byte[] buffer = new byte[16 * 1024];
                try (InputStream in = from.getInputStream();
                        OutputStream out = to.getOutputStream()) {
                    int read;
                    while ((read = in.read(buffer)) > 0) {
                        out.write(buffer, 0, read);
                        out.flush();
                    }
                } catch (IOException broken) {
                    // Either end going away ends this direction, which is all
                    // there is to say about it.
                } finally {
                    close(from);
                    close(to);
                }
            });
        }

        /** The server goes away, taking the connections on it. */
        void cut() throws IOException {
            stopped = true;
            listener.close();
            for (Socket socket : open) {
                close(socket);
            }
            open.clear();
        }

        private static void close(Socket socket) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // Closing twice is how this is used.
            }
        }

        @Override
        public void close() throws IOException {
            if (!stopped) {
                cut();
            }
        }
    }
}
