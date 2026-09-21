package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertTrue;

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
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * A fetch size has to mean the same thing here as it does elsewhere.
 *
 * <p>The property is the one that decides whether seclume can be dropped in
 * without thinking: <b>an application that reads a large table with a fetch
 * size must not need more memory here than it needed with the driver it came
 * from.</b> Not "seclume streams" as an absolute - if the vendor driver
 * buffers too, buffering is the behaviour the application already survives -
 * but "no worse than what it replaces".
 *
 * <p>Measured rather than reasoned about. A pass-through proxy counts the
 * bytes the server actually sent by the time the tenth row of a
 * twenty-thousand-row result has been read. Streaming is a few kilobytes;
 * buffering is the whole million.
 *
 * <p>This exists because of what it caught. seclume streamed on a
 * {@code PreparedStatement} and read the entire result on a plain
 * {@code Statement} - 1 188 987 bytes against pgjdbc's 2 957 - and the driver
 * said why: the simple protocol has no row limit, so a fetch size could not
 * be honoured. True of the protocol, and the wrong conclusion for a driver.
 * pgjdbc reaches the same place by taking the statement through the extended
 * protocol once a fetch size is set, and seclume now does the same. Both
 * protocols are measured here so that neither can quietly regress.
 */
@Timeout(300)
class FetchSizeStreamingTest {

    private static final int ROWS = 20_000;
    /**
     * A tenth of the way is generous and unambiguous.
     *
     * <p>The full result is well over a megabyte, so anything under this is
     * streaming by any reading, and anything over it has read the table.
     */
    private static final long STREAMING_CEILING = 128 * 1024;

    @Test
    void postgresStreamsOnBothProtocols() throws Exception {
        Path password = locate(TestHosts.postgresPasswordFile());
        Assumptions.assumeTrue(password != null, "no PostgreSQL password file");
        Assumptions.assumeTrue(reachable(TestHosts.postgres(), TestHosts.postgresPort()),
                "no PostgreSQL");

        String secret = Files.readString(password).trim();
        String path = password.toString().replace('\\', '/');
        List<String> findings = new ArrayList<>();

        for (boolean prepared : new boolean[] {false, true}) {
            long mine = measure(TestHosts.postgres(), TestHosts.postgresPort(), prepared,
                    port -> "jdbc:seclume:postgresql://127.0.0.1:" + port
                            + "/seclume_test?user=seclume_test&tls=off&provider=file&path="
                            + path,
                    null, QUERY);
            long theirs = measure(TestHosts.postgres(), TestHosts.postgresPort(), prepared,
                    port -> "jdbc:postgresql://127.0.0.1:" + port + "/seclume_test",
                    secret, QUERY);

            String how = prepared ? "PreparedStatement" : "Statement";
            System.out.println("   " + how + ": seclume " + mine + " bytes, pgjdbc "
                    + theirs + " bytes by the tenth row");

            if (theirs < STREAMING_CEILING && mine >= STREAMING_CEILING) {
                findings.add(how + ": pgjdbc read " + theirs + " bytes before the tenth row "
                        + "and seclume read " + mine + " - the application would need the "
                        + "whole table in memory here and does not there");
            }
        }
        assertTrue(findings.isEmpty(), () -> String.join("\n  ", findings));
    }

    private static final String QUERY =
            "select i, repeat('x', 40) from generate_series(1, " + ROWS + ") i";

    @FunctionalInterface
    private interface UrlFor {
        String url(int port);
    }

    /**
     * Bytes from the server by the tenth row, with a fetch size of fifty.
     *
     * <p>Always with autocommit off: PostgreSQL will not hold a portal open
     * outside a transaction, so measuring without one would show only that a
     * cursor cannot exist there - a property of the database, not of either
     * driver.
     */
    private long measure(String host, int port, boolean prepared, UrlFor urls, String secret,
            String query) throws Exception {
        try (FaultProxy proxy = new FaultProxy(host, port, FaultProxy.Mode.PASS)) {
            Properties properties = new Properties();
            if (secret != null) {
                properties.setProperty("user", "seclume_test");
                properties.setProperty("password", secret);
            }
            try (Connection connection = secret == null
                    ? DriverManager.getConnection(urls.url(proxy.port()))
                    : DriverManager.getConnection(urls.url(proxy.port()), properties)) {

                connection.setAutoCommit(false);
                long before = proxy.relayedFromServer();
                try (Statement statement = prepared
                        ? connection.prepareStatement(query) : connection.createStatement()) {
                    statement.setFetchSize(50);
                    try (ResultSet rows = prepared
                            ? ((PreparedStatement) statement).executeQuery()
                            : statement.executeQuery(query)) {
                        for (int i = 0; i < 10 && rows.next(); i++) {
                            rows.getString(2);
                        }
                    }
                }
                long used = proxy.relayedFromServer() - before;
                connection.rollback();
                return used;
            }
        }
    }

    private static Path locate(String name) {
        for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static boolean reachable(String host, int port) {
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
            return true;
        } catch (IOException unreachable) {
            return false;
        }
    }
}
