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
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.QueryStorms;
import space.seclume.jfr.Observed;
import space.seclume.tck.TestHosts;

/**
 * An N+1 written on purpose, against a real server, and found.
 *
 * <p>{@code QueryStormsTest} proves the counting. It does that by calling the
 * listener itself, which proves nothing about whether a driver ever calls it -
 * and a detector that is never called reports nothing, exactly like one that
 * finds nothing. So this one installs it and then writes the defect it is
 * looking for: a loop that reads a row at a time instead of a set.
 *
 * <p>It also checks the fingerprint that comes back, because that is the
 * detector's only output and the whole of what it may carry. If the parameter
 * were in there, the report of a performance problem would be a data leak.
 */
@Timeout(120)
class LocalQueryStormTest {

    private static final String DATABASE = "seclume_test";
    private static final String USER = "seclume_test";

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
            socket.connect(new InetSocketAddress(
                    TestHosts.postgres(), TestHosts.postgresPort()), 2000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on " + TestHosts.postgres()
                    + ":" + TestHosts.postgresPort());
        }
        url = "jdbc:seclume:postgresql://" + TestHosts.postgres()
                + ":" + TestHosts.postgresPort() + "/" + DATABASE
                + "?user=" + USER + "&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    @AfterEach
    void removeTheListener() {
        Observed.listen(null);
    }

    @Test
    void aRowAtATimeLoopIsReported() throws Exception {
        List<QueryStorms.Storm> found = new CopyOnWriteArrayList<>();
        QueryStorms.watching(10, Duration.ofSeconds(30), found::add).install();

        try (Connection connection = DriverManager.getConnection(url);
             PreparedStatement one = connection.prepareStatement(
                     "select n from generate_series(1, 1) as n where n = ?")) {
            // The defect, written out: a value at a time, in a loop, where one
            // statement with an IN list would have done.
            for (int i = 1; i <= 30; i++) {
                one.setInt(1, 1);
                try (ResultSet rows = one.executeQuery()) {
                    while (rows.next()) {
                        rows.getInt(1);
                    }
                }
            }
        }

        assertTrue(!found.isEmpty(),
                "thirty executions of one statement in a loop were not reported - either "
                + "the driver never calls the listener, or the counting is wrong");
        assertEquals(1, found.size(), "reported " + found.size() + " times, expected once");

        QueryStorms.Storm storm = found.get(0);
        assertEquals("postgresql", storm.kind());
        assertEquals(10, storm.executions(), "reported at the threshold");
        assertTrue(storm.fingerprint().contains("?"),
                "the fingerprint should carry a placeholder: " + storm.fingerprint());
        assertTrue(!storm.fingerprint().contains("generate_series(1, 1)"),
                "the literals are still in the fingerprint: " + storm.fingerprint());
        assertTrue(storm.within().toMillis() >= 0);
    }

    /** And a request that runs many different statements is left alone. */
    @Test
    void aVariedRequestAgainstTheServerIsNotReported() throws Exception {
        List<QueryStorms.Storm> found = new CopyOnWriteArrayList<>();
        QueryStorms.watching(10, Duration.ofSeconds(30), found::add).install();

        try (Connection connection = DriverManager.getConnection(url);
             java.sql.Statement statement = connection.createStatement()) {
            for (int i = 0; i < 30; i++) {
                // Different shapes, not different values. Two things had to be
                // avoided here and the first attempt hit both: a fingerprint
                // folds "select 1" and "select 2" into one - correctly - and
                // it also collapses a list of placeholders, so varying the
                // number of columns produced "select ?" thirty times and the
                // detector was right to report it. Identifiers are kept, so
                // the alias is what differs.
                try (ResultSet rows = statement.executeQuery(
                        "select 1 as column_" + i)) {
                    assertTrue(rows.next());
                }
            }
        }

        assertTrue(found.isEmpty(), "a varied request was reported as a storm: " + found);
    }
}
