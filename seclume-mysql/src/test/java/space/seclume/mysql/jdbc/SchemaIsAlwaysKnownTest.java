package space.seclume.mysql.jdbc;

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
import java.sql.Statement;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * A connection always knows which schema it is on.
 *
 * <p>Written for an intermittent that has been seen twice and never
 * reproduced: a full reactor run failed in Flyway with <i>"Unable to determine
 * the original schema for the connection"</i>, which is Flyway's way of saying
 * that {@code select database()} came back empty. A module re-run was always
 * green, and six runs of the same test on 22.09.2026 were green as well.
 *
 * <p>So this does not claim to reproduce it. What it does is turn the question
 * into an assertion that stands in the suite: the schema is asked for the way
 * Flyway asks, many times, on connections opened concurrently, and it has to
 * be the one in the URL every time. If the intermittent returns, it will fail
 * here with the two values printed rather than inside a migration tool's error
 * message, and that is the difference between an anecdote and a defect.
 *
 * <p>Both ways of asking are checked, because they travel differently: the
 * statement goes through the protocol and {@code getCatalog} is answered out
 * of what the driver believes. A driver whose belief and whose server disagree
 * is the more interesting of the two failures.
 */
@Timeout(300)
class SchemaIsAlwaysKnownTest {

    private static final int THREADS = 8;
    private static final int ROUNDS = 40;

    private String url;
    private String database;

    @BeforeEach
    void findTheServer() throws Exception {
        String host = System.getProperty("seclume.mysql.host", TestHosts.database());
        Assumptions.assumeTrue(host != null, "no MySQL host configured");
        int port = Integer.getInteger("seclume.mysql.port", 3307);
        database = "seclume_test";
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
        url = "jdbc:seclume:mysql://" + host + ":" + port + "/" + database
                + "?user=seclume_test&tls=off&allowPublicKeyRetrieval=true"
                + "&provider=file&path="
                + password.toString().replace(java.io.File.separatorChar, '/');
    }

    @Test
    void everyConnectionAnswersTheSchemaFlywayAsksFor() throws Exception {
        List<String> wrong = new CopyOnWriteArrayList<>();
        CountDownLatch startTogether = new CountDownLatch(1);
        CountDownLatch finished = new CountDownLatch(THREADS);

        for (int thread = 0; thread < THREADS; thread++) {
            int id = thread;
            Thread.ofVirtual().start(() -> {
                try {
                    startTogether.await();
                    for (int round = 0; round < ROUNDS; round++) {
                        try (Connection connection = DriverManager.getConnection(url)) {
                            // The way Flyway asks.
                            try (Statement statement = connection.createStatement();
                                    ResultSet rows = statement.executeQuery(
                                            "select database()")) {
                                if (!rows.next()) {
                                    wrong.add("thread " + id + " round " + round
                                            + ": select database() returned no row");
                                    continue;
                                }
                                String said = rows.getString(1);
                                if (!database.equals(said)) {
                                    wrong.add("thread " + id + " round " + round
                                            + ": select database() said " + said);
                                }
                            }
                            // And the way the driver answers out of its own belief.
                            String believed = connection.getCatalog();
                            if (!database.equals(believed)) {
                                wrong.add("thread " + id + " round " + round
                                        + ": getCatalog said " + believed);
                            }
                        }
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
        assertEquals(List.of(), wrong,
                "a connection did not know its schema - the intermittent this test "
                        + "was written for");
    }
}
