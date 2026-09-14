package space.seclume.postgresql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.secret.FileSecretProvider;
import space.seclume.secret.SecretProvider;

/**
 * Against a real PostgreSQL server.
 *
 * <p>Expects the role and database {@code seclume_test} on
 * {@code localhost:5432} and the password in the file
 * {@code .local-pg-password} in the project directory. If one of those is
 * missing the test is skipped rather than failed - on someone else's machine
 * its absence is not an error.
 *
 * <p>The password comes in through the {@link FileSecretProvider}, that is
 * along exactly the path the library offers. It appears in no test code, in no
 * environment variable and in no message.
 *
 * <p>With Docker, Testcontainers against several server versions would be the
 * right thing here; that is in the task and will come as soon as a Docker
 * daemon is available. A running server is a running server - but one version
 * is not two.
 */
class LocalPostgresTest {

    private static final String HOST = "127.0.0.1";
    private static final int PORT = 5432;
    private static final String DATABASE = "seclume_test";
    private static final String USER = "seclume_test";

    private static Path passwordFile;

    @BeforeAll
    static void findTheServer() {
        passwordFile = locatePasswordFile();
        Assumptions.assumeTrue(passwordFile != null && Files.exists(passwordFile),
                "no .local-pg-password - skipping the tests against a real server");
        Assumptions.assumeTrue(reachable(), "no PostgreSQL on " + HOST + ":" + PORT);
    }

    @Test
    void connectsWithScramAndAsksTheServerWhoWeAre() throws Exception {
        try (PgSession session = open()) {
            List<String> answer = new ArrayList<>();
            session.simpleQuery("select current_user, current_database()",
                    row -> {
                        answer.add(row.getString(0));
                        answer.add(row.getString(1));
                    });
            assertEquals(List.of(USER, DATABASE), answer);
            assertNotNull(session.parameters().get("server_version"));
            assertEquals('I', session.transactionStatus());
        }
    }

    /**
     * The login method really was SCRAM, not cleartext and not md5. The
     * session remembers it; an ordinary user is not allowed to read
     * {@code pg_authid}.
     */
    @Test
    void theServerUsesScram() throws Exception {
        try (PgSession session = open()) {
            assertEquals("scram-sha-256", session.authenticationMethod());
        }
    }

    @Test
    void readsRowsWithoutCopying() throws Exception {
        try (PgSession session = open()) {
            long[] sum = {0};
            int[] rows = {0};
            session.simpleQuery("select generate_series(1, 1000) as n", row -> {
                sum[0] += row.getLong(0);
                rows[0]++;
                // The raw bytes sit in the receive buffer, not in a copy.
                assertTrue(row.raw(0).byteSize() >= 1);
            });
            assertEquals(1000, rows[0]);
            assertEquals(500_500, sum[0]);
        }
    }

    @Test
    void handlesNullsAndTypes() throws Exception {
        try (PgSession session = open()) {
            List<String> values = new ArrayList<>();
            session.simpleQuery(
                    "select null::text, 42::int8, true, 'mit Umlaut äöü'::text",
                    row -> {
                        values.add(row.isNull(0) ? "<null>" : row.getString(0));
                        values.add(String.valueOf(row.getLong(1)));
                        values.add(String.valueOf(row.getBoolean(2)));
                        values.add(row.getString(3));
                    });
            assertEquals(List.of("<null>", "42", "true", "mit Umlaut äöü"), values);
        }
    }

    @Test
    void reportsServerErrorsWithSqlState() throws Exception {
        try (PgSession session = open()) {
            PgException failure = assertThrows(PgException.class,
                    () -> session.execute("select * from a_table_that_does_not_exist"));
            assertEquals("42P01", failure.getSQLState());
            assertTrue(failure.getMessage().contains("a_table_that_does_not_exist"));
            // After the error the session has to stay usable.
            session.execute("select 1");
        }
    }

    @Test
    void runsDdlAndDml() throws Exception {
        try (PgSession session = open()) {
            session.execute("drop table if exists seclume_probe");
            session.execute("create table seclume_probe (id int primary key, label text)");
            session.execute("insert into seclume_probe values (1, 'eins'), (2, 'zwei')");
            assertEquals("INSERT 0 2", session.lastCommandTag());

            List<String> labels = new ArrayList<>();
            session.simpleQuery("select label from seclume_probe order by id",
                    row -> labels.add(row.getString(0)));
            assertEquals(List.of("eins", "zwei"), labels);

            session.execute("drop table seclume_probe");
        }
    }

    /** A wrong password has to fail cleanly, not hang. */
    @Test
    void wrongPasswordFailsWithAnAuthenticationError() {
        SecretProvider wrong = new space.seclume.secret.CallbackSecretProvider(
                32, target -> {
                    for (int i = 0; i < 8; i++) {
                        target.set(java.lang.foreign.ValueLayout.JAVA_BYTE, i, (byte) 'x');
                    }
                    return 8;
                });
        SQLException failure = assertThrows(SQLException.class,
                () -> PgSession.open(new PgSession.Settings(HOST, PORT, DATABASE, USER, wrong))
                        .close());
        assertEquals("28P01", failure.getSQLState());
    }

    private static PgSession open() throws SQLException {
        return PgSession.open(new PgSession.Settings(HOST, PORT, DATABASE, USER,
                new FileSecretProvider(passwordFile, 256)));
    }

    /** Depending on where it starts, the project directory is one level up. */
    private static Path locatePasswordFile() {
        for (Path candidate : List.of(Path.of(".local-pg-password"),
                Path.of("..", ".local-pg-password"))) {
            if (Files.exists(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private static boolean reachable() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 1000);
            return true;
        } catch (IOException e) {
            return false;
        }
    }
}
