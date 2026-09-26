package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.Sensitive;
import space.seclume.secret.SecretScope;
import space.seclume.tck.ChildJvm;
import space.seclume.tck.HeapDumpScanner;
import space.seclume.tck.TestHosts;

/**
 * A secret stored <b>in</b> the database, read without becoming a String.
 *
 * <p>The library's whole claim is about the connection password. This is the
 * other half of the same problem and the half nobody says out loud: an
 * application that keeps API keys, signing keys or OAuth refresh tokens in a
 * table reads every one of them with {@code getString}, and from that moment
 * they have exactly the lifetime the connection password had before any of
 * this was written.
 *
 * <p>So the assertion here is the same one the connection password gets, with
 * the same instrument: a real heap dump is taken and searched, and the value
 * must not be in it. And with the same negative control - the value is put on
 * the heap on purpose first, and the search has to find it. Without that, a
 * broken searcher and a clean heap look identical.
 */
@Timeout(300)
class LocalSensitiveColumnTest {

    private static final String DATABASE = "seclume_test";
    private static final String USER = "seclume_test";
    /** Long and unmistakable, so a hit in a dump is a hit and not a coincidence. */
    private static final String STORED_KEY = "zl-stored-secret-6f4c2b8a19d7e530-zl";

    private static String url;

    @BeforeAll
    static void findTheServer() throws Exception {
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

        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("drop table if exists zl_vault");
            statement.execute("create table zl_vault (id int primary key, "
                    + "signing_key text, binary_key bytea, missing text)");
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into zl_vault values (1, ?, ?, null)")) {
                insert.setString(1, STORED_KEY);
                insert.setBytes(2, STORED_KEY.getBytes(StandardCharsets.UTF_8));
                insert.executeUpdate();
            }
        }
    }

    @AfterAll
    static void tidyUp() throws Exception {
        if (url == null) {
            return;
        }
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("drop table if exists zl_vault");
        }
    }

    @Test
    void theValueArrivesAndIsTheRightOne() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select signing_key, missing from zl_vault where id = 1")) {
            assertTrue(rows.next());
            Sensitive sensitive = Sensitive.of(rows);

            byte[] expected = STORED_KEY.getBytes(StandardCharsets.UTF_8);
            assertEquals(expected.length, sensitive.length(1),
                    "the length has to be known before the segment is sized");

            try (SecretScope key = SecretScope.allocate(128)) {
                // segment() to write into, length() to say how much, secret()
                // to read out of. Handing secret() to readInto gives it a
                // slice of length zero, which is the mistake this comment
                // exists to stop the next person making.
                int written = sensitive.readInto(1, key.segment());
                key.length(written);
                assertEquals(expected.length, written);
                assertEquals(expected.length, key.secret().byteSize());
                for (int i = 0; i < written; i++) {
                    assertEquals(expected[i], key.secret().get(ValueLayout.JAVA_BYTE, i),
                            "byte " + i + " differs");
                }
            }

            // A null column is -1 and not an exception: it is an answer, and
            // a caller branching on it is doing the right thing.
            assertEquals(-1, sensitive.length(2));
            try (SecretScope empty = SecretScope.allocate(16)) {
                assertEquals(-1, sensitive.readInto(2, empty.segment()));
            }
        }
    }

    @Test
    void aSegmentThatIsTooSmallIsRefusedRatherThanFilled() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select signing_key from zl_vault where id = 1")) {
            assertTrue(rows.next());
            Sensitive sensitive = Sensitive.of(rows);
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment tooSmall = arena.allocate(4);
                SQLException refused = assertThrows(SQLException.class,
                        () -> sensitive.readInto(1, tooSmall));
                assertEquals("22001", refused.getSQLState(),
                        "a truncated key fails somewhere far from here, so it is refused here");
            }
        }
    }

    /**
     * A result set built from values rather than from the answer says so.
     *
     * <p>An array's {@code getResultSet} is a list, not a window onto the
     * receive buffer, and there is nothing native in it to hand out. Saying
     * that is better than copying quietly behind an API whose entire purpose
     * is that there is no copy.
     */
    @Test
    void whatIsNotAWindowSaysSo() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select array['a', 'b']::text[] as pair")) {
            assertTrue(rows.next());
            try (ResultSet elements = rows.getArray(1).getResultSet()) {
                assertTrue(elements.next());
                if (!elements.isWrapperFor(Sensitive.class)) {
                    // Also a correct answer: it does not claim to be one.
                    return;
                }
                Sensitive sensitive = Sensitive.of(elements);
                try (Arena arena = Arena.ofConfined()) {
                    MemorySegment target = arena.allocate(64);
                    SQLException refused = assertThrows(SQLException.class,
                            () -> sensitive.readInto(2, target));
                    assertEquals("0A000", refused.getSQLState());
                }
            }
        }
    }

    /**
     * The assertion that is the whole point, and its negative control.
     *
     * <p>Both in a <b>child JVM</b>, and the first version of this was not -
     * it failed, correctly, because the value is a constant in this test
     * class: interned, permanent, and found by every search. A proof about
     * what is in a heap cannot run in a process that was told the answer.
     *
     * <p>So the child is given the row to read and never what is in it. One
     * run reads it through {@link Sensitive} and its dump must be clean; the
     * other reads it with {@code getString} and its dump must contain it,
     * because a searcher that finds nothing either way proves nothing either
     * way.
     */
    @Test
    void theValueIsNotOnTheHeapAfterANativeRead() throws Exception {
        Path dump = Files.createTempFile("zl-native-", ".hprof");
        Files.delete(dump);
        try {
            ChildJvm.Result result = ChildJvm.run(SensitiveColumnProbe.class,
                    List.of(url, dump.toString(), "native"), 180);
            assertEquals(0, result.exitCode(), "the probe failed:\n" + result.output());
            assertTrue(result.output().contains("bytes natively"),
                    "the probe did not read anything:\n" + result.output());

            List<HeapDumpScanner.Finding> findings = HeapDumpScanner.scan(dump, STORED_KEY);
            assertTrue(findings.isEmpty(),
                    "a secret read out of a table is in the heap dump - which is the one "
                    + "thing this API exists to prevent:\n"
                    + findings.stream().map(Object::toString)
                            .reduce("", (a, b) -> a + "\n" + b));
        } finally {
            Files.deleteIfExists(dump);
        }
    }

    /** The control: read as a String, the same searcher has to find it. */
    @Test
    void theSearchFindsItWhenItIsReadTheOrdinaryWay() throws Exception {
        Path dump = Files.createTempFile("zl-string-", ".hprof");
        Files.delete(dump);
        try {
            ChildJvm.Result result = ChildJvm.run(SensitiveColumnProbe.class,
                    List.of(url, dump.toString(), "string"), 180);
            assertEquals(0, result.exitCode(), "the probe failed:\n" + result.output());
            assertTrue(result.output().contains("characters as a String"),
                    "the probe did not read anything:\n" + result.output());

            assertTrue(!HeapDumpScanner.scan(dump, STORED_KEY).isEmpty(),
                    "the search did not find a value that is definitely on the heap, so it "
                    + "would not have found one that should not be there either");
        } finally {
            Files.deleteIfExists(dump);
        }
    }

    /**
     * The round trip that makes the pair worth having: written from native
     * memory, read back into native memory, never a String at either end.
     *
     * <p>A read-only secret API is half a feature. Rotating a key, storing a
     * freshly issued refresh token, saving a TOTP seed at enrolment - every
     * one of those is a parameter, and every one of them went through
     * {@code setString} until now.
     */
    @Test
    void aSecretCanBeWrittenAndReadBackWithoutAString() throws Exception {
        byte[] expected = STORED_KEY.getBytes(StandardCharsets.UTF_8);
        try (Connection connection = DriverManager.getConnection(url);
             SecretScope written = SecretScope.allocate(256)) {
            // Put the value into native memory the way a generator would.
            for (int i = 0; i < expected.length; i++) {
                written.segment().set(ValueLayout.JAVA_BYTE, i, expected[i]);
            }
            written.length(expected.length);

            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into zl_vault (id, signing_key) values (2, ?)")) {
                space.seclume.SensitiveParameters.of(insert)
                        .setSensitive(1, written.secret());
                assertEquals(1, insert.executeUpdate());
            }

            try (PreparedStatement read = connection.prepareStatement(
                    "select signing_key from zl_vault where id = 2");
                 ResultSet rows = read.executeQuery();
                 SecretScope back = SecretScope.allocate(256)) {
                assertTrue(rows.next());
                int length = Sensitive.of(rows).readInto(1, back.segment());
                back.length(length);
                assertEquals(expected.length, length,
                        "what came back is not the length that went in");
                for (int i = 0; i < length; i++) {
                    assertEquals(expected[i], back.secret().get(ValueLayout.JAVA_BYTE, i),
                            "byte " + i + " differs after the round trip");
                }
            }
        } finally {
            try (Connection connection = DriverManager.getConnection(url);
                 Statement statement = connection.createStatement()) {
                statement.execute("delete from zl_vault where id = 2");
            }
        }
    }

}
