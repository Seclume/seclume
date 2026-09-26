package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
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
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.Sensitive;
import space.seclume.secret.SecretScope;

/**
 * A secret column read without becoming a String, on MySQL.
 *
 * <p>The mechanism is shared - the bounds check and the copy live in
 * {@code ReadOnlyResultSet} - and what each driver supplies is the window:
 * which buffer, at what offset, for how many bytes. <b>That is the part that
 * can be wrong per driver</b>, and it is wrong silently: an offset off by a
 * type prefix returns bytes that look like a key and are not one. So the bytes
 * are compared, not the length.
 *
 * <p>The heap-dump proof of this API lives with the PostgreSQL driver, because
 * what it proves is about the shared path and running it four times would cost
 * four child JVMs to learn the same thing.
 */
@Timeout(180)
class LocalSensitiveColumnTest {

    private static final String HOST =
            System.getProperty("seclume.mysql.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mysql.port", 3307);
    private static final String USER = "seclume_test";
    private static final String STORED_KEY = "zl-stored-secret-6f4c2b8a19d7e530-zl";

    private static String url;

    @BeforeAll
    static void findTheServer() throws Exception {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mysql-password"), Path.of("..", ".local-mysql-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mysql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no MySQL on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:mysql://" + HOST + ":" + PORT + "/seclume_test"
                + "?user=" + USER + "&allowPublicKeyRetrieval=true&provider=file&path="
                + password.toString().replace('\\', '/');

        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            drop(statement);
            statement.execute("create table zl_vault (id int primary key, signing_key varchar(100))");
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into zl_vault values (1, ?)")) {
                insert.setString(1, STORED_KEY);
                insert.executeUpdate();
            }
        }
    }

    private static void drop(Statement statement) {
        try {
            statement.execute("drop table zl_vault");
        } catch (Exception itWasNotThere) {
            // Which is what was wanted.
        }
    }

    @AfterAll
    static void tidyUp() throws Exception {
        if (url == null) {
            return;
        }
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            drop(statement);
        }
    }

    @Test
    void theWindowIsTheValue() throws Exception {
        byte[] expected = STORED_KEY.getBytes(StandardCharsets.UTF_8);
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select signing_key from zl_vault where id = 1")) {
            assertTrue(rows.next());
            Sensitive sensitive = Sensitive.of(rows);
            assertEquals(expected.length, sensitive.length(1),
                    "the length is not the value's - the window is in the wrong place");
            try (SecretScope key = SecretScope.allocate(256)) {
                int written = sensitive.readInto(1, key.segment());
                key.length(written);
                assertEquals(expected.length, written);
                for (int i = 0; i < written; i++) {
                    assertEquals(expected[i], key.secret().get(ValueLayout.JAVA_BYTE, i),
                            "byte " + i + " differs - the offset is off by " + i);
                }
            }
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
