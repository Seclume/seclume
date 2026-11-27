package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.sql.SQLException;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * A NUL in the user or the database would end that field of the
 * HandshakeResponse early - the bytes after it read as the next field, the
 * auth data among them. Refused before the login answer is sent: the server
 * gets the greeting's reply never.
 */
class NulInLoginFieldsTest {

    private static final String USER = "seclume_test";
    private static final String PASSWORD = "ein Testpasswort";

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"user", "database", "none"})
    void aNulIsRefusedBeforeTheLoginAnswer(String field) throws Exception {
        try (FakeMySqlServer server = new FakeMySqlServer(USER, PASSWORD)) {
            server.start();
            MySession.Settings settings = new MySession.Settings("127.0.0.1", server.port(),
                    field.equals("database") ? "appdb\0x" : "testdb",
                    field.equals("user") ? USER + "\0admin" : USER,
                    new space.seclume.secret.CallbackSecretProvider(256, target -> {
                        byte[] bytes = PASSWORD.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        for (int i = 0; i < bytes.length; i++) {
                            target.set(java.lang.foreign.ValueLayout.JAVA_BYTE, i, bytes[i]);
                        }
                        return bytes.length;
                    }))
                    .allowingLegacyHash();
            if (field.equals("none")) {
                // The control: a clean login is counted, or the zeros prove nothing.
                MySession.open(settings).close();
                assertEquals(1, server.loginAnswers());
                return;
            }
            assertThrows(SQLException.class, () -> MySession.open(settings).close());
            Thread.sleep(200);
            assertEquals(0, server.loginAnswers(), "a login answer with a NUL in the " + field
                    + " reached the server");
        }
    }
}
