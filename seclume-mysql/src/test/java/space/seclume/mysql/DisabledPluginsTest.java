package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.sql.SQLInvalidAuthorizationSpecException;
import java.util.Set;

import org.junit.jupiter.api.Test;

import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.SecretProvider;

/**
 * {@code disabledAuthenticationPlugins}: a disabled plugin computes nothing.
 * The server proposes {@code mysql_native_password}; the first answer goes
 * out under another plugin, and the server's switch back is refused before a
 * native hash exists.
 */
class DisabledPluginsTest {

    private static final String USER = "app";

    @Test
    void aDisabledNativePasswordIsNeverComputed() throws Exception {
        try (FakeMySqlServer server = new FakeMySqlServer(USER, "hunter2-hunter2")) {
            server.switchBackToNative().start();
            SQLInvalidAuthorizationSpecException refused = assertThrows(
                    SQLInvalidAuthorizationSpecException.class, () -> MySession.open(
                            settings(server, Set.of("mysql_native_password"))).close());
            assertEquals("28000", refused.getSQLState());
            assertTrue(refused.getMessage().contains("mysql_native_password"),
                    refused.getMessage());
            server.awaitDone();
            assertEquals("caching_sha2_password", server.firstAnswerPlugin(),
                    "the first answer was computed with the disabled plugin");
            assertNull(server.answerToSwitchBack(), "something was sent after the switch back");
        }
    }

    @Test
    void withNothingDisabledTheProposedPluginIsUsed() throws Exception {
        MySession.Settings plain = settings(null, Set.of());
        assertEquals("mysql_native_password", MySession.firstPlugin(plain,
                "mysql_native_password"));
        MySession.Settings both = settings(null,
                Set.of("mysql_native_password", "caching_sha2_password"));
        assertThrows(SQLInvalidAuthorizationSpecException.class,
                () -> MySession.firstPlugin(both, "mysql_native_password"));
        assertEquals("client_ed25519", MySession.firstPlugin(both, "client_ed25519"));
    }

    private static MySession.Settings settings(FakeMySqlServer server, Set<String> disabled) {
        int port = server == null ? 3306 : server.port();
        return new MySession.Settings("127.0.0.1", port, "testdb", USER, secret(), "seclume",
                10_000, false, HostList.of("127.0.0.1", port), ResultLimit.NONE, TlsMode.OFF,
                space.seclume.internal.jdbc.TlsStack.AUTO, null, true, disabled);
    }

    private static SecretProvider secret() {
        byte[] bytes = "hunter2-hunter2".getBytes(StandardCharsets.UTF_8); // seclume-allow: a test password
        return new CallbackSecretProvider(64, target -> {
            for (int i = 0; i < bytes.length; i++) {
                target.set(ValueLayout.JAVA_BYTE, i, bytes[i]);
            }
            return bytes.length;
        });
    }
}
