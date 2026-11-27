package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.SecretProvider;

/**
 * Under tls=prefer the certificate is not checked, and without TLS there is
 * nothing to check: a server in the middle can ask for mysql_native_password
 * and gets SHA1(password) XOR SHA1(its scramble, SHA1(SHA1(password))) - a
 * fast hash per guess, for a scramble of its choosing. It is answered only to
 * a server that proved who it is, unless allowLegacyHashOverUnverifiedTls says
 * otherwise; the first answer offers caching_sha2_password instead, so an
 * account with a SHA-2 hash logs in as before.
 */
@Timeout(30)
// The refusal is the default; a job that opts its whole JVM out (MariaDB 11.4
// in CI) must not turn this test's refusal into a login. Isolated, because the
// opt-out is taken away for its duration.
@org.junit.jupiter.api.parallel.Isolated
class LegacyHashOverUnverifiedTlsTest {

    private static final String USER = "seclume_test";
    private static final String PASSWORD = "ein Testpasswort";

    private static SecretProvider secret() {
        byte[] bytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
        return new CallbackSecretProvider(256, target -> {
            for (int i = 0; i < bytes.length; i++) {
                target.set(ValueLayout.JAVA_BYTE, i, bytes[i]);
            }
            return bytes.length;
        });
    }

    private static MySession.Settings settings(FakeMySqlServer server) {
        return new MySession.Settings("127.0.0.1", server.port(), "testdb", USER, secret()).withTls(space.seclume.internal.jdbc.TlsMode.PREFER);
    }

    @Test
    void aSwitchToNativeOverAnUnverifiedLineIsRefusedAndNothingIsSent() throws Exception {
        String optedOut = System.clearProperty(MySession.Settings.LEGACY_HASH_PROPERTY);
        try {
            refusedAndNothingSent();
        } finally {
            if (optedOut != null) {
                System.setProperty(MySession.Settings.LEGACY_HASH_PROPERTY, optedOut);
            }
        }
    }

    private static void refusedAndNothingSent() throws Exception {
        try (FakeMySqlServer server = new FakeMySqlServer(USER, PASSWORD).switchBackToNative()
                .start()) {
            SQLException refused = assertThrows(SQLException.class,
                    () -> MySession.open(settings(server)).close());
            assertEquals("28000", refused.getSQLState(), refused.getMessage());
            assertTrue(refused.getMessage().contains("allowLegacyHashOverUnverifiedTls"),
                    refused.getMessage());
            assertEquals("caching_sha2_password", server.firstAnswerPlugin(),
                    "the first answer was computed with mysql_native_password");
            server.awaitDone();
            assertNull(server.answerToSwitchBack(), "a native answer went out");
        }
    }

    @Test
    void withTheOptOutTheNativeAnswerGoesOut() throws Exception {
        try (FakeMySqlServer server = new FakeMySqlServer(USER, PASSWORD).switchBackToNative()
                .start()) {
            assertThrows(SQLException.class,                 // the stand-in stops after the answer
                    () -> MySession.open(settings(server).allowingLegacyHash()).close());
            server.awaitDone();
            assertEquals("mysql_native_password", server.firstAnswerPlugin());
            assertNotNull(server.answerToSwitchBack(), "the opt-out sent nothing");
        }
    }
}
