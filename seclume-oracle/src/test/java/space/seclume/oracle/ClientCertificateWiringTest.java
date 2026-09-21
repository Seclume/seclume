package space.seclume.oracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.secret.SecretProviders;
import space.seclume.tls.ClientIdentities;
import space.seclume.tls.ClientIdentity;

/**
 * The same hand-offs as on the other two drivers.
 *
 * <p>Two of the three checks the PostgreSQL and MySQL suites make, because
 * the third needs a TCPS listener and these machines run none. The Oracle
 * driver is therefore wired for a client certificate and unproven against a
 * server - which is the same state its own TLS stack is in, and for the same
 * reason.
 */
@Timeout(60)
class ClientCertificateWiringTest {

    /** Enough of an identity to be carried, and deliberately unable to sign. */
    private static final class Carried implements ClientIdentity {
        @Override
        public List<byte[]> chain() {
            return List.of(new byte[] {0x30});
        }

        @Override
        public int signatureScheme() {
            return 0x0403;
        }

        @Override
        public byte[] sign(byte[] content) {
            throw new AssertionError("this identity is only meant to be carried, not used");
        }

        @Override
        public void close() {
        }
    }

    @Test
    void theUrlReachesTheIdentityBuilder() {
        String url = "jdbc:seclume:oracle://127.0.0.1:1521/FREEPDB1"
                + "?user=seclume_test&provider=file&path=/run/secrets/db"
                + "&" + ClientIdentities.CERTIFICATE + "=/etc/tls/client.crt";

        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url));
        assertTrue(refused.getMessage().contains(ClientIdentities.KEY_PREFIX + "provider"),
                "the message has to name the missing setting: " + refused.getMessage());
    }

    @Test
    void theIdentitySurvivesTheHostChoice() throws Exception {
        ClientIdentity identity = new Carried();
        OracleSession.Settings settings = new OracleSession.Settings("a", 2484, "FREEPDB1", "u",
                SecretProviders.of(Map.of("provider", "file", "path", "/run/secrets/db")),
                1_000, HostList.of("a", 2484), ResultLimit.NONE,
                TlsMode.REQUIRE, TlsStack.SECLUME, identity);

        OracleSession.Settings elsewhere = settings.at(new HostList.Host("b", 2485));

        assertSame(identity, elsewhere.identity(), "the client certificate was dropped");
        assertEquals(TlsStack.SECLUME, elsewhere.tlsStack());
        assertEquals("b", elsewhere.host());
    }
}
