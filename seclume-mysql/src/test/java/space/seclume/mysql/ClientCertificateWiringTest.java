package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.secret.SecretProviders;
import space.seclume.tck.TestHosts;
import space.seclume.tls.ClientIdentities;
import space.seclume.tls.ClientIdentity;

/**
 * The same three hand-offs as on PostgreSQL, because they are three separate
 * pieces of code.
 *
 * <p>Sharing a design does not share a defect or a fix: the omission that
 * dropped the TLS stack out of {@code Settings.at(...)} was present in all
 * three drivers and had to be corrected in all three. A test in one module
 * says nothing about the others.
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
        String url = "jdbc:seclume:mysql://127.0.0.1:3306/seclume_test"
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
        MySession.Settings settings = new MySession.Settings("a", 3306, "db", "u",
                SecretProviders.of(Map.of("provider", "file", "path", "/run/secrets/db")),
                "seclume", 1_000, false, HostList.of("a", 3306), ResultLimit.NONE,
                TlsMode.REQUIRE, TlsStack.SECLUME, identity);

        MySession.Settings elsewhere = settings.at(new HostList.Host("b", 3307));

        assertSame(identity, elsewhere.identity(), "the client certificate was dropped");
        assertEquals(TlsStack.SECLUME, elsewhere.tlsStack());
        assertEquals("b", elsewhere.host());
    }

    /**
     * The identity reaches the handshake, shown by the refusal that needs no
     * key: a client certificate cannot be presented through the JDK's TLS
     * without putting the key on the heap.
     */
    @Test
    void theIdentityReachesTheHandshake() throws Exception {
        String host = System.getProperty("seclume.mysql.host", TestHosts.database());
        int port = Integer.getInteger("seclume.mysql.port", 3307);
        Path secret = null;
        for (Path candidate : List.of(Path.of(".local-mysql-password"),
                Path.of("..", ".local-mysql-password"))) {
            if (Files.exists(candidate)) {
                secret = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(secret != null, "no .local-mysql-password");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no MySQL on " + host + ":" + port);
        }

        MySession.Settings settings = new MySession.Settings(host, port, "seclume_test",
                "seclume_test",
                SecretProviders.of(Map.of("provider", "file", "path", secret.toString())),
                "seclume", 5_000, false, HostList.of(host, port), ResultLimit.NONE,
                TlsMode.REQUIRE, TlsStack.JSSE, new Carried());

        SQLException refused = assertThrows(SQLException.class,
                () -> MySession.open(settings).close());
        assertTrue(refused.getMessage().contains("tlsStack=seclume"),
                "the identity did not reach the handshake: " + refused.getMessage());
    }
}
