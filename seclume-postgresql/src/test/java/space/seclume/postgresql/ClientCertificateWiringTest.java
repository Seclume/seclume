package space.seclume.postgresql;

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
 * The three steps between a connection string and a client certificate.
 *
 * <p>{@code MutualTlsTest} proves the certificate works and
 * {@code ClientIdentitiesTest} proves the settings build one. What is left is
 * the carrying: URL to settings, settings to the chosen host, settings to the
 * handshake. Three hand-offs with nothing clever in them, which is exactly the
 * shape of the defect this suite found earlier the same day - {@code
 * Settings.at(...)} silently dropped a component that had just been added, and
 * every assertion above it still held.
 *
 * <p>None of this needs a real key. A certificate that is never loaded still
 * proves the URL reaches the identity builder, and a stand-in identity proves
 * the rest - because what is under test is whether the object arrives, not
 * what it can sign.
 */
@Timeout(60)
class ClientCertificateWiringTest {

    /**
     * Enough of an identity to be carried, and nothing more.
     *
     * <p>Deliberately unable to sign: every test here ends before a
     * handshake, so one that reached {@code sign} would be testing something
     * it does not claim to.
     */
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

    /**
     * A URL naming a certificate without a key is refused, and the message
     * says which setting is missing.
     *
     * <p>This is the only assertion that shows the URL reaches
     * {@link ClientIdentities} at all - and it needs no certificate file,
     * because the complaint comes before anything is read.
     */
    @Test
    void theUrlReachesTheIdentityBuilder() {
        String url = "jdbc:seclume:postgresql://127.0.0.1:5432/seclume_test"
                + "?user=seclume_test&provider=file&path=/run/secrets/db"
                + "&" + ClientIdentities.CERTIFICATE + "=/etc/tls/client.crt";

        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url));
        assertTrue(refused.getMessage().contains(ClientIdentities.KEY_PREFIX + "provider"),
                "the message has to name the missing setting: " + refused.getMessage());
    }

    /** And a URL naming neither still connects to nothing in particular. */
    @Test
    void noCertificateIsNoComplaint() throws Exception {
        String url = "jdbc:seclume:postgresql://127.0.0.1:1/seclume_test"
                + "?user=seclume_test&provider=file&path=/run/secrets/db&connectTimeout=250";
        SQLException failed = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url));
        assertTrue(!failed.getMessage().contains(ClientIdentities.KEY_PREFIX),
                "a connection without a client certificate must not mention one: "
                        + failed.getMessage());
    }

    /**
     * The identity survives being pointed at another server.
     *
     * <p>{@code Settings.at(...)} rebuilds the record for the host that was
     * chosen out of the list, and a single-host list goes through it too - so
     * a component missed here is missed on every connection, not only on
     * failover.
     */
    @Test
    void theIdentitySurvivesTheHostChoice() throws Exception {
        ClientIdentity identity = new Carried();
        PgSession.Settings settings = new PgSession.Settings("a", 5432, "db", "u",
                SecretProviders.of(Map.of("provider", "file", "path", "/run/secrets/db")),
                "seclume", 1_000, HostList.of("a", 5432), ResultLimit.NONE,
                TlsMode.REQUIRE, TlsStack.SECLUME, identity);

        PgSession.Settings elsewhere = settings.at(new HostList.Host("b", 5433));

        assertSame(identity, elsewhere.identity(), "the client certificate was dropped");
        assertEquals(TlsStack.SECLUME, elsewhere.tlsStack());
        assertEquals("b", elsewhere.host());
    }

    /**
     * And it reaches the handshake - shown by the one place that reacts to
     * it without needing a key.
     *
     * <p>The JDK's TLS cannot present a client certificate without putting
     * the key on the heap, so that combination is refused. The refusal
     * happens inside {@code startTls}, after the server has agreed to TLS,
     * which makes it proof that the identity travelled the whole way: a
     * driver that lost it somewhere would connect happily.
     */
    @Test
    void theIdentityReachesTheHandshake() throws Exception {
        String host = System.getProperty("seclume.pgtls.host", TestHosts.database());
        int port = Integer.getInteger("seclume.pgtls.port", 5433);
        Path secret = null;
        for (Path candidate : List.of(Path.of(".local-pgtls-password"),
                Path.of("..", ".local-pgtls-password"))) {
            if (Files.exists(candidate)) {
                secret = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(secret != null, "no TLS server configured");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no TLS server on " + host + ":" + port);
        }

        PgSession.Settings settings = new PgSession.Settings(host, port, "seclume_test",
                "seclume_test",
                SecretProviders.of(Map.of("provider", "file", "path", secret.toString())),
                "seclume", 5_000, HostList.of(host, port), ResultLimit.NONE,
                TlsMode.REQUIRE, TlsStack.JSSE, new Carried());

        SQLException refused = assertThrows(SQLException.class,
                () -> PgSession.open(settings).close());
        assertTrue(refused.getMessage().contains("tlsStack=seclume"),
                "the identity did not reach the handshake: " + refused.getMessage());
    }
}
