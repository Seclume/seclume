package space.seclume.sqlserver.tds;

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
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.secret.SecretProviders;
import space.seclume.sqlserver.jdbc.TdsDataSource;
import space.seclume.tls.ClientIdentities;
import space.seclume.tls.ClientIdentity;

/**
 * The steps between a connection string and a client certificate, on the one
 * driver that did not have this test.
 *
 * <p>Written after finding out what its absence cost. The other three modules
 * have had it since the day it caught {@code Settings.at(...)} quietly
 * dropping a component; SQL Server did not, and by today its
 * {@code DataSource} could configure neither a client certificate, nor the TDS
 * version, nor which TLS stack carries the connection - <b>although the URL
 * could configure all three</b>. Both doors lead to the same
 * {@code TdsSession.Settings}, so one of them was silently producing a
 * different connection than the other, and nothing failed: every setting that
 * was carried was carried correctly.
 *
 * <p>That matters beyond tidiness. A {@code DataSource} is the door Spring
 * Boot uses, so mutual TLS on SQL Server was configurable exactly where
 * nobody configures anything, and unreachable where everybody does.
 *
 * <p>None of this needs a real key. A certificate that is never loaded still
 * proves the URL reaches the identity builder, and a stand-in identity proves
 * the rest - what is under test is whether the object arrives, not what it can
 * sign.
 */
@Timeout(60)
class ClientCertificateWiringTest {

    /** Enough of an identity to be carried, and nothing more. */
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
     * <p>The only assertion that shows the URL reaches {@link ClientIdentities}
     * at all - and it needs no certificate file, because the complaint comes
     * before anything is read.
     */
    @Test
    void theUrlReachesTheIdentityBuilder() {
        String url = "jdbc:seclume:sqlserver://127.0.0.1:1433/master"
                + "?user=sa&provider=file&path=/run/secrets/db"
                + "&" + ClientIdentities.CERTIFICATE + "=/etc/tls/client.crt";

        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url));
        assertTrue(refused.getMessage().contains(ClientIdentities.KEY_PREFIX + "provider"),
                "the message has to name the missing setting: " + refused.getMessage());
    }

    /** And a URL naming neither must not mention one either. */
    @Test
    void noCertificateIsNoComplaint() {
        String url = "jdbc:seclume:sqlserver://127.0.0.1:1/master"
                + "?user=sa&provider=file&path=/run/secrets/db&connectTimeout=250";
        SQLException failed = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url));
        assertTrue(!failed.getMessage().contains(ClientIdentities.KEY_PREFIX),
                "a connection without a client certificate must not mention one: "
                        + failed.getMessage());
    }

    /**
     * The identity survives being pointed at another server.
     *
     * <p>This test sits next to {@code TdsSession} rather than beside the
     * others because {@code Settings.at(...)} is package-private - and it
     * should stay that way: choosing a host out of the list is this session's
     * business and nobody else's.
     *
     * <p>{@code Settings.at(...)} rebuilds the record for the host chosen out
     * of the list, and a single-host list goes through it too - so a component
     * missed here is missed on every connection, not only on failover.
     */
    @Test
    void theIdentitySurvivesTheHostChoice() {
        ClientIdentity identity = new Carried();
        TdsSession.Settings settings = new TdsSession.Settings("a", 1433, "master", "sa",
                SecretProviders.of(Map.of("provider", "file", "path", "/run/secrets/db")),
                "seclume", 1_000, true, HostList.of("a", 1433), ResultLimit.NONE,
                TdsVersion.TDS_8_0, TlsStack.SECLUME, identity);

        TdsSession.Settings elsewhere = settings.at(new HostList.Host("b", 1434));

        assertSame(identity, elsewhere.identity(), "the client certificate was dropped");
        assertEquals(TlsStack.SECLUME, elsewhere.tlsStack(), "the TLS stack was dropped");
        assertEquals(TdsVersion.TDS_8_0, elsewhere.tdsVersion(), "the TDS version was dropped");
        assertEquals("b", elsewhere.host());
    }

    /**
     * The other door: a {@code DataSource} has to be able to say everything a
     * URL can.
     *
     * <p>This is the assertion that was missing. All three of these were
     * configurable in a URL and not in a {@code DataSource} - and a
     * {@code DataSource} is what a framework builds.
     */
    @Test
    void aDataSourceCanSayWhatAUrlCanSay() throws Exception {
        TdsDataSource source = new TdsDataSource();
        ClientIdentity identity = new Carried();
        source.setClientIdentity(identity);
        source.setTds("8.0");
        source.setTlsStack("seclume");

        assertEquals("8.0", source.getTds());
        assertEquals("seclume", source.getTlsStack());

        // And the properties reach the identity builder, shown the same way
        // the URL is shown to: a certificate without a key is refused, and the
        // complaint comes before anything is connected to. A data source that
        // never asked ClientIdentities would connect instead - to nothing, in
        // this case, and with a different message.
        TdsDataSource described = new TdsDataSource();
        described.setHost("127.0.0.1");
        described.setPort(1);
        described.setUser("sa");
        described.setProperty("provider", "file");
        described.setProperty("path", "/run/secrets/db");
        described.setProperty(ClientIdentities.CERTIFICATE, "/etc/tls/client.crt");

        RuntimeException refused = assertThrows(RuntimeException.class, described::getConnection);
        assertTrue(String.valueOf(refused.getMessage())
                        .contains(ClientIdentities.KEY_PREFIX + "provider"),
                "the data source has to name the missing setting, like the URL does: "
                        + refused.getMessage());
    }

    /**
     * And a URL handed to a {@code DataSource} keeps all three.
     *
     * <p>{@code setUrl} parses into the same settings record and then copies
     * the fields out one by one - which is exactly the shape that loses a
     * field when one is added. Three of them had been lost.
     */
    @Test
    void aUrlGivenToADataSourceKeepsTheTlsSettings() throws Exception {
        TdsDataSource source = new TdsDataSource();
        source.setUrl("jdbc:seclume:sqlserver://127.0.0.1:1433/master"
                + "?user=sa&provider=file&path=/run/secrets/db&tds=8.0&tlsStack=seclume");

        assertEquals("8.0", source.getTds(), "the TDS version did not survive setUrl");
        assertEquals("seclume", source.getTlsStack(), "the TLS stack did not survive setUrl");
    }
}
