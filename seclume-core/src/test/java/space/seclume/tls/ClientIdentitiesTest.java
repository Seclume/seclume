package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.crypto.P256Signer;

/**
 * A client identity out of configuration, and the lifetime that goes with it.
 *
 * <p>{@code MutualTlsTest} proves the identity itself against a server. This
 * proves the step in front of it: that two settings in a connection URL -
 * {@code clientCert} and a provider under {@code clientKey-} - produce one,
 * and that asking twice does not produce two.
 *
 * <p><b>Why the sharing is the part worth testing.</b> Every other object this
 * library builds from configuration is cheap to build twice. This one is not:
 * constructing it reads the key into native memory and hands it to CNG or
 * OpenSSL, which keeps it until the identity is closed - and an identity built
 * inside {@code getConnection} has nobody to close it. A pool of fifty
 * connections would then hold fifty copies of the same private key, none of
 * them reachable. So "the same settings give back the same object" is not an
 * optimisation here, it is the difference between one resident key and an
 * unbounded number.
 */
@Timeout(120)
class ClientIdentitiesTest {

    private static TestCertificates certificates;
    private static TestCertificates.Issued client;

    @BeforeAll
    static void issueACertificate() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        Assumptions.assumeTrue(P256Signer.available(),
                "off-heap P-256 signing needs Windows or 64-bit Linux with libcrypto.so.3");
        certificates = TestCertificates.generate();
        client = certificates.issueEc("cache-client", "ku:c=digitalSignature", "eku=clientAuth");
    }

    @AfterAll
    static void removeTheAuthority() throws Exception {
        if (certificates != null) {
            certificates.close();
        }
    }

    @AfterEach
    void releaseWhatWasCached() {
        // Each test gets a fresh cache: a leftover identity from an earlier
        // test would make the sharing test pass without proving anything.
        ClientIdentities.closeAll();
    }

    private Map<String, String> settings(Path dir) throws Exception {
        Path key = dir.resolve("client.key");
        Files.writeString(key, privateKeyPem());
        Path chain = dir.resolve("client.crt");
        Files.writeString(chain, certificatePem(client.certificate()));

        Map<String, String> options = new LinkedHashMap<>();
        // The password's own provider stands in the same map and has to be
        // left alone - that is the whole reason the key's settings are
        // prefixed rather than sharing the names.
        options.put("provider", "file");
        options.put("path", "/run/secrets/db-password");
        options.put(ClientIdentities.CERTIFICATE, chain.toString());
        options.put(ClientIdentities.KEY_PREFIX + "provider", "file");
        options.put(ClientIdentities.KEY_PREFIX + "path", key.toString());
        return options;
    }

    @Test
    void buildsAnIdentityFromTwoSettings(@TempDir Path dir) throws Exception {
        ClientIdentity identity = ClientIdentities.of(settings(dir));
        assertTrue(identity != null, "the settings describe an identity");
        assertEquals(1, identity.chain().size(), "the chain should be the leaf alone");
        assertEquals(HandshakeSignature.ECDSA_SECP256R1_SHA256, identity.signatureScheme());
    }

    /** The same configuration is the same identity - and therefore one key. */
    @Test
    void theSameSettingsGiveBackTheSameIdentity(@TempDir Path dir) throws Exception {
        Map<String, String> options = settings(dir);
        ClientIdentity first = ClientIdentities.of(options);
        ClientIdentity second = ClientIdentities.of(new LinkedHashMap<>(options));
        assertSame(first, second, "a second lookup loaded the private key a second time");
    }

    /** And written in another order it is still the same configuration. */
    @Test
    void theOrderOfTheSettingsDoesNotMatter(@TempDir Path dir) throws Exception {
        Map<String, String> options = settings(dir);
        ClientIdentity first = ClientIdentities.of(options);

        Map<String, String> reversed = new LinkedHashMap<>();
        options.entrySet().stream()
                .sorted((a, b) -> b.getKey().compareTo(a.getKey()))
                .forEach(entry -> reversed.put(entry.getKey(), entry.getValue()));

        assertSame(first, ClientIdentities.of(reversed));
    }

    /** No certificate named is no identity, not an error. */
    @Test
    void nothingConfiguredIsNoIdentity() {
        assertNull(ClientIdentities.of(Map.of("provider", "file", "path", "/run/secrets/db")));
    }

    /**
     * A certificate without a key is a mistake, and a loud one.
     *
     * <p>The quiet alternative would be to connect without a client
     * certificate - which is a connection that authenticates with nothing
     * while the configuration says it does, and it would only be noticed by
     * the server refusing, somewhere else, later.
     */
    @Test
    void aCertificateWithoutAKeyIsRefused() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> ClientIdentities.of(Map.of(ClientIdentities.CERTIFICATE, "/etc/x.crt")));
        assertTrue(refused.getMessage().contains(ClientIdentities.KEY_PREFIX + "provider"),
                "the message has to say what is missing: " + refused.getMessage());
    }

    // ---------------------------------------------------------------------

    private static String privateKeyPem() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(client.keystore())) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        String alias = client.certificate().getSubjectX500Principal().getName()
                .replace("CN=", "");
        PrivateKey key = (PrivateKey) store.getKey(alias, TestCertificates.PASSWORD.toCharArray());
        return "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(key.getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
    }

    private static String certificatePem(X509Certificate certificate) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'})
                        .encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }
}
