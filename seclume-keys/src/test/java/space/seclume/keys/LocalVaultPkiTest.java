package space.seclume.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.crypto.PrivateSigningKey;
import space.seclume.tck.TestHosts;

/**
 * Against a real Vault or OpenBao ({@code .github/scripts/vault_fixtures.sh}):
 * its PKI engine signs the request for a key made in OpenSSL - as the root
 * token, and as an AppRole login whose policy may do nothing but that - and
 * signs again for the next key.
 */
@Timeout(120)
class LocalVaultPkiTest {

    private static String host;
    private static Path token;
    private static Path ca;
    private static Path roleId;
    private static Path secretId;

    @BeforeAll
    static void needsVault() {
        assumeTrue(PrivateSigningKey.available(), "no OpenSSL 3 here");
        host = System.getProperty("seclume.vault.host", TestHosts.database());
        token = find(".local-vault-token");
        ca = find(".local-vault-pki-ca.pem");
        roleId = find(".local-vault-role-id");
        secretId = find(".local-vault-secret-id");
        assumeTrue(token != null && ca != null && roleId != null && secretId != null,
                "no Vault PKI fixture files");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, 8210), 2000);
        } catch (IOException e) {
            assumeTrue(false, "nothing on " + host + ":8210");
        }
    }

    private static Path find(String name) {
        for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    /** verify=false: the dev server's own certificate comes from a CA it made at start. */
    private static String spec(String login) {
        return "address=https://" + host + ":8210&verify=false&pki-role=client"
                + "&common-name=orders.seclume.test&ttl=10m" + login;
    }

    private static void check(VaultPkiKeyManager manager) throws Exception {
        X509Certificate root = SeclumeKeys.certificates(ca)[0];
        X509Certificate[] chain = manager.getCertificateChain("seclume");
        assertTrue(chain[0].getSubjectX500Principal().getName()
                .contains("CN=orders.seclume.test"), chain[0].getSubjectX500Principal().getName());
        chain[0].verify(root.getPublicKey());              // signed by the PKI's root
        assertTrue(chain[0].getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.2"),
                "not a client certificate");
        Duration life = Duration.between(chain[0].getNotBefore().toInstant(),
                chain[0].getNotAfter().toInstant());
        assertTrue(life.compareTo(Duration.ofMinutes(11)) <= 0, "ttl=10m not honoured: " + life);
        assertTrue(manager.getPrivateKey("seclume") instanceof OpenSslPrivateKey);
    }

    @Test
    void theRootTokenGetsACertificateAndANextOne() throws Exception {
        try (VaultPkiKeyManager manager = (VaultPkiKeyManager) SeclumeKeys.vaultPkiKeyManager(
                spec("&token-provider=file&token-path=" + token))) {
            check(manager);
            X509Certificate first = manager.getCertificateChain("seclume")[0];
            manager.renewNow();
            X509Certificate second = manager.getCertificateChain("seclume")[0];
            check(manager);
            assertNotEquals(first.getSerialNumber(), second.getSerialNumber());
            assertNotEquals(first.getPublicKey(), second.getPublicKey());
            assertEquals(2, manager.generations());
        }
    }

    @Test
    void anAppRoleLoginWhosePolicyMaySignAndNoMore() throws Exception {
        try (VaultPkiKeyManager manager = (VaultPkiKeyManager) SeclumeKeys.vaultPkiKeyManager(
                spec("&auth-method=approle&auth-role-id=" + Files.readString(roleId).trim()
                        + "&secret-id-provider=file&secret-id-path=" + secretId))) {
            check(manager);
        }
    }
}
