package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.crypto.PrivateSigningKey;
import space.seclume.secret.KmsSigningKey;
import space.seclume.secret.VaultPkiIssuer;
import space.seclume.tck.TestHosts;

/**
 * A database login by a key that never leaves Vault: {@code pg-client} in a
 * real Vault's or OpenBao's transit engine signs its own certification
 * request, the PKI engine certifies it ({@link VaultPkiIssuer#certify}), and
 * the connection presents that certificate with every handshake signed in
 * transit ({@code clientKey-kms=vault-transit}) - against the fixture of
 * {@code .github/scripts/vault_fixtures.sh}, whose PostgreSQL lets
 * {@code orders.seclume.test} in by certificate alone.
 */
@Timeout(120)
class LocalVaultTransitLoginTest {

    private static String host;
    private static Path pgCa;
    private static Path token;

    @BeforeAll
    static void needsVaultAndPostgres() {
        assumeTrue(PrivateSigningKey.available(), "no OpenSSL 3 here");
        host = System.getProperty("seclume.vault.host", TestHosts.database());
        pgCa = find(".local-vault-pg-ca.pem");
        token = find(".local-vault-token");
        assumeTrue(pgCa != null && token != null && find(".local-vault-pki-ca.pem") != null,
                "no Vault fixture files");
        for (int port : new int[] {8210, 5440}) {
            try (Socket probe = new Socket()) {
                probe.connect(new InetSocketAddress(host, port), 2000);
            } catch (IOException e) {
                assumeTrue(false, "nothing on " + host + ":" + port);
            }
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

    /** verify=false for Vault: the dev server's certificate comes from a CA it made itself. */
    private static Map<String, String> vault() {
        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("address", "https://" + host + ":8210");
        settings.put("verify", "false");
        settings.put("token-provider", "file");
        settings.put("token-path", token.toString());
        return settings;
    }

    @Test
    void aKeyThatNeverLeavesVaultLogsIn() throws Exception {
        Map<String, String> transit = vault();
        transit.put("kms", "vault-transit");
        transit.put("key-name", "pg-client");
        Map<String, String> pki = vault();
        pki.put("pki-role", "client");
        pki.put("common-name", "orders.seclume.test");
        pki.put("ttl", "10m");

        Path chain = Files.createTempFile("seclume-transit-client", ".pem");
        try {
            try (KmsSigningKey key = KmsSigningKey.of(transit);
                 VaultPkiIssuer issuer = new VaultPkiIssuer(pki)) {
                StringBuilder pem = new StringBuilder();
                for (X509Certificate certificate : issuer.certify(key)) {
                    pem.append("-----BEGIN CERTIFICATE-----\n")
                            .append(Base64.getMimeEncoder(64, new byte[] {'\n'})
                                    .encodeToString(certificate.getEncoded()))
                            .append("\n-----END CERTIFICATE-----\n");
                }
                Files.writeString(chain, pem);
            }
            StringBuilder url = new StringBuilder("jdbc:seclume:postgresql://" + host
                    + ":5440/postgres?user=orders.seclume.test&tls=verify-full&tlsStack=seclume"
                    + "&tlsRootCert=" + pgCa.toString().replace('\\', '/')
                    + "&provider=none&clientCert=" + chain.toString().replace('\\', '/'));
            transit.forEach((name, value) -> url.append("&clientKey-").append(name).append('=')
                    .append(value.replace('\\', '/')));
            try (Connection connection = DriverManager.getConnection(url.toString());
                 Statement statement = connection.createStatement();
                 ResultSet row = statement.executeQuery("SELECT current_user, client_dn "
                         + "FROM pg_stat_ssl WHERE pid = pg_backend_pid()")) {
                assertTrue(row.next());
                assertEquals("orders.seclume.test", row.getString(1));
                assertTrue(row.getString(2).contains("CN=orders.seclume.test"),
                        row.getString(2));
            }
        } finally {
            Files.deleteIfExists(chain);
        }
    }
}
