package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.crypto.PrivateSigningKey;
import space.seclume.tck.TestHosts;

/**
 * A database login with no password at all: PostgreSQL's {@code cert} method,
 * the client certificate from a real Vault's or OpenBao's PKI engine for a key
 * generated in OpenSSL ({@code clientCertVaultPki-}) - against the fixture of
 * {@code .github/scripts/vault_fixtures.sh}, whose PostgreSQL trusts the PKI's
 * root for client certificates and lets {@code orders.seclume.test} in by
 * certificate alone.
 */
@Timeout(120)
class LocalVaultPkiLoginTest {

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
                "no Vault PKI fixture files");
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

    @Test
    void theCertificateIsTheLogin() throws SQLException {
        // verify=false for Vault: the dev server's certificate comes from a CA it
        // made for itself. PostgreSQL's is checked.
        String url = "jdbc:seclume:postgresql://" + host + ":5440/postgres"
                + "?user=orders.seclume.test&tls=verify-full&tlsStack=seclume"
                + "&tlsRootCert=" + pgCa.toString().replace('\\', '/')
                + "&provider=none"
                + "&clientCertVaultPki-address=https://" + host + ":8210"
                + "&clientCertVaultPki-verify=false"
                + "&clientCertVaultPki-pki-role=client"
                + "&clientCertVaultPki-common-name=orders.seclume.test"
                + "&clientCertVaultPki-ttl=10m"
                + "&clientCertVaultPki-token-provider=file"
                + "&clientCertVaultPki-token-path=" + token.toString().replace('\\', '/');
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement();
             ResultSet row = statement.executeQuery("SELECT current_user, client_dn "
                     + "FROM pg_stat_ssl WHERE pid = pg_backend_pid()")) {
            assertTrue(row.next());
            assertEquals("orders.seclume.test", row.getString(1));
            assertTrue(row.getString(2).contains("CN=orders.seclume.test"), row.getString(2));
        }
    }
}
