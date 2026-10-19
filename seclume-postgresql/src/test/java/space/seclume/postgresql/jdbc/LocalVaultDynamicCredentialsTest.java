package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;
import space.seclume.tck.TestHosts;

/**
 * Vault's database secrets engine against a real Vault and PostgreSQL (the
 * {@code vault_fixtures.sh} fixture: Vault on 8210, PostgreSQL on 5440, the
 * role {@code app} with a 20 second lease). The driver logs in as the user
 * Vault created - not the URL's -, a second connection as the same one, the
 * lease is renewed halfway instead of a new user being made, and closing the
 * provider revokes the lease: Vault drops the user, and its revocation ends
 * the session still open. Skipped without the fixture.
 */
@Timeout(120)
class LocalVaultDynamicCredentialsTest {

    private static String host;
    private static Path token;
    private static Path ca;

    @BeforeAll
    static void needsVault() {
        host = System.getProperty("seclume.vault.host", TestHosts.database());
        token = find(".local-vault-token");
        ca = find(".local-vault-pg-ca.pem");
        assumeTrue(token != null && ca != null, "no Vault fixture files");
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

    private static String user(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet row = statement.executeQuery("select current_user")) {
            row.next();
            return row.getString(1);
        }
    }

    @Test
    void theDriverLogsInAsVaultsUserRenewsItAndTheEndRevokesIt() throws Exception {
        // verify=false: the dev server's certificate comes from a CA it made
        // for itself inside its container. PostgreSQL's is checked.
        SecretProvider vault = SecretProviders.of(Map.of("provider", "vault",
                "address", "https://" + host + ":8210", "path", "database/creds/app",
                "verify", "false", "token-provider", "file",
                "token-path", token.toString()));
        SeclumeDataSource source = new SeclumeDataSource();
        source.setUrl("jdbc:seclume:postgresql://" + host + ":5440/postgres?user=not-this-one"
                + "&tls=verify-full&tlsRootCert=" + ca.toString().replace('\\', '/')
                + "&provider=none");
        source.setSecretProvider(vault);

        Connection first = source.getConnection();
        String dynamic = user(first);
        assertTrue(dynamic.startsWith("v-"), "logged in as " + dynamic + ", not Vault's user");
        Instant firstLease = source.credentialsValidUntil();
        try (Connection second = source.getConnection()) {
            assertEquals(dynamic, user(second), "a second user for a second connection");
        }

        Thread.sleep(11_000);                          // past half of the 20 seconds
        try (Connection renewed = source.getConnection()) {
            assertEquals(dynamic, user(renewed), "renewed: the same user, not a new one");
        }
        assertTrue(source.credentialsValidUntil().isAfter(firstLease.plusSeconds(5)),
                "the lease did not move: " + firstLease + " -> "
                        + source.credentialsValidUntil());

        // Vault's token went into every request from native memory: it is in no
        // object of this JVM, however many requests it signed.
        space.seclume.tck.NoSecretInHeap.assertAbsent(token);

        vault.close();                                 // the lease is given back
        assertThrows(SQLException.class, () -> user(first),
                "the revoked user's session was not ended");
        first.close();
    }
}
