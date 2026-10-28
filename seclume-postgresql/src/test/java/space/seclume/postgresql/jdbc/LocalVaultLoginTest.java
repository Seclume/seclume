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
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;
import space.seclume.tck.NoSecretInHeap;
import space.seclume.tck.TestHosts;

/**
 * Logging in to a real Vault - or OpenBao, the fixture runs either - with
 * AppRole and with a JWT, and using the token that gives for Vault's
 * database secrets engine (the {@code vault_fixtures.sh} fixture: Vault on
 * 8210, PostgreSQL on 5440; the login roles' tokens live 30 seconds, at most
 * 90). The driver logs in as Vault's user; past the token's half-life the
 * token is renewed and the same user stays; neither the JWT nor the secret
 * id is on the heap afterwards. Skipped without the fixture.
 */
@Timeout(180)
class LocalVaultLoginTest {

    private static String host;
    private static Path ca;
    private static Path jwt;
    private static Path roleId;
    private static Path secretId;

    @BeforeAll
    static void needsVault() {
        host = System.getProperty("seclume.vault.host", TestHosts.database());
        ca = find(".local-vault-pg-ca.pem");
        jwt = find(".local-vault-jwt");
        roleId = find(".local-vault-role-id");
        secretId = find(".local-vault-secret-id");
        assumeTrue(ca != null && jwt != null && roleId != null && secretId != null,
                "no Vault login fixture files");
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

    private static SeclumeDataSource source(SecretProvider vault) {
        SeclumeDataSource source = new SeclumeDataSource();
        source.setUrl("jdbc:seclume:postgresql://" + host + ":5440/postgres?user=not-this-one"
                + "&tls=verify-full&tlsRootCert=" + ca.toString().replace('\\', '/')
                + "&provider=none");
        source.setSecretProvider(vault);
        return source;
    }

    private static Map<String, String> vault(String... pairs) {
        // verify=false: the dev server's certificate comes from a CA it made
        // for itself inside its container. PostgreSQL's is checked.
        Map<String, String> settings = new LinkedHashMap<>(Map.of("provider", "vault",
                "address", "https://" + host + ":8210", "path", "database/creds/app",
                "verify", "false"));
        for (int i = 0; i < pairs.length; i += 2) {
            settings.put(pairs[i], pairs[i + 1]);
        }
        return settings;
    }

    @Test
    void anAppRoleLoginFetchesTheCredential() throws Exception {
        // The role id is an identifier, not a secret: a setting like any other.
        String role = Files.readString(roleId).strip();
        try (SecretProvider vault = SecretProviders.of(vault("auth-method", "approle",
                "auth-role-id", role,
                "secret-id-provider", "file", "secret-id-path", secretId.toString()))) {
            try (Connection connection = source(vault).getConnection()) {
                assertTrue(user(connection).startsWith("v-"), "not Vault's user");
            }
        }
        NoSecretInHeap.assertAbsent(secretId);
    }

    /**
     * The token lives 30 seconds. Past fifteen it is renewed - the lease of
     * the database user hangs from it - and the next connection is the same
     * user, not one fetched under a new login.
     */
    @Test
    void aJwtLoginsTokenIsRenewedAndTheUserStays() throws Exception {
        try (SecretProvider vault = SecretProviders.of(vault("auth-method", "jwt",
                "auth-role", "app", "jwt-provider", "file", "jwt-path", jwt.toString()))) {
            SeclumeDataSource source = source(vault);
            String first;
            try (Connection connection = source.getConnection()) {
                first = user(connection);
            }
            assertTrue(first.startsWith("v-"), "logged in as " + first);
            Instant until = source.credentialsValidUntil();
            assertTrue(until != null && until.isBefore(Instant.now().plusSeconds(31)),
                    "the 30 second token does not bound the credential: " + until);

            Thread.sleep(16_000);
            try (Connection connection = source.getConnection()) {
                assertEquals(first, user(connection), "renewed: the same user");
            }
            assertTrue(source.credentialsValidUntil().isAfter(until),
                    "nothing was renewed: " + until + " -> " + source.credentialsValidUntil());
        }
        NoSecretInHeap.assertAbsent(jwt);
    }
}
