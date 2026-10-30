package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.FieldKeys;
import space.seclume.secret.SecretProviders;
import space.seclume.secret.SecretScope;
import space.seclume.secret.SecretUnavailableException;
import space.seclume.tck.TestHosts;

/**
 * Field encryption's data key from a real Vault (and OpenBao): made by
 * {@code transit/datakey/wrapped}, configured as the ciphertext transit handed
 * out, opened by {@code provider=vault-transit} with a token that may decrypt
 * that key and nothing else. The fixture is {@code vault_fixtures.sh}.
 */
@Timeout(120)
class LocalVaultTransitFieldKeyTest {

    private static String host;
    private static String wrapped;
    private static Path token;

    @BeforeAll
    static void needsVault() throws IOException {
        host = System.getProperty("seclume.vault.host", TestHosts.database());
        Path key = find(".local-vault-field-key");
        token = find(".local-vault-field-token");
        assumeTrue(key != null && token != null, "no Vault fixture files");
        wrapped = Files.readString(key).trim();
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

    /** verify=false: the dev server's certificate comes from a CA it made itself. */
    private static Map<String, String> settings() {
        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("provider", "vault-transit");
        settings.put("address", "https://" + host + ":8210");
        settings.put("verify", "false");
        settings.put("key-name", "field-data");
        settings.put("ciphertext", wrapped);
        settings.put("token-provider", "file");
        settings.put("token-path", token.toString());
        return settings;
    }

    private static FieldKeys ring() {
        return FieldKeys.builder().key(1, SecretProviders.of(settings())).build();
    }

    @Test
    void theWrappedKeyOpensInVaultAndKeysTheColumns() {
        byte[] plain = "a value under a key only Vault can open".getBytes(StandardCharsets.UTF_8);
        byte[] stored;
        byte[] searchable;
        try (FieldKeys keys = ring()) {
            stored = keys.column("t.secret", EncryptedColumn.Mode.RANDOMIZED)
                    .encrypt(MemorySegment.ofArray(plain));
            searchable = keys.column("t.ssn", EncryptedColumn.Mode.DETERMINISTIC)
                    .encrypt(MemorySegment.ofArray(plain));
        }
        // The next start of the application: the same ciphertext, the same key from Vault.
        try (FieldKeys keys = ring();
             SecretScope out = SecretScope.allocate(64)) {
            EncryptedColumn secret = keys.column("t.secret", EncryptedColumn.Mode.RANDOMIZED);
            out.length(secret.decrypt(stored, out.segment()));
            assertArrayEquals(plain, out.secret().toArray(ValueLayout.JAVA_BYTE));
            assertArrayEquals(searchable, keys.column("t.ssn", EncryptedColumn.Mode.DETERMINISTIC)
                    .encrypt(MemorySegment.ofArray(plain)), "the same key twice");
        }
    }

    @Test
    void anAlteredCiphertextIsRefusedByVault() {
        Map<String, String> settings = settings();
        int at = wrapped.length() - 6;
        char swapped = wrapped.charAt(at) == 'A' ? 'B' : 'A';
        settings.put("ciphertext", wrapped.substring(0, at) + swapped + wrapped.substring(at + 1));
        SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                () -> FieldKeys.builder().key(1, SecretProviders.of(settings)).build());
        assertTrue(e.getMessage().contains("400"), e.getMessage());
    }

    @Test
    void theTokenOpensThisKeyAndNoOther() {
        Map<String, String> settings = settings();
        settings.put("key-name", "pg-client");
        SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                () -> FieldKeys.builder().key(1, SecretProviders.of(settings)).build());
        assertTrue(e.getMessage().contains("403"), e.getMessage());
        try (FieldKeys keys = ring()) {
            assertEquals(List.of(1), keys.keyIds(), "the right key name still opens");
        }
    }
}
