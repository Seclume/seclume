package space.seclume.quarkus.deployment;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.FieldKeys;
import space.seclume.secret.SecretScope;

/**
 * {@code seclume.field-encryption.*} in Quarkus: the ring from the
 * configuration - one key by its provider's settings, one by a {@code uri} -
 * its primary, injected and installed for the JPA converters.
 */
class FieldKeysTest {

    private static final Path ONE = keyFile(1);
    private static final Path TWO = keyFile(2);

    private static Path keyFile(int n) {
        try {
            byte[] key = new byte[32];
            for (int i = 0; i < key.length; i++) {
                key[i] = (byte) (n * 31 + i * 7);
            }
            Path file = Files.createTempFile("seclume-field-key-" + n, ".b64");
            file.toFile().deleteOnExit();
            return Files.writeString(file, Base64.getEncoder().encodeToString(key));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @RegisterExtension
    static final QuarkusExtensionTest APP = new QuarkusExtensionTest()
            .overrideConfigKey("quarkus.datasource.devservices.enabled", "false")
            .overrideConfigKey("seclume.field-encryption.keys.1.provider", "file")
            .overrideConfigKey("seclume.field-encryption.keys.1.path", ONE.toString())
            .overrideConfigKey("seclume.field-encryption.keys.2.uri", "file:" + TWO)
            .overrideConfigKey("seclume.field-encryption.primary", "1");

    @Inject
    FieldKeys keys;

    @Test
    void theRingIsTheConfiguredOneAndInstalled() {
        assertEquals(List.of(1, 2), keys.keyIds());
        assertEquals(1, keys.primary());
        assertSame(keys, FieldKeys.installed(), "the converters would not find it");
        EncryptedColumn column = keys.column("t.c", EncryptedColumn.Mode.RANDOMIZED);
        byte[] value = column.encrypt(MemorySegment.ofArray("quarkus".getBytes(
                StandardCharsets.UTF_8)));
        try (SecretScope out = SecretScope.allocate(16)) {
            out.length(column.decrypt(value, out.segment()));
            assertArrayEquals("quarkus".getBytes(StandardCharsets.UTF_8),
                    out.secret().toArray(ValueLayout.JAVA_BYTE));
        }
    }
}
