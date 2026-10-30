package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;

import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.FieldKeys;
import space.seclume.secret.SecretScope;

/**
 * {@code seclume.field-encryption.*}: the ring made from the properties, its
 * keys under their numbers, the primary, the one-line {@code uri} form, the
 * ring installed while the context lives and wiped when it closes - and every
 * way the properties can be wrong refused at start.
 *
 * <p>Isolated: the installed ring is global.
 */
@Isolated
class FieldEncryptionAutoConfigurationTest {

    private static final Random RANDOM = new Random(20261030L);

    @TempDir
    Path directory;

    @AfterEach
    void uninstall() {
        FieldKeys.install(null);
    }

    private Path key(String name) throws Exception {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        return Files.writeString(directory.resolve(name), Base64.getEncoder().encodeToString(key)
                + "\n");
    }

    private static AnnotationConfigApplicationContext context(Map<String, Object> properties) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources()
                .addFirst(new MapPropertySource("test", properties));
        context.register(SeclumeFieldEncryptionAutoConfiguration.class);
        context.refresh();
        return context;
    }

    private static Throwable root(Throwable failure) {
        Throwable root = failure;
        while (root.getCause() != null) {
            root = root.getCause();
        }
        return root;
    }

    @Test
    void noKeysNoRing() {
        try (AnnotationConfigApplicationContext context = context(new HashMap<>())) {
            assertTrue(context.getBeansOfType(FieldKeys.class).isEmpty());
            assertThrows(IllegalStateException.class, FieldKeys::installed);
        }
    }

    @Test
    void aRingFromThePropertiesInstalledWhileTheContextLives() throws Exception {
        Map<String, Object> properties = new HashMap<>();
        properties.put("seclume.field-encryption.keys.1.provider", "file");
        properties.put("seclume.field-encryption.keys.1.path", key("one").toString());
        properties.put("seclume.field-encryption.keys.7.uri", "file:" + key("seven"));
        long open = SecretScope.open();
        byte[] sealed;
        try (AnnotationConfigApplicationContext context = context(properties)) {
            FieldKeys keys = context.getBean(FieldKeys.class);
            assertSame(keys, FieldKeys.installed());
            assertEquals(List.of(1, 7), keys.keyIds());
            assertEquals(7, keys.primary(), "the highest number, when none is named");
            sealed = keys.column("t.c", Mode.RANDOMIZED).encrypt(
                    MemorySegment.ofArray("x".getBytes(StandardCharsets.UTF_8)));
            assertEquals(7, keys.column("t.c", Mode.RANDOMIZED).keyId(sealed));
        }
        assertThrows(IllegalStateException.class, FieldKeys::installed,
                "the ring outlived its context");
        assertEquals(open, SecretScope.open(), "a key stayed in memory after the context closed");

        // The next start reads the same keys and the same value.
        try (AnnotationConfigApplicationContext again = context(properties);
             SecretScope out = SecretScope.allocate(8)) {
            assertEquals(1, again.getBean(FieldKeys.class).column("t.c", Mode.RANDOMIZED)
                    .decrypt(sealed, out.segment()));
        }
    }

    @Test
    void thePrimaryCanBeNamed() throws Exception {
        Map<String, Object> properties = new HashMap<>();
        properties.put("seclume.field-encryption.keys.1.provider", "file");
        properties.put("seclume.field-encryption.keys.1.path", key("a").toString());
        properties.put("seclume.field-encryption.keys.2.provider", "file");
        properties.put("seclume.field-encryption.keys.2.path", key("b").toString());
        properties.put("seclume.field-encryption.primary", "1");
        try (AnnotationConfigApplicationContext context = context(properties)) {
            assertEquals(1, context.getBean(FieldKeys.class).primary());
        }
    }

    @Test
    void twoNumbersAreTwoKeys() throws Exception {
        Path same = key("same");
        Map<String, Object> properties = new HashMap<>();
        properties.put("seclume.field-encryption.keys.1.uri", "file:" + same);
        properties.put("seclume.field-encryption.keys.2.uri", "file:" + key("other"));
        properties.put("seclume.field-encryption.primary", "1");
        byte[] underOne;
        try (AnnotationConfigApplicationContext context = context(properties)) {
            underOne = context.getBean(FieldKeys.class).column("t.c", Mode.DETERMINISTIC)
                    .encrypt(MemorySegment.ofArray(new byte[] {1}));
        }
        properties.put("seclume.field-encryption.primary", "2");
        try (AnnotationConfigApplicationContext context = context(properties)) {
            byte[] underTwo = context.getBean(FieldKeys.class).column("t.c", Mode.DETERMINISTIC)
                    .encrypt(MemorySegment.ofArray(new byte[] {1}));
            assertNotEquals(HexFormat.of().formatHex(underOne), HexFormat.of().formatHex(underTwo));
            assertArrayEquals(underOne, context.getBean(FieldKeys.class)
                    .column("t.c", Mode.DETERMINISTIC).searchTerms(
                            MemorySegment.ofArray(new byte[] {1})).get(1));
        }
    }

    @Test
    void whatIsWrongIsRefusedAtStart() throws Exception {
        Path good = key("good");
        Map<String, Map<String, Object>> wrong = new java.util.LinkedHashMap<>();
        wrong.put("a key without a number", Map.of(
                "seclume.field-encryption.keys.main.provider", "file",
                "seclume.field-encryption.keys.main.path", good.toString()));
        wrong.put("a key numbered zero", Map.of(
                "seclume.field-encryption.keys.0.provider", "file",
                "seclume.field-encryption.keys.0.path", good.toString()));
        wrong.put("a primary that is not a key", Map.of(
                "seclume.field-encryption.keys.1.provider", "file",
                "seclume.field-encryption.keys.1.path", good.toString(),
                "seclume.field-encryption.primary", "3"));
        wrong.put("a key that is not 32 bytes", Map.of(
                "seclume.field-encryption.keys.1.provider", "file",
                "seclume.field-encryption.keys.1.path",
                Files.writeString(directory.resolve("short"), "c2hvcnQ=").toString()));
        wrong.put("a key file that is not there", Map.of(
                "seclume.field-encryption.keys.1.provider", "file",
                "seclume.field-encryption.keys.1.path", directory.resolve("absent").toString()));
        wrong.put("a password in the configuration", Map.of(
                "seclume.field-encryption.keys.1.provider", "file",
                "seclume.field-encryption.keys.1.password", "hunter2"));
        long open = SecretScope.open();
        for (Map.Entry<String, Map<String, Object>> entry : wrong.entrySet()) {
            Exception refused = assertThrows(Exception.class,
                    () -> context(new HashMap<>(entry.getValue())).close(), entry.getKey());
            assertTrue(root(refused).getMessage() != null, entry.getKey());
            assertThrows(IllegalStateException.class, FieldKeys::installed, entry.getKey());
        }
        assertEquals(open, SecretScope.open(), "a refused ring left a key in memory");
    }

    @Test
    void aRingOfTheApplicationsOwnIsLeftAlone() throws Exception {
        Map<String, Object> properties = new HashMap<>();
        properties.put("seclume.field-encryption.keys.1.uri", "file:" + key("k"));
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.getEnvironment().getPropertySources()
                    .addFirst(new MapPropertySource("test", properties));
            FieldKeys own = FieldKeys.builder().key(5, new space.seclume.secret.FileSecretProvider(
                    key("own"), 128)).build();
            context.registerBean("ownKeys", FieldKeys.class, () -> own);
            context.register(SeclumeFieldEncryptionAutoConfiguration.class);
            context.refresh();
            assertSame(own, context.getBean(FieldKeys.class));
            own.close();
        }
    }
}
