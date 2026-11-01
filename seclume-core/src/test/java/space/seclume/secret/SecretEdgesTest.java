package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

/**
 * The secret package at its edges: names of exactly the characters a store
 * uses, secret URIs that start with what they should not, a scope of one byte
 * and a provider that fills it exactly, a closed scope asked its length, a
 * secret watch whose source cannot be read when it starts, and a watch that
 * wipes its three scopes on close. Written against the mutants PIT left alive
 * in this package.
 *
 * <p>Isolated: the count of open secret scopes is the JVM's.
 */
@Isolated
class SecretEdgesTest {

    @TempDir
    Path directory;

    // ------------------------------------------------------------ names

    @Test
    void aNameIsLettersDigitsDashAndUnderscoreAtEveryEdge() {
        String every = "azAZ09-_";
        assertSame(every, SecretNames.require("secret-id", every, false), "returned as given");
        for (char c : "az AZ 09-_".replace(" ", "").toCharArray()) {
            assertEquals(String.valueOf(c), SecretNames.require("name", String.valueOf(c), false));
        }
        for (char c : new char[] {'`', '{', '@', '[', '/', ':', '.', ' ', '+', 'ä'}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> SecretNames.require("secret-id", "ab" + c, false), "'" + c + "'");
            assertEquals("secret-id has a character a secret store does not use in a name: letters, digits, "
                    + "'-' and '_' only", e.getMessage());
        }
        assertNull(SecretNames.require("version", null, true));
        assertEquals("", SecretNames.require("version", "", true));
        assertEquals("secret-id is missing",
                assertThrows(IllegalArgumentException.class, () -> SecretNames.require("secret-id", "", false))
                        .getMessage());
        assertEquals("secret-id is missing",
                assertThrows(IllegalArgumentException.class, () -> SecretNames.require("secret-id", null, false))
                        .getMessage());
    }

    // ------------------------------------------------------------ URIs

    @Test
    void aSecretUriStartsWithItsProviderAndNothingElse() {
        for (String wrong : List.of("?path=/x", ":/run/secrets/db", " :/x", "?")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> SecretProviders.settingsOf(wrong), wrong);
            assertTrue(e.getMessage().startsWith("a secret URI starts with its provider"), e.getMessage());
        }
        assertEquals(Map.of("provider", "env"), SecretProviders.settingsOf("env"));
        assertEquals(Map.of("provider", "file", "path", "/x"), SecretProviders.settingsOf("file:/x"));
        assertEquals(Map.of("provider", "file"), SecretProviders.settingsOf("file:"), "no path, no path setting");
        assertEquals(Map.of("provider", "file", "path", "/x", "max-length", "9"),
                SecretProviders.settingsOf("file:/x?max-length=9"));
        assertEquals(Map.of("provider", "f", "a", "1"), SecretProviders.settingsOf("f?a=1"));
    }

    @Test
    void anEncryptedUriNamesItsCiphertextFileInAnyCase() {
        for (String provider : List.of("encrypted", "ENCRYPTED", "Encrypted")) {
            Map<String, String> settings = SecretProviders.settingsOf(provider + ":/etc/db.enc?key-provider=env");
            assertEquals("file", settings.get("cipher-provider"), provider);
            assertEquals("/etc/db.enc", settings.get("cipher-path"));
            assertFalse(settings.containsKey("path"));
        }
        assertEquals(Map.of("provider", "encryptedx", "path", "/p"), SecretProviders.settingsOf("encryptedx:/p"));
    }

    @Test
    void aSettingIsAKeyAnEqualsSignAndAValue() {
        Map<String, String> settings = SecretProviders.settingsOf("file:/x?=v&a==b&&c=");
        assertEquals("v", settings.get(""), "an empty key is a key");
        assertEquals("=b", settings.get("a"), "the first equals sign divides");
        assertEquals("", settings.get("c"));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> SecretProviders.settingsOf("file:/x?flag"));
        assertEquals("a secret URI setting without a value: 'flag'", e.getMessage());
    }

    @Test
    void anInlineSecretStopsAnyProviderBeforeItIsBuilt() {
        for (String forbidden : List.of("password", "secret", "value")) {
            Map<String, String> settings = new LinkedHashMap<>();
            settings.put("provider", "file");
            settings.put("path", "/run/secrets/db");
            settings.put(forbidden, "x");
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> SecretProviders.of(settings));
            assertTrue(e.getMessage().startsWith("'" + forbidden + "' is not a seclume setting."), e.getMessage());
            assertFalse(e.getMessage().contains("=x"), "never the value");
        }
    }

    @Test
    void aMaximumLengthIsAtLeastOne() throws Exception {
        Path file = Files.writeString(directory.resolve("one"), "k");
        try (SecretProvider one = SecretProviders.of(Map.of("provider", "file", "path", file.toString(),
                "max-length", "1"))) {
            assertEquals(1, one.maxSecretLength());
        }
        for (String wrong : List.of("0", "-1", "x")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> SecretProviders.of(Map.of("provider", "file", "path", file.toString(), "max-length", wrong)));
            assertEquals("max-length must be a positive number: " + wrong, e.getMessage());
        }
    }

    // ------------------------------------------------------------ scopes

    /** A provider that writes {@code reported} as its length, whatever it wrote. */
    private static SecretProvider reporting(int capacity, int reported) {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                target.fill((byte) 7);
                return reported;
            }

            @Override
            public int maxSecretLength() {
                return capacity;
            }
        };
    }

    @Test
    void aScopeIsAtLeastOneByte() {
        try (SecretScope one = SecretScope.allocate(1)) {
            assertEquals(1, one.segment().byteSize());
        }
        for (int wrong : new int[] {0, -1}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> SecretScope.allocate(wrong));
            assertEquals("capacity must be positive", e.getMessage());
        }
    }

    @Test
    void aProviderMayFillItsScopeExactlyAndNotOneByteMore() {
        long before = SecretScope.open();
        try (SecretScope full = SecretScope.fromProvider(reporting(8, 8))) {
            assertEquals(8, full.length());
        }
        try (SecretScope empty = SecretScope.fromProvider(reporting(8, 0))) {
            assertEquals(0, empty.length());
        }
        for (int wrong : new int[] {9, -1, Integer.MAX_VALUE}) {
            SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                    () -> SecretScope.fromProvider(reporting(8, wrong)));
            assertEquals("provider reported an implausible secret length: " + wrong, e.getMessage());
        }
        assertEquals(before, SecretScope.open(), "every refused read wiped its scope");
    }

    @Test
    void aClosedScopeIsNotAskedItsLengthNorToldOne() {
        SecretScope scope = SecretScope.allocate(4);
        scope.length(4);
        assertTrue(scope.toString().startsWith("SecretScope[capacity=4, locked="), scope.toString());
        assertEquals(scope.toString().contains("locked=true"), scope.isLocked());
        scope.close();
        for (Runnable call : List.<Runnable>of(scope::length, () -> scope.length(1), scope::segment, scope::secret)) {
            IllegalStateException e = assertThrows(IllegalStateException.class, call::run);
            assertEquals("secret scope is closed", e.getMessage());
        }
        assertTrue(scope.toString().startsWith("SecretScope[capacity=released, locked="), scope.toString());
    }

    // ------------------------------------------------------------ the watch

    @Test
    void aSourceUnreadableAtTheStartIsNoRotationWhenItCanBeRead() throws Exception {
        AtomicBoolean readable = new AtomicBoolean(false);
        SecretProvider source = new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                if (!readable.get()) {
                    throw new SecretUnavailableException("not mounted yet, in this test");
                }
                target.set(java.lang.foreign.ValueLayout.JAVA_BYTE, 0, (byte) 'a');
                return 1;
            }

            @Override
            public int maxSecretLength() {
                return 8;
            }
        };
        AtomicInteger rotations = new AtomicInteger();
        try (SecretWatch watch = SecretWatch.start("late", source, Duration.ofHours(1), rotations::incrementAndGet)) {
            assertFalse(watch.checkNow(), "still unreadable");
            readable.set(true);
            assertFalse(watch.checkNow(), "the first secret it can read is what it knows, not a change");
            assertFalse(watch.checkNow());
            assertEquals(0, watch.changes());
            assertEquals(0, rotations.get());
            assertEquals("late", watch.name());
        }
    }

    @Test
    void aWatchWipesItsScopesOnCloseAndSeesNothingAfter() throws Exception {
        Path file = Files.writeString(directory.resolve("watched"), "one");
        try (SecretProvider source = SecretProviders.of(Map.of("provider", "file", "path", file.toString()))) {
            long before = SecretScope.open();
            SecretWatch watch = SecretWatch.start("w", source, Duration.ofHours(1), () -> { });
            assertEquals(before + 3, SecretScope.open(), "its key, the fingerprint and a candidate");
            watch.close();
            assertEquals(before, SecretScope.open(), "all three wiped");
            assertDoesNotThrow(watch::close, "a second close");
            Files.writeString(file, "two");
            assertFalse(watch.checkNow(), "a closed watch sees nothing");
            assertEquals(0, watch.changes());
        }
    }
}
