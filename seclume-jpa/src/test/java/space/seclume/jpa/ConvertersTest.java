package space.seclume.jpa;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import jakarta.persistence.Converter;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.FieldEncryptionException;
import space.seclume.field.FieldKeys;
import space.seclume.field.Sealed;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * The converters as a persistence provider calls them, without one: what
 * goes to the database, what comes back, NULL, the installed ring and the one
 * handed in, and that each converter's values are its column's only.
 * {@code JpaFieldEncryptionCase} in seclume-spring-test runs them in Hibernate
 * against the four databases.
 *
 * <p>Isolated: the installed ring is global.
 */
@Isolated
class ConvertersTest {

    private static final Random RANDOM = new Random(20261030L);

    static final class Ssn extends EncryptedStringConverter {
        Ssn() {
            super("patient.ssn", Mode.DETERMINISTIC);
        }
    }

    static final class Name extends EncryptedStringConverter {
        Name() {
            super("patient.name", Mode.RANDOMIZED);
        }
    }

    static final class Scan extends EncryptedBytesConverter {
        Scan() {
            super("patient.scan", Mode.RANDOMIZED);
        }
    }

    static final class Injected extends EncryptedStringConverter {
        Injected(FieldKeys keys) {
            super(keys, "patient.ssn", Mode.DETERMINISTIC);
        }
    }

    @AfterEach
    void uninstall() {
        FieldKeys.install(null);
    }

    static FieldKeys ring() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        return FieldKeys.builder().key(1, new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                MemorySegment.copy(key, 0, target, ValueLayout.JAVA_BYTE, 0, key.length);
                return key.length;
            }

            @Override
            public int maxSecretLength() {
                return 32;
            }
        }).build();
    }

    @Test
    void aStringGoesOutEncryptedAndComesBackItself() {
        try (FieldKeys keys = ring()) {
            FieldKeys.install(keys);
            Name name = new Name();
            String text = "Ana María Ñúñez - 東京";
            byte[] stored = name.convertToDatabaseColumn(text);
            assertEquals(text.getBytes(StandardCharsets.UTF_8).length + EncryptedColumn.OVERHEAD,
                    stored.length);
            assertFalse(new String(stored, StandardCharsets.ISO_8859_1).contains("Ana"));
            assertEquals(text, name.convertToEntityAttribute(stored));
            assertFalse(Arrays.equals(stored, name.convertToDatabaseColumn(text)),
                    "a randomized column repeated a ciphertext");
            assertEquals("", name.convertToEntityAttribute(name.convertToDatabaseColumn("")));
        }
    }

    @Test
    void aDeterministicStringIsTheSameParameterEveryTime() {
        try (FieldKeys keys = ring()) {
            FieldKeys.install(keys);
            Ssn ssn = new Ssn();
            assertArrayEquals(ssn.convertToDatabaseColumn("078-05-1120"),
                    new Ssn().convertToDatabaseColumn("078-05-1120"),
                    "two converters of one column disagree - a query would find nothing");
            assertNotEquals(HexFormat.of().formatHex(ssn.convertToDatabaseColumn("078-05-1120")),
                    HexFormat.of().formatHex(ssn.convertToDatabaseColumn("078-05-1121")));
        }
    }

    @Test
    void nullIsNullBothWays() {
        try (FieldKeys keys = ring()) {
            FieldKeys.install(keys);
            assertNull(new Name().convertToDatabaseColumn(null));
            assertNull(new Name().convertToEntityAttribute(null));
            assertNull(new Scan().convertToDatabaseColumn(null));
            assertNull(new Scan().convertToEntityAttribute(null));
            assertNull(new SealedConverter().convertToDatabaseColumn(null));
            assertNull(new SealedConverter().convertToEntityAttribute(null));
        }
    }

    @Test
    void bytesRoundTrip() {
        try (FieldKeys keys = ring()) {
            FieldKeys.install(keys);
            byte[] scan = new byte[4096];
            RANDOM.nextBytes(scan);
            Scan converter = new Scan();
            assertArrayEquals(scan, converter.convertToEntityAttribute(
                    converter.convertToDatabaseColumn(scan)));
            assertArrayEquals(new byte[0], converter.convertToEntityAttribute(
                    converter.convertToDatabaseColumn(new byte[0])));
        }
    }

    @Test
    void aValueOfAnotherColumnOrAlteredIsRefusedWithTheConverterNamed() {
        try (FieldKeys keys = ring()) {
            FieldKeys.install(keys);
            byte[] name = new Name().convertToDatabaseColumn("x");
            FieldEncryptionException other = assertThrows(FieldEncryptionException.class,
                    () -> new Scan().convertToEntityAttribute(name));
            assertTrue(other.getMessage().contains(Scan.class.getName()), other.getMessage());
            byte[] altered = name.clone();
            altered[altered.length - 1] ^= 1;
            assertThrows(FieldEncryptionException.class,
                    () -> new Name().convertToEntityAttribute(altered));
            assertThrows(FieldEncryptionException.class,
                    () -> new Ssn().convertToEntityAttribute(name), "the other mode");
        }
    }

    @Test
    void theRingIsLookedUpAtFirstUseNotWhenTheConverterIsMade() {
        Name made = new Name();             // as a provider makes it, before the keys exist
        IllegalStateException none = assertThrows(IllegalStateException.class,
                () -> made.convertToDatabaseColumn("x"));
        assertTrue(none.getMessage().contains("seclume.field-encryption.keys"), none.getMessage());
        try (FieldKeys keys = ring()) {
            FieldKeys.install(keys);
            assertEquals("x", made.convertToEntityAttribute(made.convertToDatabaseColumn("x")));
        }
    }

    @Test
    void aRingHandedInIsUsedInsteadOfTheInstalledOne() {
        try (FieldKeys installed = ring();
             FieldKeys injected = ring()) {
            FieldKeys.install(installed);
            byte[] viaInjected = new Injected(injected).convertToDatabaseColumn("1");
            byte[] viaInstalled = new Ssn().convertToDatabaseColumn("1");
            assertNotEquals(HexFormat.of().formatHex(viaInjected),
                    HexFormat.of().formatHex(viaInstalled));
            assertEquals("1", new Injected(injected).convertToEntityAttribute(viaInjected));
        }
    }

    @Test
    void closingTheInstalledRingUninstallsIt() {
        FieldKeys keys = ring();
        FieldKeys.install(keys);
        assertSame(keys, FieldKeys.installed());
        keys.close();
        assertThrows(IllegalStateException.class, FieldKeys::installed);
        assertThrows(IllegalStateException.class, () -> FieldKeys.install(keys),
                "a closed ring was installed");
    }

    @Test
    void sealedValuesAreStoredAsTheyAreAndNeedNoKey() {
        SealedConverter converter = new SealedConverter();
        assertTrue(SealedConverter.class.getAnnotation(Converter.class).autoApply());
        try (FieldKeys keys = ring();
             SecretScope token = SecretScope.allocate(64);
             SecretScope back = SecretScope.allocate(64)) {
            byte[] secret = "ghp_0123456789abcdefghijABCDEFGHIJ012345".getBytes(
                    StandardCharsets.US_ASCII);
            MemorySegment.copy(secret, 0, token.segment(), ValueLayout.JAVA_BYTE, 0,
                    secret.length);
            token.length(secret.length);
            EncryptedColumn column = keys.column("tenant.api_token", Mode.RANDOMIZED);
            Sealed sealed = column.seal(token.secret());
            byte[] stored = converter.convertToDatabaseColumn(sealed);
            Sealed loaded = converter.convertToEntityAttribute(stored);
            assertEquals(sealed, loaded);
            assertEquals(sealed.hashCode(), loaded.hashCode());
            back.length(column.open(loaded, back.segment()));
            assertArrayEquals(secret, back.secret().toArray(ValueLayout.JAVA_BYTE));
            assertFalse(loaded.toString().contains("ghp_"), loaded.toString());
            assertEquals(secret.length, loaded.plaintextLength());
            assertEquals(1, loaded.keyId());
            assertFalse(loaded.deterministic());
            stored[0] = 9;
            assertThrows(FieldEncryptionException.class,
                    () -> converter.convertToEntityAttribute(stored), "not the format");
            assertThrows(FieldEncryptionException.class,
                    () -> converter.convertToEntityAttribute(new byte[3]));
        }
    }

    @Test
    void aConverterNeedsItsColumnAndMode() {
        assertThrows(IllegalArgumentException.class, () -> new EncryptedStringConverter(" ",
                Mode.RANDOMIZED) { });
        assertThrows(IllegalArgumentException.class, () -> new EncryptedBytesConverter("t.c",
                null) { });
        assertEquals("Ssn[patient.ssn, deterministic]", new Ssn().toString());
    }
}
