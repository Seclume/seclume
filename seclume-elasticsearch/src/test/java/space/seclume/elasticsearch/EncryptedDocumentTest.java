package space.seclume.elasticsearch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.FieldEncryptionException;
import space.seclume.field.FieldKeys;
import space.seclume.secret.SecretProvider;

/** Documents with encrypted fields: the rest untouched, deterministic fields found, a rotation searched. */
class EncryptedDocumentTest {

    private static SecretProvider key(int seed) {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                for (int i = 0; i < 32; i++) {
                    target.set(ValueLayout.JAVA_BYTE, i, (byte) (seed * 23 + i));
                }
                return 32;
            }

            @Override
            public int maxSecretLength() {
                return 32;
            }
        };
    }

    private static EncryptedDocument patients(FieldKeys keys) {
        return EncryptedDocument.of(keys, "patients").field("ssn", Mode.DETERMINISTIC)
                .field("diagnosis", Mode.RANDOMIZED);
    }

    @Test
    void chosenFieldsAreSealedTheRestIsNot() {
        try (FieldKeys keys = FieldKeys.builder().key(1, key(1)).build()) {
            Map<String, Object> document = new HashMap<>();
            document.put("name", "Alice");
            document.put("ssn", "123-45-6789");
            document.put("diagnosis", "zl-search-canary");
            document.put("visits", 3);
            Map<String, Object> stored = patients(keys).encrypt(document);
            assertEquals("Alice", stored.get("name"));
            assertEquals(3, stored.get("visits"));
            assertFalse(stored.toString().contains("zl-search-canary"));
            assertFalse(stored.toString().contains("123-45-6789"));
            assertEquals(document, patients(keys).decrypt(stored));
        }
    }

    @Test
    void aDeterministicFieldIsFoundByItsTermsThroughARotation() {
        Map<String, Object> old;
        try (FieldKeys one = FieldKeys.builder().key(1, key(1)).build()) {
            old = patients(one).encrypt(Map.of("ssn", "123-45-6789"));
            assertEquals(List.of(old.get("ssn")), patients(one).searchTerms("ssn", "123-45-6789"));
        }
        try (FieldKeys both = FieldKeys.builder().key(1, key(1)).key(2, key(2)).primary(2).build()) {
            List<String> terms = patients(both).searchTerms("ssn", "123-45-6789");
            assertEquals(2, terms.size());
            assertEquals(patients(both).encrypt(Map.of("ssn", "123-45-6789")).get("ssn"), terms.get(0));
            assertEquals(old.get("ssn"), terms.get(1), "the old document is found too");
            assertEquals("123-45-6789", patients(both).decrypt(old).get("ssn"));
        }
    }

    @Test
    void randomizedFieldsDifferAndAreNotSearchable() {
        try (FieldKeys keys = FieldKeys.builder().key(1, key(1)).build()) {
            Object one = patients(keys).encrypt(Map.of("diagnosis", "x")).get("diagnosis");
            Object two = patients(keys).encrypt(Map.of("diagnosis", "x")).get("diagnosis");
            assertNotEquals(one, two);
            assertThrows(IllegalArgumentException.class, () -> patients(keys).searchTerms("diagnosis", "x"));
            assertThrows(IllegalArgumentException.class, () -> patients(keys).searchTerms("name", "x"));
        }
    }

    @Test
    void aValueMovedToAnotherFieldOrIndexOpensNothing() {
        try (FieldKeys keys = FieldKeys.builder().key(1, key(1)).build()) {
            Object ssn = patients(keys).encrypt(Map.of("ssn", "1")).get("ssn");
            Map<String, Object> moved = new HashMap<>();
            moved.put("diagnosis", ssn);
            assertThrows(FieldEncryptionException.class, () -> patients(keys).decrypt(moved));
            EncryptedDocument otherIndex = EncryptedDocument.of(keys, "staff").field("ssn", Mode.DETERMINISTIC);
            assertThrows(FieldEncryptionException.class, () -> otherIndex.decrypt(Map.of("ssn", ssn)));
            assertThrows(FieldEncryptionException.class, () -> patients(keys).decrypt(Map.of("ssn", "not base64!")));
            assertThrows(FieldEncryptionException.class, () -> patients(keys).decrypt(Map.of("ssn", 42)));
        }
    }

    @Test
    void nullsMissingFieldsAndWrongTypes() {
        try (FieldKeys keys = FieldKeys.builder().key(1, key(1)).build()) {
            Map<String, Object> document = new HashMap<>();
            document.put("ssn", null);
            Map<String, Object> stored = patients(keys).encrypt(document);
            assertTrue(stored.containsKey("ssn"));
            assertNull(stored.get("ssn"));
            assertFalse(stored.containsKey("diagnosis"));
            assertThrows(IllegalArgumentException.class, () -> patients(keys).encrypt(Map.of("ssn", 12345)));
            assertThrows(IllegalArgumentException.class, () -> EncryptedDocument.of(keys, " "));
            assertThrows(IllegalArgumentException.class, () -> EncryptedDocument.of(keys, "i").field("", Mode.RANDOMIZED));
        }
    }
}
