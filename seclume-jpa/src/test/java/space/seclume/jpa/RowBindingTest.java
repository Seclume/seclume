package space.seclume.jpa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import org.junit.jupiter.api.Test;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.FieldEncryptionException;
import space.seclume.field.FieldKeys;
import space.seclume.field.Sealed;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * What ENCRYPTION.md says of the converters: a converted value is not bound
 * to its row - one copied into another row of the same column is read there
 * as that row's own - and a Sealed value sealed with the row's id is, and is
 * refused in another row. Should a converter ever learn its row, the first
 * test fails, and the documentation is to change with it.
 */
class RowBindingTest {

    static final class Iban extends EncryptedStringConverter {
        Iban(FieldKeys keys) {
            super(keys, "customer.iban", Mode.RANDOMIZED);
        }
    }

    private static FieldKeys ring() {
        byte[] key = new byte[32];
        new Random(85).nextBytes(key);
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
    void aConvertedValueCopiedIntoAnotherRowIsReadThere() {
        try (FieldKeys keys = ring()) {
            Iban converter = new Iban(keys);
            // Entered by the customer of row 7 through the application ...
            byte[] row7 = converter.convertToDatabaseColumn("AT00 DECOY 0000 0007");
            // ... copied by someone who can write to the table into row 42.
            byte[] row42 = row7.clone();
            assertEquals("AT00 DECOY 0000 0007", converter.convertToEntityAttribute(row42));
        }
    }

    @Test
    void aValueSealedWithItsRowsIdIsRefusedInAnother() {
        try (FieldKeys keys = ring()) {
            EncryptedColumn iban = keys.column("customer.iban", Mode.RANDOMIZED);
            byte[] plain = "AT00 DECOY 0000 0007".getBytes(StandardCharsets.UTF_8);
            Sealed row7 = iban.seal(MemorySegment.ofArray(plain), id("7"));
            Sealed row42 = Sealed.of(row7.ciphertext().clone());
            try (SecretScope target = SecretScope.allocate(64)) {
                assertEquals(plain.length, iban.open(row7, id("7"), target.segment()));
                assertThrows(FieldEncryptionException.class,
                        () -> iban.open(row42, id("42"), target.segment()));
            }
        }
    }

    private static byte[] id(String id) {
        return id.getBytes(StandardCharsets.UTF_8);
    }
}
