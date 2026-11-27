package space.seclume.field;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import space.seclume.field.EncryptedColumn.Context;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.secret.SecretProvider;

/**
 * A column whose values have to be bound to a row: encrypt and decrypt
 * without a context were allowed on every column, and a value written that
 * way opened in any other row of it. A column made with Context.REQUIRED
 * refuses that; its keys and format are the ones without the rule.
 */
class RequiredContextTest {

    private static SecretProvider key() {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                for (int i = 0; i < 32; i++) {
                    target.set(ValueLayout.JAVA_BYTE, i, (byte) (7 * i + 1));
                }
                return 32;
            }

            @Override
            public int maxSecretLength() {
                return 32;
            }
        };
    }

    private static MemorySegment text(String text) {
        return MemorySegment.ofArray(text.getBytes(StandardCharsets.UTF_8));
    }

    private static final byte[] ROW = "row:42".getBytes(StandardCharsets.UTF_8);

    @Test
    void withoutAContextNothingIsWrittenOrRead() {
        try (FieldKeys keys = FieldKeys.builder().key(1, key()).build()) {
            for (Mode mode : Mode.values()) {
                EncryptedColumn bound = keys.column("orders.note", mode, Context.REQUIRED);
                assertEquals(Context.REQUIRED, bound.context());
                assertThrows(IllegalArgumentException.class, () -> bound.encrypt(text("x")));
                assertThrows(IllegalArgumentException.class,
                        () -> bound.encrypt(text("x"), new byte[0]));
                assertThrows(IllegalArgumentException.class, () -> bound.seal(text("x"), null));
                byte[] value = bound.encrypt(text("x"), ROW);
                try (Arena arena = Arena.ofConfined()) {
                    MemorySegment target = arena.allocate(16);
                    assertThrows(IllegalArgumentException.class,
                            () -> bound.decrypt(value, target));
                    assertThrows(IllegalArgumentException.class,
                            () -> bound.reencrypt(value));
                    assertEquals(1, bound.decrypt(value, ROW, target));
                }
            }
        }
    }

    /** The rule is the column's use, not its keys: values move between the two freely. */
    @Test
    void theKeysAreTheOnesWithoutTheRule() {
        try (FieldKeys keys = FieldKeys.builder().key(1, key()).build()) {
            EncryptedColumn bound = keys.column("orders.note", Mode.RANDOMIZED, Context.REQUIRED);
            EncryptedColumn free = keys.column("orders.note", Mode.RANDOMIZED);
            assertEquals(Context.OPTIONAL, free.context());
            assertSame(free, keys.column("orders.note", Mode.RANDOMIZED, Context.OPTIONAL));
            assertSame(bound, keys.column("orders.note", Mode.RANDOMIZED, Context.REQUIRED));
            byte[] written = free.encrypt(text("abc"), ROW);
            try (Arena arena = Arena.ofConfined()) {
                assertEquals(3, bound.decrypt(written, ROW, arena.allocate(8)));
            }
        }
    }
}
