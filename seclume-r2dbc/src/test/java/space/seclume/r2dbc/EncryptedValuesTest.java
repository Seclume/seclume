package space.seclume.r2dbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.r2dbc.spi.Readable;
import io.r2dbc.spi.Statement;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.FieldEncryptionException;
import space.seclume.field.FieldKeys;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * {@link EncryptedValues} against a statement and a row that only record and
 * hand back: what is bound is the column's ciphertext, NULL is NULL, what is
 * read is decrypted into native memory, a foreign value is refused. The live
 * round trip is {@code LocalEncryptedR2dbcTest}.
 */
class EncryptedValuesTest {

    private static FieldKeys ring() {
        return FieldKeys.builder().key(1, new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                target.asSlice(0, 32).fill((byte) 3);
                return 32;
            }

            @Override
            public int maxSecretLength() {
                return 32;
            }
        }).build();
    }

    /** A statement that records what was bound, and NULLs as their type. */
    private static Statement recording(Map<Object, Object> bound) {
        return (Statement) Proxy.newProxyInstance(Statement.class.getClassLoader(),
                new Class<?>[] {Statement.class}, (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "bind" -> bound.put(args[0], args[1]);
                        case "bindNull" -> bound.put(args[0], "NULL of " + args[1]);
                        default -> throw new UnsupportedOperationException(method.getName());
                    }
                    return proxy;
                });
    }

    /** A row that hands back {@code values} by index or name. */
    private static Readable row(Map<Object, Object> values) {
        return (Readable) Proxy.newProxyInstance(Readable.class.getClassLoader(),
                new Class<?>[] {Readable.class}, (proxy, method, args) -> {
                    if (method.getName().equals("get") && args.length == 2
                            && args[1] == ByteBuffer.class) {
                        return values.get(args[0]);
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    @Test
    void whatIsBoundIsCiphertextAndWhatIsReadIsThePlaintext() {
        byte[] plain = "an r2dbc secret".getBytes(StandardCharsets.UTF_8);
        try (FieldKeys keys = ring();
             SecretScope out = SecretScope.allocate(64)) {
            EncryptedColumn column = keys.column("t.c", Mode.RANDOMIZED);
            Map<Object, Object> bound = new HashMap<>();
            Statement statement = recording(bound);
            assertSame(statement, EncryptedValues.bind(statement, 1, column,
                    MemorySegment.ofArray(plain)));
            EncryptedValues.bind(statement, "named", column, MemorySegment.ofArray(plain));
            ByteBuffer stored = (ByteBuffer) bound.get(1);
            assertEquals(plain.length + EncryptedColumn.OVERHEAD, stored.remaining());

            Map<Object, Object> values = new HashMap<>();
            values.put(0, stored);
            values.put("named", bound.get("named"));
            Readable row = row(values);
            assertEquals(plain.length, EncryptedValues.length(row, 0, column));
            out.length(EncryptedValues.readInto(row, 0, column, out.segment()));
            assertArrayEquals(plain, out.secret().toArray(ValueLayout.JAVA_BYTE));
            assertEquals(plain.length, EncryptedValues.readInto(row, "named", column,
                    out.segment()));
            assertEquals(0, stored.position(), "reading moved the buffer the row holds");
        }
    }

    @Test
    void nullIsNullBothWays() {
        try (FieldKeys keys = ring();
             SecretScope out = SecretScope.allocate(8)) {
            EncryptedColumn column = keys.column("t.c", Mode.RANDOMIZED);
            Map<Object, Object> bound = new HashMap<>();
            EncryptedValues.bind(recording(bound), 0, column, null);
            EncryptedValues.bind(recording(bound), "n", column, null);
            assertEquals("NULL of class java.nio.ByteBuffer", bound.get(0));
            assertEquals("NULL of class java.nio.ByteBuffer", bound.get("n"));
            Readable empty = row(new HashMap<>());
            assertEquals(-1, EncryptedValues.readInto(empty, 0, column, out.segment()));
            assertEquals(-1, EncryptedValues.length(empty, 0, column));
        }
    }

    @Test
    void anotherColumnsValueIsRefused() {
        try (FieldKeys keys = ring();
             SecretScope out = SecretScope.allocate(64)) {
            byte[] other = keys.column("t.other", Mode.RANDOMIZED).encrypt(
                    MemorySegment.ofArray(new byte[] {1, 2, 3}));
            Map<Object, Object> values = new HashMap<>();
            values.put(0, ByteBuffer.wrap(other));
            assertThrows(FieldEncryptionException.class, () -> EncryptedValues.readInto(
                    row(values), 0, keys.column("t.c", Mode.RANDOMIZED), out.segment()));
        }
    }
}
