package space.seclume.redis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import io.lettuce.core.codec.StringCodec;

import space.seclume.field.FieldEncryptionException;
import space.seclume.field.FieldKeys;
import space.seclume.secret.SecretProvider;

/** The codec on its own: values sealed, keys as chosen, names kept apart. */
class EncryptedCodecTest {

    private static SecretProvider key(int seed) {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                for (int i = 0; i < 32; i++) {
                    target.set(ValueLayout.JAVA_BYTE, i, (byte) (seed * 17 + i));
                }
                return 32;
            }

            @Override
            public int maxSecretLength() {
                return 32;
            }
        };
    }

    private static String text(ByteBuffer buffer) {
        byte[] bytes = new byte[buffer.remaining()];
        buffer.duplicate().get(bytes);
        return new String(bytes, StandardCharsets.ISO_8859_1);
    }

    @Test
    void valuesAreSealedKeysStayReadable() {
        try (FieldKeys keys = FieldKeys.builder().key(1, key(1)).build()) {
            EncryptedCodec<String, String> codec = EncryptedCodec.of(StringCodec.UTF8, keys, "sessions");
            ByteBuffer value = codec.encodeValue("user=alice; token=zl-redis-canary");
            assertFalse(text(value).contains("zl-redis-canary"));
            assertEquals("user=alice; token=zl-redis-canary", codec.decodeValue(value));
            assertEquals("session:42", text(codec.encodeKey("session:42")));
            assertEquals("session:42", codec.decodeKey(codec.encodeKey("session:42")));
            assertNotEquals(text(value), text(codec.encodeValue("user=alice; token=zl-redis-canary")));
        }
    }

    @Test
    void encryptedKeysAreDeterministic() {
        try (FieldKeys keys = FieldKeys.builder().key(1, key(1)).build()) {
            EncryptedCodec<String, String> codec = EncryptedCodec.withEncryptedKeys(StringCodec.UTF8, keys, "carts");
            ByteBuffer one = codec.encodeKey("customer:alice@example.org");
            assertFalse(text(one).contains("alice"));
            assertEquals(text(one), text(codec.encodeKey("customer:alice@example.org")), "GET finds it again");
            assertEquals("customer:alice@example.org", codec.decodeKey(one));
        }
    }

    @Test
    void anotherNameOrRingOpensNothing() {
        try (FieldKeys keys = FieldKeys.builder().key(1, key(1)).build();
             FieldKeys other = FieldKeys.builder().key(1, key(2)).build()) {
            ByteBuffer value = EncryptedCodec.of(StringCodec.UTF8, keys, "sessions").encodeValue("v");
            assertThrows(FieldEncryptionException.class,
                    () -> EncryptedCodec.of(StringCodec.UTF8, keys, "carts").decodeValue(value.duplicate()));
            assertThrows(FieldEncryptionException.class,
                    () -> EncryptedCodec.of(StringCodec.UTF8, other, "sessions").decodeValue(value.duplicate()));
            assertThrows(FieldEncryptionException.class, () -> EncryptedCodec.of(StringCodec.UTF8, keys, "sessions")
                    .decodeValue(ByteBuffer.wrap("plain".getBytes(StandardCharsets.UTF_8))));
            assertThrows(IllegalArgumentException.class, () -> EncryptedCodec.of(null, keys, "x"));
            assertThrows(IllegalArgumentException.class, () -> EncryptedCodec.of(StringCodec.UTF8, keys, " "));
        }
    }

    @Test
    void aRotationIsReadThrough() {
        ByteBuffer old;
        try (FieldKeys one = FieldKeys.builder().key(1, key(1)).build()) {
            old = EncryptedCodec.of(StringCodec.UTF8, one, "s").encodeValue("under key 1");
        }
        try (FieldKeys both = FieldKeys.builder().key(1, key(1)).key(2, key(2)).primary(2).build()) {
            assertEquals("under key 1", EncryptedCodec.of(StringCodec.UTF8, both, "s").decodeValue(old));
        }
    }
}
