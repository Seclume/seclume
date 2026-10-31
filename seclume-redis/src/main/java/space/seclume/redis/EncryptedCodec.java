package space.seclume.redis;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import io.lettuce.core.codec.RedisCodec;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.FieldKeys;

/**
 * A Lettuce codec that stores values encrypted - and keys too, if asked -
 * in seclume's field encryption format: the Redis server, its RDB and AOF
 * files, a replica and {@code MONITOR} see ciphertext.
 *
 * <pre>{@code
 * RedisCodec<String, String> codec = EncryptedCodec.of(StringCodec.UTF8, keys, "sessions");
 * StatefulRedisConnection<String, String> redis = client.connect(codec);
 * }</pre>
 *
 * <p>Values are encrypted {@link Mode#RANDOMIZED}, under the column
 * {@code redis.<name>.value}. Keys stay readable - {@code SCAN}, {@code TTL}
 * and patterns keep working - unless {@link #withEncryptedKeys} is used: then
 * they are encrypted {@link Mode#DETERMINISTIC}, so that {@code GET} of the
 * same key still finds the same entry, but patterns no longer match.
 *
 * <p>A value written under one {@code name} does not open under another. A
 * value read back from a key it was not written for does: Lettuce's codec does
 * not hand the key to {@code decodeValue}, so binding a value to its key is not
 * possible here - use different names for data that must not be swapped.
 */
public final class EncryptedCodec<K, V> implements RedisCodec<K, V> {

    private final RedisCodec<K, V> inner;
    private final EncryptedColumn values;
    private final EncryptedColumn keys;
    private final byte[] context;

    private EncryptedCodec(RedisCodec<K, V> inner, FieldKeys ring, String name, boolean encryptKeys) {
        this.inner = inner;
        this.values = ring.column("redis." + name + ".value", Mode.RANDOMIZED);
        this.keys = encryptKeys ? ring.column("redis." + name + ".key", Mode.DETERMINISTIC) : null;
        this.context = ("redis:" + name).getBytes(StandardCharsets.UTF_8); // seclume-allow: a name, not a secret
    }

    /**
     * Values encrypted, keys as they are.
     *
     * @param ring the ring; {@code null} for the installed one
     * @param name what these entries are - {@code sessions}, {@code carts} - part of their key
     */
    public static <K, V> EncryptedCodec<K, V> of(RedisCodec<K, V> inner, FieldKeys ring, String name) {
        return new EncryptedCodec<>(check(inner, name), ring(ring), name, false);
    }

    /** As {@link #of}, and the keys encrypted deterministically. */
    public static <K, V> EncryptedCodec<K, V> withEncryptedKeys(RedisCodec<K, V> inner, FieldKeys ring,
            String name) {
        return new EncryptedCodec<>(check(inner, name), ring(ring), name, true);
    }

    private static <K, V> RedisCodec<K, V> check(RedisCodec<K, V> inner, String name) {
        if (inner == null || name == null || name.isBlank()) {
            throw new IllegalArgumentException("an encrypted codec needs the codec it wraps and a name");
        }
        return inner;
    }

    private static FieldKeys ring(FieldKeys ring) {
        FieldKeys chosen = ring != null ? ring : FieldKeys.installed();
        if (chosen == null) {
            throw new IllegalStateException("no field encryption keys: give the codec a ring, or install one");
        }
        return chosen;
    }

    @Override
    public K decodeKey(ByteBuffer bytes) {
        return inner.decodeKey(keys == null ? bytes : decrypt(keys, bytes));
    }

    @Override
    public V decodeValue(ByteBuffer bytes) {
        return inner.decodeValue(decrypt(values, bytes));
    }

    @Override
    public ByteBuffer encodeKey(K key) {
        ByteBuffer plain = inner.encodeKey(key);
        return keys == null ? plain : encrypt(keys, plain);
    }

    @Override
    public ByteBuffer encodeValue(V value) {
        return encrypt(values, inner.encodeValue(value));
    }

    private ByteBuffer encrypt(EncryptedColumn column, ByteBuffer plain) {
        byte[] bytes = new byte[plain.remaining()];
        plain.duplicate().get(bytes);
        return ByteBuffer.wrap(column.encrypt(MemorySegment.ofArray(bytes), context));
    }

    private ByteBuffer decrypt(EncryptedColumn column, ByteBuffer stored) {
        byte[] bytes = new byte[stored.remaining()];
        stored.duplicate().get(bytes);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment plain = arena.allocate(Math.max(1, column.plaintextLength(bytes)));
            int length = column.decrypt(bytes, context, plain);
            ByteBuffer out = ByteBuffer.wrap(plain.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE));
            plain.fill((byte) 0);
            return out;
        }
    }
}
