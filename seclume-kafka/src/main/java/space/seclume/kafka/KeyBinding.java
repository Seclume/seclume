package space.seclume.kafka;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Map;

import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.serialization.Deserializer;
import org.apache.kafka.common.serialization.Serializer;

import space.seclume.crypto.Digest;
import space.seclume.crypto.HashAlgorithm;

/**
 * Binds an encrypted value to its record's key.
 *
 * <p>Kafka does not show a value's serializer the key, so without this a value
 * copied within its topic under another key - account-17's balance as
 * account-99's - decrypted there as that key's own; whoever can write to the
 * broker can do that. Kafka does serialize a record's key and then its value
 * on one thread, with one {@link Headers} object for both, and deserializes
 * them the same way. So the key's (de)serializer, wrapped here, takes the
 * SHA-256 of the key's bytes as they go on the wire - or as they came off it -
 * and leaves it for the value's {@link EncryptingSerializer} or
 * {@link DecryptingDeserializer}, which put it into the value's associated
 * data. Nothing of it is sent: a header that claims a key's digest is not
 * read, the consumer takes the digest of the key it actually received.
 *
 * <pre>{@code
 * new KafkaProducer<>(properties, KeyBinding.serializer(new StringSerializer()),
 *         new EncryptingSerializer<>(new OrderSerializer(), keys, Mode.RANDOMIZED));
 * new KafkaConsumer<>(properties, KeyBinding.deserializer(new StringDeserializer()),
 *         new DecryptingDeserializer<>(new OrderDeserializer(), keys));
 * }</pre>
 */
public final class KeyBinding {

    /** The digest of the key serialized last on this thread, and the record it belongs to. */
    private record Bound(Headers headers, byte[] digest) {
    }

    private static final ThreadLocal<Bound> LAST = new ThreadLocal<>();

    private KeyBinding() {
    }

    /** {@code inner}, with each key's digest left for the value's serializer. */
    public static <K> Serializer<K> serializer(Serializer<K> inner) {
        if (inner == null) {
            throw new IllegalArgumentException("KeyBinding.serializer needs the key serializer "
                    + "it wraps");
        }
        return new Serializer<>() {
            @Override
            public void configure(Map<String, ?> configs, boolean isKey) {
                inner.configure(configs, isKey);
            }

            @Override
            public byte[] serialize(String topic, K data) {
                throw new SerializationException("a key bound to its value needs the record's "
                        + "headers - KafkaProducer passes them; serialize(topic, headers, key)");
            }

            @Override
            public byte[] serialize(String topic, Headers headers, K data) {
                byte[] bytes = inner.serialize(topic, headers, data);
                LAST.set(new Bound(headers, digest(bytes)));
                return bytes;
            }

            @Override
            public void close() {
                inner.close();
            }
        };
    }

    /** {@code inner}, with the digest of each key as received left for the value's deserializer. */
    public static <K> Deserializer<K> deserializer(Deserializer<K> inner) {
        if (inner == null) {
            throw new IllegalArgumentException("KeyBinding.deserializer needs the key "
                    + "deserializer it wraps");
        }
        return new Deserializer<>() {
            @Override
            public void configure(Map<String, ?> configs, boolean isKey) {
                inner.configure(configs, isKey);
            }

            @Override
            public K deserialize(String topic, byte[] data) {
                throw new SerializationException("a value bound to its key needs the record's "
                        + "headers - KafkaConsumer passes them; deserialize(topic, headers, key)");
            }

            @Override
            public K deserialize(String topic, Headers headers, byte[] data) {
                LAST.set(new Bound(headers, digest(data)));
                return inner.deserialize(topic, headers, data);
            }

            @Override
            public void close() {
                inner.close();
            }
        };
    }

    /**
     * The digest of this record's key, taken by the wrapped key (de)serializer
     * for exactly these headers, or null - once: a second value cannot use it.
     */
    static byte[] take(Headers headers) {
        Bound bound = LAST.get();
        LAST.remove();
        return bound != null && headers != null && bound.headers() == headers
                ? bound.digest() : null;
    }

    /**
     * SHA-256 over a marker and the key's bytes: a record without a key and
     * one with an empty key are different records.
     */
    static byte[] digest(byte[] key) {
        try (Digest sha = HashAlgorithm.SHA_256.newDigest()) {
            MemorySegment marker = MemorySegment.ofArray(new byte[] {(byte) (key == null ? 0 : 1)});
            sha.update(marker, 0, 1);
            if (key != null) {
                sha.update(MemorySegment.ofArray(key), 0, key.length);
            }
            MemorySegment out = MemorySegment.ofArray(new byte[sha.digestLength()]);
            sha.digest(out, 0);
            return out.toArray(ValueLayout.JAVA_BYTE);
        }
    }

    /** The associated data of a value bound to the key with this digest: topic, a zero, the digest. */
    static byte[] context(String topic, byte[] keyDigest) {
        byte[] topicPart = EncryptingSerializer.context(topic);
        byte[] context = new byte[topicPart.length + 1 + keyDigest.length];
        System.arraycopy(topicPart, 0, context, 0, topicPart.length);
        System.arraycopy(keyDigest, 0, context, topicPart.length + 1, keyDigest.length);
        return context;
    }
}
