package space.seclume.kafka;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.serialization.Serializer;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.FieldKeys;

/**
 * A record's value - or key - encrypted before it reaches the broker, in
 * seclume's field encryption format: the broker, its log segments, a
 * mirror and whoever reads the topic without the ring see ciphertext.
 *
 * <pre>{@code
 * Serializer<Order> values = new EncryptingSerializer<>(new OrderSerializer(), keys, Mode.RANDOMIZED);
 * new KafkaProducer<>(properties, new StringSerializer(), values);
 * ...
 * new KafkaConsumer<>(properties, new StringDeserializer(), new DecryptingDeserializer<>(new OrderDeserializer(), keys));
 * }</pre>
 *
 * <p>Each topic has its own column key ({@code kafka.<topic>.value}, or
 * {@code .key}), and the topic's name is bound to every value: a record
 * copied into another topic does not decrypt there. A key is best encrypted
 * {@link Mode#DETERMINISTIC}, so that equal keys still go to the same
 * partition; a value {@link Mode#RANDOMIZED}.
 *
 * <p>What the inner serializer produces is the application's own data on the
 * heap, as it is without encryption; what this adds is that it leaves the
 * process only as ciphertext. {@code null} stays {@code null} - a tombstone is
 * a tombstone.
 */
public class EncryptingSerializer<T> implements Serializer<T> {

    private final Serializer<T> inner;
    private final FieldKeys keys;
    private final Mode mode;
    private boolean isKey;

    /**
     * @param inner what turns a {@code T} into bytes
     * @param keys  the ring; {@code null} for the installed one ({@link FieldKeys#installed()})
     * @param mode  randomized for values, deterministic for keys
     */
    public EncryptingSerializer(Serializer<T> inner, FieldKeys keys, Mode mode) {
        if (inner == null || mode == null) {
            throw new IllegalArgumentException("an encrypting serializer needs the serializer it wraps "
                    + "and a mode");
        }
        this.inner = inner;
        this.keys = keys;
        this.mode = mode;
    }

    @Override
    public void configure(Map<String, ?> configs, boolean isKey) {
        this.isKey = isKey;
        inner.configure(configs, isKey);
    }

    @Override
    public byte[] serialize(String topic, T data) {
        return encrypt(topic, inner.serialize(topic, data));
    }

    @Override
    public byte[] serialize(String topic, Headers headers, T data) {
        return encrypt(topic, inner.serialize(topic, headers, data));
    }

    private byte[] encrypt(String topic, byte[] plain) {
        if (plain == null) {
            return null;
        }
        EncryptedColumn column = column(ring(keys), topic, isKey, mode);
        return column.encrypt(MemorySegment.ofArray(plain), context(topic));
    }

    @Override
    public void close() {
        inner.close();
    }

    static FieldKeys ring(FieldKeys keys) {
        FieldKeys ring = keys != null ? keys : FieldKeys.installed();
        if (ring == null) {
            throw new IllegalStateException("no field encryption keys: give the serializer a ring, or "
                    + "install one (FieldKeys.install, seclume.field-encryption.* in Spring or Quarkus)");
        }
        return ring;
    }

    static EncryptedColumn column(FieldKeys ring, String topic, boolean isKey, Mode mode) {
        return ring.column("kafka." + topic + (isKey ? ".key" : ".value"), mode);
    }

    static byte[] context(String topic) {
        return ("kafka-topic:" + topic).getBytes(StandardCharsets.UTF_8); // seclume-allow: a topic's name
    }
}
