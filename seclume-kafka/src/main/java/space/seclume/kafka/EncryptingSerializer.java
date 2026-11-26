package space.seclume.kafka;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.apache.kafka.common.errors.SerializationException;
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
 * copied into another topic does not decrypt there. A value is bound to its
 * record's key as well - account-17's balance copied under account-99 does
 * not decrypt - which needs the key's serializer wrapped in
 * {@link KeyBinding#serializer}: Kafka does not show a value's serializer the
 * key. Without the wrapper a value is refused rather than written unbound;
 * {@code seclume.kafka.bind-to-key=false} in the producer's configuration (or
 * the constructor's {@code bindToKey}) writes it unbound, as before. A key is best encrypted
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
    /** Whether a value is bound to its record's key - see {@link KeyBinding}. */
    private boolean bindToKey;

    /** The configuration that writes values unbound to their key, as before 0.15. */
    public static final String BIND_TO_KEY = "seclume.kafka.bind-to-key";

    /**
     * A value bound to its record's key: the key serializer wrapped in
     * {@link KeyBinding#serializer}.
     *
     * @param inner what turns a {@code T} into bytes
     * @param keys  the ring; {@code null} for the installed one ({@link FieldKeys#installed()})
     * @param mode  randomized for values, deterministic for keys
     */
    public EncryptingSerializer(Serializer<T> inner, FieldKeys keys, Mode mode) {
        this(inner, keys, mode, true);
    }

    /**
     * @param bindToKey false writes values a broker can move between keys of
     *                  their topic, as before 0.15 - see the class comment
     */
    public EncryptingSerializer(Serializer<T> inner, FieldKeys keys, Mode mode,
                                boolean bindToKey) {
        if (inner == null || mode == null) {
            throw new IllegalArgumentException("an encrypting serializer needs the serializer it wraps "
                    + "and a mode");
        }
        this.inner = inner;
        this.keys = keys;
        this.mode = mode;
        this.bindToKey = bindToKey;
    }

    @Override
    public void configure(Map<String, ?> configs, boolean isKey) {
        this.isKey = isKey;
        Object bind = configs == null ? null : configs.get(BIND_TO_KEY);
        if (bind != null) {
            bindToKey = Boolean.parseBoolean(bind.toString().strip());
        }
        inner.configure(configs, isKey);
    }

    @Override
    public byte[] serialize(String topic, T data) {
        if (bound()) {
            throw new SerializationException("a value of topic " + topic + " is bound to its "
                    + "record's key, which needs the record's headers - KafkaProducer passes them");
        }
        return encrypt(topic, inner.serialize(topic, data), null);
    }

    @Override
    public byte[] serialize(String topic, Headers headers, T data) {
        byte[] keyDigest = bound() ? KeyBinding.take(headers) : null;
        if (bound() && keyDigest == null) {
            throw new SerializationException("a value of topic " + topic + " is bound to its "
                    + "record's key, and the key serializer does not say which key that is: "
                    + "wrap it in KeyBinding.serializer(...), or set " + BIND_TO_KEY + "=false "
                    + "to write values a broker can move between keys");
        }
        return encrypt(topic, inner.serialize(topic, headers, data), keyDigest);
    }

    /** A value is bound; a key, encrypted itself, is what the binding is taken of. */
    private boolean bound() {
        return bindToKey && !isKey;
    }

    private byte[] encrypt(String topic, byte[] plain, byte[] keyDigest) {
        if (plain == null) {
            return null;
        }
        EncryptedColumn column = column(ring(keys), topic, isKey, mode);
        return column.encrypt(MemorySegment.ofArray(plain),
                keyDigest == null ? context(topic) : KeyBinding.context(topic, keyDigest));
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
