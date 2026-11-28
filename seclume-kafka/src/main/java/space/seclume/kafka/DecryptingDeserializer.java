package space.seclume.kafka;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Map;

import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.serialization.Deserializer;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.FieldEncryptionException;
import space.seclume.field.FieldKeys;

/**
 * Opens what {@link EncryptingSerializer} wrote, then hands the bytes to the
 * inner deserializer. A record that was not written for this topic with this
 * ring is a {@link SerializationException} - which a consumer can skip or send
 * to a dead letter topic - never a wrong value.
 *
 * <p>The mode is read from the value itself; any key the ring holds opens it,
 * so a consumer reads through a key rotation without being told.
 *
 * <p>A value is read as bound to the key of its record, as
 * {@link EncryptingSerializer} writes it: the key deserializer wrapped in
 * {@link KeyBinding#deserializer} gives the digest of the key actually
 * received, and a value moved under another key does not decrypt. A record
 * without a key is read as bound to no key. Values written unbound, before
 * 0.15 or with {@code seclume.kafka.bind-to-key=false}, are read with
 * {@code seclume.kafka.bind-to-key=false} too - or, while a topic holds both,
 * with {@code seclume.kafka.read-unbound=true}, which accepts an unbound value
 * where a bound one does not open: for a migration, since it accepts what a
 * broker moved.
 */
public class DecryptingDeserializer<T> implements Deserializer<T> {

    private final Deserializer<T> inner;
    private final FieldKeys keys;
    private boolean isKey;
    private boolean bindToKey = true;
    private boolean readUnbound;

    /** The configuration that, while a topic holds both, accepts values written unbound. */
    public static final String READ_UNBOUND = "seclume.kafka.read-unbound";

    /** @param keys the ring; {@code null} for the installed one */
    public DecryptingDeserializer(Deserializer<T> inner, FieldKeys keys) {
        if (inner == null) {
            throw new IllegalArgumentException("a decrypting deserializer needs the deserializer it wraps");
        }
        this.inner = inner;
        this.keys = keys;
    }

    @Override
    public void configure(Map<String, ?> configs, boolean isKey) {
        this.isKey = isKey;
        if (configs != null) {
            Object bind = configs.get(EncryptingSerializer.BIND_TO_KEY);
            if (bind != null) {
                bindToKey = Boolean.parseBoolean(bind.toString().strip());
            }
            Object unbound = configs.get(READ_UNBOUND);
            if (unbound != null) {
                readUnbound = Boolean.parseBoolean(unbound.toString().strip());
            }
        }
        inner.configure(configs, isKey);
    }

    @Override
    public T deserialize(String topic, byte[] data) {
        if (bound()) {
            throw new SerializationException("a value of topic " + topic + " is bound to its "
                    + "record's key, which needs the record's headers - KafkaConsumer passes them");
        }
        return inner.deserialize(topic, decrypt(topic, data, null));
    }

    @Override
    public T deserialize(String topic, Headers headers, byte[] data) {
        byte[] keyDigest = null;
        if (bound()) {
            // No digest from the key's deserializer: the record has no key -
            // Kafka does not call a key deserializer for one.
            keyDigest = KeyBinding.take(headers);
            if (keyDigest == null) {
                keyDigest = KeyBinding.digest(null);
            }
        }
        return inner.deserialize(topic, headers, decrypt(topic, data, keyDigest));
    }

    private boolean bound() {
        return bindToKey && !isKey;
    }

    private byte[] decrypt(String topic, byte[] data, byte[] keyDigest) {
        if (keyDigest == null) {
            return open(topic, data, EncryptingSerializer.context(topic));
        }
        try {
            return open(topic, data, KeyBinding.context(topic, keyDigest));
        } catch (SerializationException notUnderThisKey) {
            if (!readUnbound) {
                throw new SerializationException("a record of topic " + topic + " does not "
                        + "decrypt under its key: it was moved from another key, or written "
                        + "unbound (before 0.15, or with " + EncryptingSerializer.BIND_TO_KEY
                        + "=false), or the consumer's key deserializer is not wrapped in "
                        + "KeyBinding.deserializer(...). " + READ_UNBOUND + "=true accepts unbound "
                        + "values while a topic holds both", notUnderThisKey);
            }
            return open(topic, data, EncryptingSerializer.context(topic));
        }
    }

    private byte[] open(String topic, byte[] data, byte[] context) {
        if (data == null) {
            return null;
        }
        if (data.length < 2) {
            throw new SerializationException("a record of topic " + topic + " is not seclume ciphertext");
        }
        Mode mode = data[1] == 1 ? Mode.DETERMINISTIC : Mode.RANDOMIZED;
        EncryptedColumn column = EncryptingSerializer.column(EncryptingSerializer.ring(keys), topic, isKey, mode);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment plain = arena.allocate(Math.max(1, column.plaintextLength(data)));
            int length = column.decrypt(data, context, plain);
            byte[] bytes = plain.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE);
            plain.fill((byte) 0);
            return bytes;
        } catch (FieldEncryptionException e) {
            throw new SerializationException("a record of topic " + topic + " does not decrypt with "
                    + "this ring: " + e.getMessage(), e);
        }
    }

    @Override
    public void close() {
        inner.close();
    }
}
