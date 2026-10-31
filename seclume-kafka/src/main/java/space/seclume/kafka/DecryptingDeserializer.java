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
 */
public class DecryptingDeserializer<T> implements Deserializer<T> {

    private final Deserializer<T> inner;
    private final FieldKeys keys;
    private boolean isKey;

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
        inner.configure(configs, isKey);
    }

    @Override
    public T deserialize(String topic, byte[] data) {
        return inner.deserialize(topic, decrypt(topic, data));
    }

    @Override
    public T deserialize(String topic, Headers headers, byte[] data) {
        return inner.deserialize(topic, headers, decrypt(topic, data));
    }

    private byte[] decrypt(String topic, byte[] data) {
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
            int length = column.decrypt(data, EncryptingSerializer.context(topic), plain);
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
