package space.seclume.kafka;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Map;

import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.junit.jupiter.api.Test;

import space.seclume.field.FieldKeys;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.secret.SecretProvider;

/**
 * What ENCRYPTION.md says of the Kafka serializers: a value is bound to its
 * topic, not to its record's key - Kafka's Serializer is not shown the key.
 * Someone who can write to the broker puts account-17's "credit 5000" under
 * account-99, and the consumer reads it there. Should the serializers ever
 * learn the key, this test fails, and the documentation is to change with it.
 */
class RecordKeyBindingTest {

    private static FieldKeys ring() {
        return FieldKeys.builder().key(1, new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                for (int i = 0; i < 32; i++) {
                    target.set(ValueLayout.JAVA_BYTE, i, (byte) (i * 11 + 7));
                }
                return 32;
            }

            @Override
            public int maxSecretLength() {
                return 32;
            }
        }).build();
    }

    @Test
    void aValueCopiedToAnotherKeyOfItsTopicIsReadThere() {
        try (FieldKeys keys = ring();
             EncryptingSerializer<String> serializer = new EncryptingSerializer<>(
                     new StringSerializer(), keys, Mode.RANDOMIZED);
             DecryptingDeserializer<String> deserializer = new DecryptingDeserializer<>(
                     new StringDeserializer(), keys)) {
            serializer.configure(Map.of(), false);
            deserializer.configure(Map.of(), false);
            byte[] forAccount17 = serializer.serialize("ledger", "credit 5000");
            // The same bytes as the value of a record keyed account-99.
            assertEquals("credit 5000", deserializer.deserialize("ledger", forAccount17.clone()));
        }
    }
}
