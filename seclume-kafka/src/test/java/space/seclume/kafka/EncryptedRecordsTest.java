package space.seclume.kafka;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.header.internals.RecordHeaders;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.FieldKeys;
import space.seclume.secret.SecretProvider;

/**
 * Records encrypted for a topic: back as they went, never in the clear, bound
 * to their topic. Isolated: one test installs a ring for the process.
 */
@Isolated
class EncryptedRecordsTest {

    private static SecretProvider key(int seed) {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                for (int i = 0; i < 32; i++) {
                    target.set(ValueLayout.JAVA_BYTE, i, (byte) (seed * 31 + i));
                }
                return 32;
            }

            @Override
            public int maxSecretLength() {
                return 32;
            }
        };
    }

    private static EncryptingSerializer<String> values(FieldKeys keys) {
        EncryptingSerializer<String> serializer = new EncryptingSerializer<>(new StringSerializer(), keys,
                Mode.RANDOMIZED);
        serializer.configure(Map.of(), false);
        return serializer;
    }

    private static DecryptingDeserializer<String> reader(FieldKeys keys, boolean isKey) {
        DecryptingDeserializer<String> deserializer = new DecryptingDeserializer<>(new StringDeserializer(), keys);
        deserializer.configure(Map.of(), isKey);
        return deserializer;
    }

    @Test
    void aValueComesBackAsItWentAndIsNeverInTheClear() {
        try (FieldKeys keys = FieldKeys.builder().key(1, key(1)).build()) {
            byte[] stored = produce(values(keys), "orders", "4111 1111 1111 1111");
            assertFalse(new String(stored, StandardCharsets.ISO_8859_1).contains("4111"));
            assertEquals("4111 1111 1111 1111", consume(reader(keys, false), "orders", stored));
            assertEquals("4111 1111 1111 1111", reader(keys, false).deserialize("orders",
                    new RecordHeaders(), stored));
            assertFalse(java.util.Arrays.equals(stored, produce(values(keys), "orders", "4111 1111 1111 1111")),
                    "randomized: the same value twice, two ciphertexts");
        }
    }

    @Test
    void aDeterministicKeyKeepsItsPartition() {
        try (FieldKeys keys = FieldKeys.builder().key(1, key(1)).build()) {
            EncryptingSerializer<String> recordKeys = new EncryptingSerializer<>(new StringSerializer(), keys,
                    Mode.DETERMINISTIC);
            recordKeys.configure(Map.of(), true);
            byte[] one = recordKeys.serialize("orders", "customer-7");
            assertArrayEquals(one, recordKeys.serialize("orders", "customer-7"));
            assertEquals("customer-7", reader(keys, true).deserialize("orders", one));
            assertThrows(SerializationException.class, () -> consume(reader(keys, false), "orders", one),
                    "a key is not a value: its column key is another");
        }
    }

    @Test
    void aRecordCopiedIntoAnotherTopicDoesNotOpenThere() {
        try (FieldKeys keys = FieldKeys.builder().key(1, key(1)).build()) {
            byte[] stored = produce(values(keys), "orders", "secret order");
            assertThrows(SerializationException.class, () -> consume(reader(keys, false), "audit", stored));
        }
    }

    @Test
    void anotherRingAndGarbageAreSerializationErrors() {
        try (FieldKeys keys = FieldKeys.builder().key(1, key(1)).build();
             FieldKeys other = FieldKeys.builder().key(1, key(2)).build()) {
            byte[] stored = produce(values(keys), "orders", "x");
            assertThrows(SerializationException.class, () -> consume(reader(other, false), "orders", stored));
            assertThrows(SerializationException.class, () -> consume(reader(keys, false), "orders",
                    "plain text".getBytes(StandardCharsets.UTF_8)));
            assertThrows(SerializationException.class, () -> consume(reader(keys, false), "orders", new byte[1]));
        }
    }

    @Test
    void aRotationIsReadThroughWithoutBeingTold() {
        byte[] old;
        try (FieldKeys one = FieldKeys.builder().key(1, key(1)).build()) {
            old = produce(values(one), "orders", "written under key 1");
        }
        try (FieldKeys both = FieldKeys.builder().key(1, key(1)).key(2, key(2)).primary(2).build()) {
            assertEquals("written under key 1", consume(reader(both, false), "orders", old));
            byte[] fresh = produce(values(both), "orders", "under key 2");
            assertEquals(2, both.column("kafka.orders.value", Mode.RANDOMIZED).keyId(fresh));
        }
    }

    @Test
    void tombstonesStayTombstonesAndTheInstalledRingIsUsed() {
        try (FieldKeys keys = FieldKeys.builder().key(1, key(1)).build()) {
            assertNull(produce(values(keys), "orders", null));
            assertNull(consume(reader(keys, false), "orders", null));
            FieldKeys.install(keys);
            try {
                byte[] stored = produce(values(null), "orders", "installed");
                assertEquals("installed", consume(reader(null, false), "orders", stored));
            } finally {
                FieldKeys.install(null);
            }
        }
        assertThrows(IllegalStateException.class, () -> produce(values(null), "orders", "no ring"));
        assertThrows(IllegalArgumentException.class, () -> new EncryptingSerializer<String>(null, null, Mode.RANDOMIZED));
        assertThrows(IllegalArgumentException.class, () -> new DecryptingDeserializer<String>(null, null));
    }

    /**
     * What KafkaProducer does for a record without a key: the key serializer -
     * wrapped in KeyBinding, as a bound value needs - then the value's, with
     * one Headers object.
     */
    private static byte[] produce(EncryptingSerializer<String> values, String topic, String value) {
        org.apache.kafka.common.header.Headers headers =
                new org.apache.kafka.common.header.internals.RecordHeaders();
        KeyBinding.serializer(new StringSerializer()).serialize(topic, headers, null);
        return values.serialize(topic, headers, value);
    }

    /** What KafkaConsumer does for one: no key, so no key deserializer; then the value's. */
    private static String consume(DecryptingDeserializer<String> reader, String topic, byte[] value) {
        return reader.deserialize(topic, new org.apache.kafka.common.header.internals.RecordHeaders(),
                value);
    }
}
