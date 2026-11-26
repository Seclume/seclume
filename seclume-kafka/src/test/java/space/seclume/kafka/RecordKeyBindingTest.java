package space.seclume.kafka;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.header.internals.RecordHeaders;
import org.apache.kafka.common.serialization.Deserializer;
import org.apache.kafka.common.serialization.Serializer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.junit.jupiter.api.Test;

import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.FieldKeys;
import space.seclume.secret.SecretProvider;

/**
 * A value is bound to its record's key: someone who can write to the broker
 * puts account-17's "credit 5000" under account-99, and the consumer refuses
 * it there. Kafka does not show a value's serializer the key, so the key's
 * serializer and deserializer, wrapped in {@link KeyBinding}, hand its digest
 * over - the consumer's the digest of the key it actually received, whatever
 * a header claims.
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

    /** A record as KafkaProducer writes it: key, then value, one Headers object. */
    private record Record(byte[] key, byte[] value, Headers headers) {
    }

    private static Record produce(Serializer<String> keys, Serializer<String> values,
            String topic, String key, String value) {
        Headers headers = new RecordHeaders();
        byte[] keyBytes = keys.serialize(topic, headers, key);
        return new Record(keyBytes, values.serialize(topic, headers, value), headers);
    }

    /** And as KafkaConsumer reads it: key deserializer only for a key, then the value's. */
    private static String consume(Deserializer<String> keys, Deserializer<String> values,
            String topic, byte[] key, byte[] value, Headers headers) {
        if (key != null) {
            keys.deserialize(topic, headers, key);
        }
        return values.deserialize(topic, headers, value);
    }

    private static EncryptingSerializer<String> values(FieldKeys ring, Map<String, ?> config) {
        EncryptingSerializer<String> serializer = new EncryptingSerializer<>(
                new StringSerializer(), ring, Mode.RANDOMIZED);
        serializer.configure(config, false);
        return serializer;
    }

    private static DecryptingDeserializer<String> reader(FieldKeys ring, Map<String, ?> config) {
        DecryptingDeserializer<String> deserializer = new DecryptingDeserializer<>(
                new StringDeserializer(), ring);
        deserializer.configure(config, false);
        return deserializer;
    }

    private static final Serializer<String> KEYS = KeyBinding.serializer(new StringSerializer());
    private static final Deserializer<String> KEYS_IN = KeyBinding.deserializer(
            new StringDeserializer());

    @Test
    void aValueUnderItsOwnKeyIsReadAndUnderAnotherIsRefused() {
        try (FieldKeys keys = ring()) {
            Record account17 = produce(KEYS, values(keys, Map.of()), "ledger", "account-17",
                    "credit 5000");
            assertEquals("credit 5000", consume(KEYS_IN, reader(keys, Map.of()), "ledger",
                    account17.key(), account17.value(), new RecordHeaders()));
            // The broker puts the same value under account-99.
            byte[] account99 = "account-99".getBytes(StandardCharsets.UTF_8);
            SerializationException refused = assertThrows(SerializationException.class,
                    () -> consume(KEYS_IN, reader(keys, Map.of()), "ledger", account99,
                            account17.value(), new RecordHeaders()));
            assertTrue(refused.getMessage().contains("does not decrypt under its key"),
                    refused.getMessage());
        }
    }

    @Test
    void aHeaderClaimingTheOtherKeysDigestIsNotRead() {
        try (FieldKeys keys = ring()) {
            Record account17 = produce(KEYS, values(keys, Map.of()), "ledger", "account-17",
                    "credit 5000");
            Headers forged = new RecordHeaders();
            forged.add("seclume.aad.key", KeyBinding.digest(
                    "account-17".getBytes(StandardCharsets.UTF_8)));
            assertThrows(SerializationException.class, () -> consume(KEYS_IN,
                    reader(keys, Map.of()), "ledger",
                    "account-99".getBytes(StandardCharsets.UTF_8), account17.value(), forged));
        }
    }

    @Test
    void aRecordWithoutAKeyIsBoundToNoKey() {
        try (FieldKeys keys = ring()) {
            Record none = produce(KEYS, values(keys, Map.of()), "ledger", null, "no key");
            assertEquals("no key", consume(KEYS_IN, reader(keys, Map.of()), "ledger", null,
                    none.value(), new RecordHeaders()));
            Record empty = produce(KEYS, values(keys, Map.of()), "ledger", "", "empty key");
            assertThrows(SerializationException.class, () -> consume(KEYS_IN,
                    reader(keys, Map.of()), "ledger", null, empty.value(), new RecordHeaders()),
                    "an empty key and no key are different records");
            assertThrows(SerializationException.class, () -> consume(KEYS_IN,
                    reader(keys, Map.of()), "ledger", "k".getBytes(StandardCharsets.UTF_8),
                    none.value(), new RecordHeaders()), "a keyless value moved under a key");
        }
    }

    @Test
    void withoutTheKeyWrapperAValueIsRefusedNotWrittenUnbound() {
        try (FieldKeys keys = ring()) {
            SerializationException refused = assertThrows(SerializationException.class,
                    () -> produce(new StringSerializer(), values(keys, Map.of()), "ledger",
                            "account-17", "credit 5000"));
            assertTrue(refused.getMessage().contains("KeyBinding.serializer"),
                    refused.getMessage());
        }
    }

    @Test
    void unboundOnlyWhereTheConfigurationSaysSo() {
        Map<String, String> unbound = Map.of(EncryptingSerializer.BIND_TO_KEY, "false");
        try (FieldKeys keys = ring()) {
            Record old = produce(new StringSerializer(), values(keys, unbound), "ledger",
                    "account-17", "credit 5000");
            // A bound reader refuses it; one told so reads it.
            assertThrows(SerializationException.class, () -> consume(KEYS_IN,
                    reader(keys, Map.of()), "ledger", old.key(), old.value(), new RecordHeaders()));
            assertEquals("credit 5000", consume(new StringDeserializer(), reader(keys, unbound),
                    "ledger", old.key(), old.value(), new RecordHeaders()));
            // During a migration: bound values are read bound, unbound ones accepted.
            Map<String, String> migrating = Map.of(DecryptingDeserializer.READ_UNBOUND, "true");
            assertEquals("credit 5000", consume(KEYS_IN, reader(keys, migrating), "ledger",
                    old.key(), old.value(), new RecordHeaders()));
            Record bound = produce(KEYS, values(keys, Map.of()), "ledger", "account-17", "new");
            assertEquals("new", consume(KEYS_IN, reader(keys, migrating), "ledger",
                    bound.key(), bound.value(), new RecordHeaders()));
        }
    }
}
