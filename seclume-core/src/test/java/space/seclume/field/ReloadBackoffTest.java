package space.seclume.field;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.secret.SecretProvider;

/**
 * After a checkpoint the ring forgets its keys and reads them again on next
 * use. A provider that could not be reached - the network not yet up after a
 * restore - was asked again for every single value: one Vault or KMS request
 * per row. A failed reload holds the next ones off for a moment.
 */
class ReloadBackoffTest {

    @Test
    void aFailedReloadIsNotRepeatedForEveryValue() {
        AtomicInteger asked = new AtomicInteger();
        AtomicBoolean reachable = new AtomicBoolean(true);
        byte[] key = FieldEncryptionTest.otherKey();
        SecretProvider provider = new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                asked.incrementAndGet();
                if (!reachable.get()) {
                    throw new IllegalStateException("the key service is not reachable (decoy)");
                }
                MemorySegment.copy(key, 0, target, ValueLayout.JAVA_BYTE, 0, key.length);
                return key.length;
            }

            @Override
            public int maxSecretLength() {
                return key.length;
            }
        };
        try (FieldKeys keys = FieldKeys.builder().key(1, provider).build()) {
            EncryptedColumn column = keys.column("t.a", Mode.RANDOMIZED);
            assertEquals(1, asked.get());
            reachable.set(false);
            keys.forget();
            MemorySegment value = MemorySegment.ofArray("x".getBytes(StandardCharsets.UTF_8));
            for (int i = 0; i < 50; i++) {
                assertThrows(RuntimeException.class, () -> column.encrypt(value));
            }
            assertEquals(2, asked.get(), "the provider was asked once per value");
        }
    }
}
