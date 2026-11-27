package space.seclume.field;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.secret.SecretProvider;

/**
 * A key of one byte repeated - zeros from /dev/zero, 0x41 from a placeholder
 * filled in - has eight bits of choice. Refused when the ring is built.
 */
class FieldKeysTrivialKeyTest {

    private static SecretProvider filled(int value) {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                target.asSlice(0, 32).fill((byte) value);
                return 32;
            }

            @Override
            public int maxSecretLength() {
                return 32;
            }
        };
    }

    @ParameterizedTest(name = "0x{0}")
    @ValueSource(ints = {0x00, 0x41, 0xff, 0x07})
    void aKeyOfOneRepeatedByteIsRefused(int value) {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> FieldKeys.builder().key(1, filled(value)).build().close());
        assertTrue(refused.getMessage().contains("key 1"), refused.getMessage());
    }

    @ParameterizedTest(name = "differs at byte {0}")
    @ValueSource(ints = {0, 17, 31})
    void oneByteDifferentIsAKey(int at) {
        SecretProvider almost = new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                target.asSlice(0, 32).fill((byte) 0x01);
                target.set(ValueLayout.JAVA_BYTE, at, (byte) 0x02);
                return 32;
            }

            @Override
            public int maxSecretLength() {
                return 32;
            }
        };
        FieldKeys.builder().key(1, almost).build().close();
    }
}
