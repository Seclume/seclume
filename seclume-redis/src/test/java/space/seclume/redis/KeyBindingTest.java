package space.seclume.redis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;

import org.junit.jupiter.api.Test;

import io.lettuce.core.codec.StringCodec;
import space.seclume.field.FieldKeys;
import space.seclume.secret.SecretProvider;

/**
 * What ENCRYPTION.md says of the Redis codec: a value the codec wrote is not
 * bound to its key - copied by someone who can write to Redis under another
 * key, it is read there as that key's own - and a value written with
 * encodeValueFor is, and is refused under another. Should the codec ever
 * learn its key, the first test fails, and the documentation is to change
 * with it.
 */
class KeyBindingTest {

    private static FieldKeys ring() {
        return FieldKeys.builder().key(1, new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                for (int i = 0; i < 32; i++) {
                    target.set(ValueLayout.JAVA_BYTE, i, (byte) (i * 13 + 5));
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
    void aCodecValueCopiedToAnotherKeyIsReadThere() {
        try (FieldKeys keys = ring()) {
            EncryptedCodec<String, String> codec = EncryptedCodec.of(StringCodec.UTF8, keys, "accounts");
            ByteBuffer written = codec.encodeValue("credit 5000");       // under account:17
            ByteBuffer copied = written.duplicate();                     // SET account:99 <that>
            assertEquals("credit 5000", codec.decodeValue(copied));
        }
    }

    /** The edges of the bound round trip: nothing at all, and a value of a mebibyte. */
    @Test
    void anEmptyAndAMebibyteValueComeBackUnderTheirKey() {
        try (FieldKeys keys = ring()) {
            EncryptedCodec<String, String> codec = EncryptedCodec.of(StringCodec.UTF8, keys, "accounts");
            for (String value : new String[] {"", "x".repeat(1 << 20)}) {
                ByteBuffer written = codec.encodeValueFor("account:17", value);
                assertEquals(value, codec.decodeValueFor("account:17", written.duplicate()),
                        value.length() + " characters");
                assertThrows(RuntimeException.class,
                        () -> codec.decodeValueFor("account:18", written.duplicate()));
            }
        }
    }

    @Test
    void aValueBoundToItsKeyIsRefusedUnderAnother() {
        try (FieldKeys keys = ring()) {
            EncryptedCodec<String, String> codec = EncryptedCodec.of(StringCodec.UTF8, keys, "accounts");
            ByteBuffer written = codec.encodeValueFor("account:17", "credit 5000");
            assertEquals("credit 5000", codec.decodeValueFor("account:17", written.duplicate()));
            assertThrows(RuntimeException.class,
                    () -> codec.decodeValueFor("account:99", written.duplicate()));
            assertThrows(RuntimeException.class, () -> codec.decodeValue(written.duplicate()),
                    "a bound value opens only where it is bound");
        }
    }
}
