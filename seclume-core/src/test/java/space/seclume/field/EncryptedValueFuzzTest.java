package space.seclume.field;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import space.seclume.crypto.AesGcmSiv;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.secret.SecretScope;

/**
 * Coverage-guided search for a stored value that decrypts when it should not,
 * or fails with anything but {@link FieldEncryptionException}: what comes out
 * of a database column is as hostile as what comes off a socket - whoever can
 * write to the table chooses it.
 *
 * <p>The ordinary build replays the seed corpus
 * ({@code EncryptedValueFuzzTestInputs}); {@code JAZZER_FUZZ=1} searches, and
 * CI's {@code parser-fuzz} job does that for a minute on every pull request.
 * {@link FieldEncryptionPropertyTest} runs a seeded random sample of the same
 * in every build without Jazzer.
 */
class EncryptedValueFuzzTest {

    private static final byte[] KEY = new byte[32];
    private static final byte[] KNOWN = "the only value this column was ever given"
            .getBytes(StandardCharsets.US_ASCII);

    /**
     * Anything at all, in both modes: refused, or - only if it is exactly a
     * value this ring wrote - the plaintext that was written.
     */
    @FuzzTest(maxDuration = "60s")
    void anyStoredValueDecryptsOnlyIfItWasWritten(byte[] stored) {
        try (FieldKeys keys = FieldEncryptionTest.ring(1, KEY);
             SecretScope out = SecretScope.allocate(Math.max(1, stored.length))) {
            for (Mode mode : Mode.values()) {
                EncryptedColumn column = keys.column("fuzz.value", mode);
                try {
                    int length = column.decrypt(stored, out.segment());
                    // Only a forgery of AES-GCM-SIV gets here: the column was given one value.
                    assertArrayEquals(KNOWN, out.segment().asSlice(0, length)
                            .toArray(ValueLayout.JAVA_BYTE), mode + ": a forged value decrypted");
                } catch (FieldEncryptionException expected) {
                    // refused, as it should be
                } catch (RuntimeException e) {
                    fail(mode + ": " + e, e);
                }
            }
        }
    }

    /** AES-GCM-SIV itself: any key, nonce, AAD and message round-trips, and one flipped bit fails. */
    @FuzzTest(maxDuration = "60s")
    void aesGcmSivRoundTripsAndRefusesAnyChange(FuzzedDataProvider data) {
        int keyLength = data.consumeBoolean() ? 32 : 16;
        byte[] key = data.consumeBytes(keyLength);
        byte[] nonce = data.consumeBytes(AesGcmSiv.NONCE);
        if (key.length != keyLength || nonce.length != AesGcmSiv.NONCE) {
            return;
        }
        byte[] aad = data.consumeBytes(data.consumeInt(0, 64));
        int flip = data.consumeInt(-1, 1 << 16);
        byte[] message = data.consumeRemainingAsBytes();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment k = copy(arena, key);
            MemorySegment n = copy(arena, nonce);
            MemorySegment a = copy(arena, aad);
            MemorySegment sealed = arena.allocate(message.length + 16L);
            AesGcmSiv.encrypt(k, 0, keyLength, n, 0, a, 0, aad.length,
                    MemorySegment.ofArray(message), 0, message.length, sealed, 0);
            MemorySegment out = arena.allocate(Math.max(1, message.length));
            if (flip >= 0) {
                long at = flip % (message.length + 16L);
                sealed.set(ValueLayout.JAVA_BYTE, at,
                        (byte) (sealed.get(ValueLayout.JAVA_BYTE, at) ^ (1 << (flip & 7))));
                if (AesGcmSiv.decrypt(k, 0, keyLength, n, 0, a, 0, aad.length, sealed, 0,
                        message.length, out, 0)) {
                    fail("a flipped bit at " + at + " was accepted");
                }
            } else {
                if (!AesGcmSiv.decrypt(k, 0, keyLength, n, 0, a, 0, aad.length, sealed, 0,
                        message.length, out, 0)) {
                    fail("a genuine message was refused");
                }
                assertArrayEquals(message, out.asSlice(0, message.length)
                        .toArray(ValueLayout.JAVA_BYTE));
            }
        }
    }

    private static MemorySegment copy(Arena arena, byte[] bytes) {
        MemorySegment segment = arena.allocate(Math.max(1, bytes.length));
        MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return segment;
    }
}
