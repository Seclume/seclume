package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * Nonces and placeholders came from a SecureRandom of each class's own; the
 * kernel's source is the one seclume vouches for, on Windows and under a DRBG
 * configuration as well. A heap array is filled from it through native memory.
 */
class EntropyArrayTest {

    @Test
    void anArrayIsFilledAndTwoFillsDiffer() {
        byte[] first = new byte[32];
        byte[] second = new byte[32];
        Entropy.fill(first);
        Entropy.fill(second);
        assertFalse(Arrays.equals(new byte[32], first), "nothing was drawn");
        assertFalse(Arrays.equals(first, second), "two draws were the same");
        Entropy.fill(new byte[0]);
    }
}
