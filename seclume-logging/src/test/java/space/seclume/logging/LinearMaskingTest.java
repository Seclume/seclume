package space.seclume.logging;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.StaticSecretProvider;

/**
 * A line of 200,000 '&' made the masker look for the end of a character
 * reference from every '&' again - quadratic, seconds per line. It is read
 * once now. Measured as what linear means: twice the line, about twice the
 * time, not four times; and a bound on the line itself, with room for a slow
 * runner.
 */
@Timeout(120)
class LinearMaskingTest {

    private static long median(SecretMasker masker, String line) {
        long[] took = new long[7];
        for (int i = 0; i < took.length; i++) {
            long started = System.nanoTime();
            masker.mask(line);
            took[i] = System.nanoTime() - started;
        }
        Arrays.sort(took);
        return took[took.length / 2];
    }

    @Test
    void aLineOfAmpersandsStaysLinear() {
        try (SecretMasker masker = new SecretMasker(Map.of("db",
                new StaticSecretProvider("linear-Pa55word")))) {
            // Eight times the line: linear is about 8 times the time, quadratic
            // 64. Twice the line put linear (2) and quadratic (4) so close that a
            // busy CI runner's noise crossed the line between them.
            String small = "&".repeat(100_000);
            String large = "&".repeat(800_000);
            for (int i = 0; i < 5; i++) {          // warm up, both sizes
                masker.mask(small);
                masker.mask(large);
            }
            long once = median(masker, small);
            long twice = median(masker, large);
            assertTrue(once < 1_000_000_000L, "100,000 '&' took " + once / 1_000_000 + " ms");
            assertTrue(twice < 20 * once + 5_000_000, "eight times the line took "
                    + (double) twice / once + " times as long - not linear (" + once / 1_000_000
                    + " ms, then " + twice / 1_000_000 + " ms)");
        }
    }
}
