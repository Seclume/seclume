package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Random;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The encrypted-flight sweep of {@code ServerHelloFuzzTest}, as a fixed sample
 * that runs in every build - the fuzzer searches, this makes sure that what it
 * searches with still works and that the obvious cases stay caught.
 *
 * <p>Deterministic: one seeded {@link Random}, the seed in the failure. The
 * full search is {@code JAZZER_FUZZ=1}.
 */
@Timeout(300)
class EncryptedFlightSampleTest {

    private static final long SEED = Long.getLong("seclume.fuzz.seed", 0x5ec1_0e_2026L);
    private static final int CASES = Integer.getInteger("seclume.fuzz.flights",
            Boolean.getBoolean("seclume.fuzz.full") ? 20_000 : 1_500);

    @Test
    void noSampledFlightConnectsUnauthenticatedOrFailsLikeABug() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        EncryptedFlight.Material material = EncryptedFlight.material();
        Random random = new Random(SEED);
        for (int i = 0; i < CASES; i++) {
            byte[] input = new byte[1 + random.nextInt(i % 3 == 0 ? 12 : 400)];
            random.nextBytes(input);
            if (i % 5 == 0 && input.length > 1) {
                // A sparse mask: one spoilt byte in an otherwise intact flight
                // reaches much further into the parser than noise does.
                byte keep = input[0];
                int at = random.nextInt(input.length);
                byte spoil = input[at];
                java.util.Arrays.fill(input, (byte) 0);
                input[0] = (byte) (keep | 5);       // bytes, length kept
                input[at == 0 ? 1 : at] = spoil;
            }
            try {
                EncryptedFlight.run(input, material);
            } catch (AssertionError e) {
                throw new AssertionError("case " + i + " of seed " + SEED + ": "
                        + e.getMessage(), e);
            }
        }
        // The control: the two legal orders, and the untouched flight, connect.
        for (byte[] legal : new byte[][] {
            {0, 0, 2, 3, 4, 5},                 // EE, Certificate, CertificateVerify, Finished
            {2, 0, 1, 2, 3, 4, 5},              // with CertificateRequest, verify-full
            {7},                                // overlay of nothing: the flight as it is
        }) {
            assertTrue(EncryptedFlight.run(legal, material),
                    "the control did not connect, so the sweep proves nothing");
        }
    }
}
