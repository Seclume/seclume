package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * P2: OpenSSL's generator can be reseeded - what a restored process does
 * before its first handshake. That a restore from one image really gives
 * each instance different key shares needs a CRaC JDK and is shown by
 * seclume-crac/proof, not here.
 */
class OpenSslRandomTest {

    @Test
    void theGeneratorTakesAFreshSeed() {
        Assumptions.assumeTrue(OpenSslRandom.available(), "no libcrypto.so.3 here");
        assertTrue(OpenSslRandom.reseed());
        assertTrue(OpenSslRandom.reseed(), "a second reseed is as good as the first");
    }

    @Test
    void keysAreStillMadeAfterAReseed() {
        Assumptions.assumeTrue(OpenSslRandom.available(), "no libcrypto.so.3 here");
        OpenSslRandom.reseed();
        try (NativeP256 key = NativeP256.generate()) {
            assertTrue(key != null);
        }
    }
}
