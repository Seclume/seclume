package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import space.seclume.crypto.HashAlgorithm;

/**
 * Which hash belongs to which signature - the part of channel binding that is
 * a decision rather than arithmetic.
 *
 * <p>The arithmetic is checked where it counts, against a real PostgreSQL that
 * recomputes the fingerprint from its own certificate and refuses the login if
 * it differs. What is checked here is the mapping, because a wrong one fails
 * with a message about the password and sends whoever debugs it in the wrong
 * direction entirely.
 */
class ChannelBindingTest {

    @ParameterizedTest
    @CsvSource({
        // RFC 5929 section 4.1: the certificate's own hash, except that
        // MD5 and SHA-1 are lifted to SHA-256.
        "SHA256withRSA,SHA_256",
        "SHA384withECDSA,SHA_384",
        "SHA512withRSA,SHA_512",
        "SHA1withRSA,SHA_256",
        "MD5withRSA,SHA_256",
        "SHA256withECDSA,SHA_256",
        "SHA-256withRSA,SHA_256",
        "sha256WithRSAEncryption,SHA_256",
    })
    void picksTheHashOfTheSignature(String signature, HashAlgorithm expected) {
        assertEquals(expected, ChannelBinding.hashFor(signature));
    }

    /**
     * An algorithm whose hash is not in its name is refused, not guessed.
     *
     * <p>RSASSA-PSS carries the hash in its parameters. Guessing SHA-256 there
     * would be right most of the time and silently wrong the rest, and „silently
     * wrong" in this place means a login that fails complaining about the
     * password.
     */
    @Test
    void refusesWhatItCannotName() {
        assertThrows(IllegalArgumentException.class, () -> ChannelBinding.hashFor("RSASSA-PSS"));
        assertThrows(IllegalArgumentException.class, () -> ChannelBinding.hashFor(null));
    }

    /** The buffer size callers rely on has to hold the longest answer. */
    @Test
    void theStatedMaximumHolds() {
        for (HashAlgorithm algorithm : HashAlgorithm.values()) {
            assertEquals(true, algorithm.digestLength() <= ChannelBinding.MAX_LENGTH,
                    algorithm + " is longer than the stated maximum");
        }
    }
}
