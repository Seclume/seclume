package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * {@code tlsPin} with every first character a base64 pin can have, written
 * both ways: {@code sha256/<base64>} and curl's {@code sha256//<base64>}.
 *
 * <p>One key in 64 has a base64 that starts with '/'. The parser took that
 * '/' for curl's extra slash and refused the pin, which made
 * {@code TrustChoiceTest.thePinnedKeyIsTrusted} fail on one run in 64 -
 * and made those servers' keys impossible to pin.
 */
class TrustChoicePinTest {

    @Test
    void everyFirstCharacterIsReadBothWays() throws Exception {
        for (int first = 0; first < 64; first++) {
            byte[] key = new byte[32];
            for (int i = 1; i < key.length; i++) {
                key[i] = (byte) (i * 37);
            }
            key[0] = (byte) (first << 2);
            String base64 = Base64.getEncoder().encodeToString(key);
            assertArrayEquals(key, TrustChoice.parsePin("sha256/" + base64), base64);
            assertArrayEquals(key, TrustChoice.parsePin("sha256//" + base64), base64);
            assertArrayEquals(key, TrustChoice.parsePin("sha256/" + base64.replace('+', ' ')),
                    base64);
            assertArrayEquals(key, TrustChoice.parsePin("sha256/" + base64.replace("=", "")),
                    base64);
            assertArrayEquals(key, TrustChoice.parsePin("sha256//" + base64.replace("=", "")),
                    base64);
        }
    }
}
