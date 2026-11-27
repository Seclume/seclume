package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Base64;
import java.util.Random;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Base64Text decodes as the JDK's strict decoders do - the same bytes for
 * every valid text, a refusal for every invalid one - without their intrinsic.
 */
class Base64TextTest {

    @Test
    void theSameAsTheJdkForEveryLengthAndBothAlphabets() {
        Random random = new Random(64);
        for (int length = 0; length < 300; length++) {
            byte[] data = new byte[length];
            random.nextBytes(data);
            String standard = Base64.getEncoder().encodeToString(data);
            assertArrayEquals(data, Base64Text.decode(standard), standard);
            String url = Base64.getUrlEncoder().withoutPadding().encodeToString(data);
            assertArrayEquals(data, Base64Text.decodeUrl(url), url);
            String urlPadded = Base64.getUrlEncoder().encodeToString(data);
            assertArrayEquals(data, Base64Text.decodeUrl(urlPadded), urlPadded);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"A", "QUJD=", "QQ===", "QQ=A", "QU JD", "QUJD\n",
        "QU-D", "QU_D", "@@@@"})
    void whatTheStrictDecoderRefusesIsRefused(String text) {
        assertThrows(IllegalArgumentException.class, () -> Base64.getDecoder().decode(text),
                "the JDK takes " + text);
        assertThrows(IllegalArgumentException.class, () -> Base64Text.decode(text), text);
    }

    /** Stricter than the JDK: bits set beyond the last byte - no encoder writes them. */
    @ParameterizedTest
    @ValueSource(strings = {"QR==", "QR", "QUK=", "QUK"})
    void strayBitsAreRefused(String text) {
        assertThrows(IllegalArgumentException.class, () -> Base64Text.decode(text), text);
    }

    @Test
    void paddingMayBeLeftOutAsTheJdkAllows() {
        assertArrayEquals(Base64.getDecoder().decode("QQ"), Base64Text.decode("QQ"));
        assertArrayEquals(Base64.getDecoder().decode("QUI"), Base64Text.decode("QUI"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"QU+D", "QU/D", "A", "QR", "QUJ=x", "QU JD"})
    void whatTheUrlDecoderRefusesIsRefused(String text) {
        assertThrows(IllegalArgumentException.class, () -> Base64Text.decodeUrl(text), text);
    }
}
