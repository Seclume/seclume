package space.seclume.ldap;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Base64;

import org.junit.jupiter.api.Test;

/**
 * One server, one certificate: a second registration of the same server with
 * another pin is refused - and one with the same pin is the same trust. The
 * pins used to be compared as String.valueOf of their byte arrays, so the same
 * pin given twice was refused as another.
 */
class LdapRegistrationTest {

    private static String pin(int fill) {
        byte[] digest = new byte[32];
        java.util.Arrays.fill(digest, (byte) fill);
        return "sha256/" + Base64.getEncoder().encodeToString(digest);
    }

    private static String url(String pin) {
        return "ldaps://registration.example:6361/dc=example,dc=com?user=app@example.com"
                + "&provider=file&path=/run/secrets/ldap&tlsPin=" + pin;
    }

    @Test
    void theSamePinTwiceIsTheSameTrustAndAnotherIsRefused() {
        SeclumeLdap.of(url(pin(1)));
        assertDoesNotThrow(() -> SeclumeLdap.of(url(pin(1))), "the same pin, given again");
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> SeclumeLdap.of(url(pin(2))));
        assertTrue(refused.getMessage().contains("another tlsRootCert/tlsPin"),
                refused.getMessage());
    }
}
