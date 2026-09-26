package space.seclume.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** {@code --print-pin} connects without checking: the URL's own trust settings go. */
class PrintPinTest {

    @Test
    void theTrustSettingsAreReplacedByEncryptionWithoutChecking() {
        assertEquals("jdbc:seclume:postgresql://h:5432/db?user=u&provider=file&path=/p"
                        + "&tls=require",
                Verify.uncheckedTls("jdbc:seclume:postgresql://h:5432/db?user=u&tls=verify-full"
                        + "&tlsPin=sha256/AAAA&provider=file&path=/p&tlsRootCert=/ca.pem"));
        assertEquals("jdbc:seclume:mysql://h/db?tls=require",
                Verify.uncheckedTls("jdbc:seclume:mysql://h/db"));
        assertEquals("jdbc:seclume:oracle://h/x?user=u&tls=require#usertcp",
                Verify.uncheckedTls("jdbc:seclume:oracle://h/x?user=u#usertcp"));
    }
}
