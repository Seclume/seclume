package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * SSPI on Windows, without a domain: the library binds, and a login to a
 * service no KDC knows fails with a message that says why. The login itself
 * is shown against a real domain - see {@code seclume-sqlserver/proof/sspi.ps1}.
 */
class SspiTest {

    @Test
    void windowsHasIt() {
        Assumptions.assumeTrue(Platform.isWindows());
        assertTrue(Sspi.available());
        assertTrue(Gssapi.available());
    }

    @Test
    void aServiceNobodyKnowsIsRefusedWithAReason() {
        Assumptions.assumeTrue(Sspi.available());
        IllegalStateException refused = assertThrows(IllegalStateException.class, () -> {
            try (Gssapi.Context context =
                         Gssapi.initiatePrincipal("MSSQLSvc/nothing.seclume.invalid:1433")) {
                context.step(null, 0, 0);
            }
        });
        assertTrue(refused.getMessage().contains("Kerberos"), refused.getMessage());
        assertTrue(refused.getMessage().contains("SEC_E_") || refused.getMessage().contains("0x"),
                refused.getMessage());
    }

    @Test
    void statusCodesAreNamed() {
        assertEquals("SEC_E_TARGET_UNKNOWN: the KDC does not know that service principal (SPN) "
                + "(0x80090303)", Sspi.describe(0x80090303));
        assertEquals("0x80091234", Sspi.describe(0x80091234));
    }
}
