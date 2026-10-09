package space.seclume.oracle.jdbc;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * The 11g verifier is a SHA-1 hash, so it is allowed only by name - and a
 * value that is not the name is a mistake to report, not a "no" to assume.
 */
class OraUrlLegacyVerifierTest {

    @Test
    void isOffUnlessAskedFor() {
        assertFalse(OraUrl.legacyVerifier(null));
        assertFalse(OraUrl.legacyVerifier(""));
        assertFalse(OraUrl.legacyVerifier("  "));
    }

    @Test
    void isOnFor11g() {
        assertTrue(OraUrl.legacyVerifier("11g"));
        assertTrue(OraUrl.legacyVerifier(" 11G "));
    }

    @Test
    void refusesAnythingElse() {
        assertThrows(IllegalArgumentException.class, () -> OraUrl.legacyVerifier("true"));
        assertThrows(IllegalArgumentException.class, () -> OraUrl.legacyVerifier("10g"));
    }

    @Test
    void travelsFromTheUrlIntoTheSettings() throws Exception {
        String base = "jdbc:seclume:oracle://db:1521/XE"
                + "?user=scott&provider=file&path=/run/secrets/db";
        assertFalse(OraUrl.settings(base, null).legacyVerifier11g());
        assertTrue(OraUrl.settings(base + "&legacyVerifier=11g", null).legacyVerifier11g());
        assertThrows(java.sql.SQLException.class,
                () -> OraUrl.settings(base + "&legacyVerifier=yes", null));
    }
}
