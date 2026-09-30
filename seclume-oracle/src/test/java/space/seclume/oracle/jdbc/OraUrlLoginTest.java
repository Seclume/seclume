package space.seclume.oracle.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;
import java.util.Properties;

import org.junit.jupiter.api.Test;

import space.seclume.oracle.OracleOsLogin;
import space.seclume.oracle.OracleSession;

/** {@code authentication=kerberos|nts}: no user, no secret provider - the system's login. */
class OraUrlLoginTest {

    @Test
    void kerberosAndNtsNeedNoUser() throws SQLException {
        OracleSession.Settings kerberos = OraUrl.settings(OraUrl.PREFIX
                + "//db.example:1521/FREEPDB1?authentication=kerberos", new Properties());
        assertSame(OracleOsLogin.KERBEROS, kerberos.secret());
        assertEquals("", kerberos.user());
        assertEquals("KERBEROS5", OracleOsLogin.KERBEROS.service());

        OracleSession.Settings nts = OraUrl.settings(OraUrl.PREFIX
                + "//db.example:1521/FREEPDB1?authentication=NTS", new Properties());
        assertSame(OracleOsLogin.NTS, nts.secret());
        assertEquals("", nts.user());
        assertEquals("NTS", OracleOsLogin.NTS.service());
    }

    @Test
    void anythingElseIsRefusedWithTheChoices() {
        SQLException refused = assertThrows(SQLException.class, () -> OraUrl.settings(
                OraUrl.PREFIX + "//db.example:1521/FREEPDB1?authentication=ntlm",
                new Properties()));
        assertTrue(refused.getMessage().contains("kerberos or nts"), refused.getMessage());
    }

    @Test
    void anOsLoginHasNoSecretToWrite() {
        assertThrows(IllegalStateException.class,
                () -> OracleOsLogin.NTS.writeSecret(java.lang.foreign.MemorySegment.NULL));
        assertEquals(0, OracleOsLogin.KERBEROS.maxSecretLength());
    }
}
