package space.seclume.sqlserver.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;
import java.util.Properties;

import org.junit.jupiter.api.Test;

import space.seclume.sqlserver.tds.Kerberos;

/** How an integrated login is asked for, and which service principal it goes to. */
class KerberosOptionTest {

    @Test
    void kerberosNeedsNoUserAndNoProvider() throws SQLException {
        var settings = TdsUrl.settings(
                "jdbc:seclume:sqlserver://sql.example:1433/app?authentication=kerberos",
                new Properties());
        assertTrue(Kerberos.is(settings.secret()));
        assertEquals("MSSQLSvc/sql.example:1433", Kerberos.servicePrincipal(settings.secret()));
    }

    @Test
    void mssqlJdbcSpellingAndAnExplicitSpnAreTaken() throws SQLException {
        var settings = TdsUrl.settings("jdbc:seclume:sqlserver://10.0.0.5:1433/app"
                + "?integratedSecurity=true&authenticationScheme=JavaKerberos"
                + "&serverSpn=MSSQLSvc/sql.example:1433@EXAMPLE.COM", new Properties());
        assertEquals("MSSQLSvc/sql.example:1433@EXAMPLE.COM",
                Kerberos.servicePrincipal(settings.secret()));
    }

    @Test
    void ntlmIsRefused() {
        SQLException refused = assertThrows(SQLException.class, () -> TdsUrl.settings(
                "jdbc:seclume:sqlserver://sql.example/app?integratedSecurity=true"
                        + "&authenticationScheme=NTLM", new Properties()));
        assertTrue(refused.getMessage().contains("Kerberos"), refused.getMessage());
    }
}
