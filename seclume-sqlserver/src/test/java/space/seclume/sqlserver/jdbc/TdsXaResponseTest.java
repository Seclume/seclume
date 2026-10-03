package space.seclume.sqlserver.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.sql.SQLException;

import org.junit.jupiter.api.Test;

class TdsXaResponseTest {
    @Test
    void invalidReturnCodesBecomeSqlExceptions() {
        for (String code : new String[] {"not-a-number", "99999999999999999999"}) {
            SQLException error = assertThrows(SQLException.class,
                    () -> TdsXaResource.check("xa_prepare", new String[] {code, ""}));
            assertEquals("25000", error.getSQLState());
        }
    }

    @Test
    void successAndReadOnlyRemainSuccessful() throws SQLException {
        TdsXaResource.check("xa_prepare", new String[] {"0", ""});
        TdsXaResource.check("xa_prepare", new String[] {"3", ""});
    }

    @Test
    void validFailureCodesRetainTheirVendorCode() {
        SQLException error = assertThrows(SQLException.class,
                () -> TdsXaResource.check("xa_prepare", new String[] {"-7", "failure"}));
        assertEquals(-7, error.getErrorCode());
        assertEquals("25000", error.getSQLState());
    }
}
