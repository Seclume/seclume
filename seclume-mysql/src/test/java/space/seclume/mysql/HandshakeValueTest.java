package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.sql.SQLException;

import org.junit.jupiter.api.Test;

/**
 * A HandshakeResponse field ends at its first zero byte. A user or database
 * with one inside shifted every field after it - the auth response, the
 * plugin name - by bytes whoever chose the value wrote.
 */
class HandshakeValueTest {

    @Test
    void aZeroByteInUserOrDatabaseIsRefused() {
        for (String value : new String[] {"app\0mysql_clear_password", "\0", "shop\0"}) {
            SQLException refused = assertThrows(SQLException.class,
                    () -> MySession.handshakeValue("user", value));
            assertEquals("08001", refused.getSQLState());
        }
    }

    @Test
    void ordinaryValuesPass() throws SQLException {
        assertEquals("app_user", MySession.handshakeValue("user", "app_user"));
    }
}
