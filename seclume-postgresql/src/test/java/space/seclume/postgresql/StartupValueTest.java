package space.seclume.postgresql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.sql.SQLException;

import org.junit.jupiter.api.Test;

/**
 * A StartupMessage value ends at its first zero byte. A user, database or
 * applicationName with one inside began a parameter of its own -
 * {@code app\0options\0-c search_path=evil} - set by whoever chose the value.
 */
class StartupValueTest {

    @Test
    void aZeroByteInAStartupValueIsRefused() {
        for (String value : new String[] {"app\0options\0-c search_path=evil", "\0", "db\0"}) {
            SQLException refused = assertThrows(SQLException.class,
                    () -> PgSession.startupValue("user", value));
            assertEquals("08001", refused.getSQLState());
        }
    }

    @Test
    void ordinaryValuesPass() throws SQLException {
        assertEquals("app_user", PgSession.startupValue("user", "app_user"));
        assertEquals("report été", PgSession.startupValue("applicationName", "report été"));
    }
}
