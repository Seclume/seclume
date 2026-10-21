package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;

import org.junit.jupiter.api.Test;

/** {@code requireAuth} from the URL, under its own name and libpq's, and into the DataSource. */
class RequireAuthUrlTest {

    private static final String BASE =
            "jdbc:seclume:postgresql://db.example.com/app?user=app&provider=none";

    @Test
    void theUrlCarriesItUnderBothNames() throws Exception {
        assertFalse(SeclumeUrl.settings(BASE + "&requireAuth=scram-sha-256", null)
                .requireAuth().allows("md5"));
        assertFalse(SeclumeUrl.settings(BASE + "&require_auth=!md5", null)
                .requireAuth().allows("md5"));
        assertTrue(SeclumeUrl.settings(BASE, null).requireAuth().allows("md5"));
    }

    @Test
    void aMethodItDoesNotKnowIsAConfigurationError() {
        assertThrows(SQLException.class,
                () -> SeclumeUrl.settings(BASE + "&requireAuth=md4", null));
    }

    @Test
    void theDataSourceKeepsWhatTheUrlSaid() throws Exception {
        SeclumeDataSource source = new SeclumeDataSource();
        source.setUrl(BASE + "&requireAuth=!md5,!password");
        assertTrue(source.getRequireAuth().contains("!md5"), source.getRequireAuth());
    }
}
