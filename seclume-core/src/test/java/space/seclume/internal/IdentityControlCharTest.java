package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.junit.jupiter.api.Test;

/**
 * user, database and application name go into every driver's login as text,
 * framed by a NUL, a length or a key=value list. A control character in one
 * ended its field or started another - #36 to #39, fixed one driver at a
 * time. The URL parse refuses it now, for all of them, before a socket opens.
 */
class IdentityControlCharTest {

    private static JdbcUrl.Parsed parse(String url, Properties properties) {
        return JdbcUrl.parse(url, properties, "jdbc:seclume:postgresql:", 5432);
    }

    @Test
    void aControlCharacterInAnIdentityIsRefused() {
        for (String url : new String[] {
            "jdbc:seclume:postgresql://db/app?user=app%00replication",
            "jdbc:seclume:postgresql://db/app\nother?user=app",
            "jdbc:seclume:postgresql://db/app?applicationName=x%0D%0Aoptions%3D-c",
            "jdbc:seclume:postgresql://db/app?application-name=x%1F"}) {
            IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                    () -> parse(url, new Properties()), url);
            assertFalse(refused.getMessage().contains("replication"), "the value stays out");
        }
        Properties fromProperties = new Properties();
        fromProperties.setProperty("user", "app\u0000x");
        assertThrows(IllegalArgumentException.class,
                () -> parse("jdbc:seclume:postgresql://db/app", fromProperties));
    }

    @Test
    void ordinaryIdentitiesAndOtherOptionsPass() {
        JdbcUrl.Parsed parsed = parse("jdbc:seclume:postgresql://db/app?user=app_user"
                + "&applicationName=billing%20service&options=-c%20search_path%3Da", new Properties());
        assertEquals("app", parsed.database());
        assertEquals("app_user", parsed.option("user"));
        assertTrue(parsed.option("applicationName").contains(" "));
    }
}
