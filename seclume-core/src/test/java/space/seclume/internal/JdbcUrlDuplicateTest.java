package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.junit.jupiter.api.Test;

/**
 * A key the URL gives twice is refused. The last one used to win, so
 * {@code tls=verify-full&...&tls=off} was off: whatever appended an option to
 * an application's URL could turn a protection off. Properties still override
 * the URL - that is deliberate and one value each.
 */
class JdbcUrlDuplicateTest {

    private static final String PREFIX = "jdbc:seclume:postgresql:";

    private static JdbcUrl.Parsed parse(String query, Properties properties) {
        return JdbcUrl.parse(PREFIX + "//db.example.com:5432/app?" + query, properties, PREFIX,
                5432);
    }

    @Test
    void aSecurityOptionGivenTwiceIsRefused() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> parse("user=app&tls=verify-full&provider=file&path=/s&tls=off", null));
        assertTrue(refused.getMessage().contains("tls twice"), refused.getMessage());
        assertFalse(refused.getMessage().contains("verify-full"), "a value in the message");
    }

    @Test
    void keysCompareAsTheDriversReadThem() {
        assertThrows(IllegalArgumentException.class,
                () -> parse("tlsPin=sha256/AAAA&tls-pin=sha256/BBBB", null));
        assertThrows(IllegalArgumentException.class,
                () -> parse("user=app&USER=postgres", null));
        assertThrows(IllegalArgumentException.class,
                () -> parse("path=/run/secrets/a&path=/tmp/b", null));
    }

    @Test
    void eachKeyOnceIsTakenAndPropertiesStillOverride() {
        Properties override = new Properties();
        override.setProperty("tls", "verify-full");
        JdbcUrl.Parsed parsed = parse("user=app&tls=require&provider=file&path=/s", override);
        assertEquals("verify-full", parsed.option("tls"));
        assertEquals("app", parsed.option("user"));
    }
}
