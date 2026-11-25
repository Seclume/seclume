package space.seclume.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

import space.seclume.internal.JdbcUrl;

/**
 * The migration copied decoded values into the seclume URL it wrote. A value
 * holding {@code &tls=off} became an option of its own; a host or a user name
 * with a {@code ?} or a line break started the query or another property.
 * Values are encoded now, and where encoding cannot help - a host, a user name
 * on its own line - the source is refused.
 */
class MigrateEncodingTest {

    private static String url(Migrate.Result result) {
        String line = result.properties().stream()
                .filter(property -> property.contains(".url="))
                .findFirst().orElseThrow();
        return line.substring(line.indexOf('=') + 1);
    }

    @Test
    void aHostOrUserWithAQueryIsRefused() {
        for (String part : new String[] {"db?tls=off", "db&tls=off", "db#x", "db\nx", "a=b"}) {
            assertThrows(IllegalArgumentException.class, () -> Migrate.plain(part, "host"), part);
        }
        assertEquals("db.example.org:5432", Migrate.plain("db.example.org:5432", "host"));
        assertEquals("app_user", Migrate.plain("app_user", "user name"));
    }

    @Test
    void valuesRoundTrip() throws Exception {
        String awkward = "billing & co = 100% \"ü\" #1";
        Migrate.Result result = Migrate.translateUrl("jdbc:postgresql://db/app?sslmode=verify-full"
                + "&ApplicationName=" + java.net.URLEncoder.encode(awkward,
                        java.nio.charset.StandardCharsets.UTF_8));
        String translated = url(result);
        Map<String, String> options = JdbcUrl.parse(translated, new java.util.Properties(),
                "jdbc:seclume:postgresql:", 5432).options();
        assertTrue(options.containsValue(awkward), translated + " -> " + options);
        assertEquals("verify-full", options.get("tls"), translated);
    }
}
