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

    /**
     * A pool setting's value went into its properties line as it stood: a line
     * break started another property, a backslash was Properties.load's. Only
     * what has the setting's shape is written now; the rest is reported.
     */
    @Test
    void aPoolValueOfTheWrongShapeIsReportedNotWritten() {
        Map<String, String> config = new java.util.LinkedHashMap<>();
        config.put("spring.datasource.url", "jdbc:postgresql://db/app?sslmode=verify-full");
        config.put("spring.datasource.hikari.maximum-pool-size", "10\nseclume.secret-guard=off");
        config.put("spring.datasource.hikari.idle-timeout", "30000\\u000a");
        config.put("spring.datasource.hikari.max-lifetime", "1800000");
        Migrate.Result result = Migrate.translate(config);
        String lines = String.join("\n", result.properties());
        assertTrue(!lines.contains("secret-guard") && !lines.contains("maximum-pool-size")
                && !lines.contains("idle-timeout"), lines);
        assertTrue(lines.contains("pool.max-lifetime=1800000ms"), lines);
        assertTrue(result.findings().stream().anyMatch(f -> f.text().contains("not a number")),
                result.findings().toString());
    }

    @Test
    void aTnsAliasThatWouldStartSomethingElseIsRefused() {
        for (String alias : new String[] {"orders\nseclume.secret-guard=off", "orders#x",
                "orders=x"}) {
            assertThrows(IllegalArgumentException.class,
                    () -> Migrate.translateUrl("jdbc:oracle:thin:@" + alias), alias);
        }
    }

    /** sslpassword is the client key's password in the configuration - not "handled", unsafe. */
    @Test
    void sslpasswordIsUnsafeAndDropped() {
        Migrate.Result result = Migrate.translateUrl(
                "jdbc:postgresql://db/app?sslmode=verify-full&sslpassword=x");
        assertTrue(result.findings().stream().anyMatch(f -> f.level() == Migrate.Level.UNSAFE
                && f.text().startsWith("sslpassword")), result.findings().toString());
        assertTrue(result.properties().stream().noneMatch(p -> p.contains("sslpassword")));
    }

    /**
     * The URL written is read back as the driver reads it; one whose options
     * came back otherwise than meant is refused - and the tool exits with 2.
     */
    @Test
    void aUrlThatDoesNotReadBackAsMeantIsRefused() {
        Map<String, String> meant = Map.of("tls", "verify-full");
        Migrate.readsBack("jdbc:seclume:postgresql://db/app?tls=verify-full", "postgresql", null,
                "app", meant);
        assertThrows(IllegalArgumentException.class, () -> Migrate.readsBack(
                "jdbc:seclume:postgresql://db/app?tls=verify-full&tls=off", "postgresql", null,
                "app", meant));
        assertThrows(IllegalArgumentException.class, () -> Migrate.readsBack(
                "jdbc:seclume:postgresql://db/other?tls=verify-full", "postgresql", null, "app",
                meant));
    }
}
