package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.impl.NoOpLog;

import org.junit.jupiter.api.Test;

import org.springframework.boot.logging.DeferredLogFactory;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

/**
 * The two things the post-processor does, and the one thing it must never do.
 */
class SeclumeEnvironmentPostProcessorTest {

    /** Everything the guard logs, so a test can read it without a log file. */
    private final List<String> warnings = new ArrayList<>();

    private final DeferredLogFactory logs = new DeferredLogFactory() {
        @Override
        public Log getLog(Supplier<Log> destination) {
            return new NoOpLog() {
                @Override
                public void warn(Object message) {
                    warnings.add(String.valueOf(message));
                }
            };
        }
    };

    private StandardEnvironment environmentOf(Map<String, Object> properties) {
        StandardEnvironment environment = new StandardEnvironment();
        // The system property and environment variable sources of a real JVM
        // would drag in whatever the machine happens to have - including, on a
        // developer's box, real credentials. The guard tests have to see only
        // what they put there themselves.
        environment.getPropertySources().remove(
                StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        environment.getPropertySources().remove(
                StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        environment.getPropertySources().addFirst(new MapPropertySource("test", properties));
        return environment;
    }

    private void run(StandardEnvironment environment) {
        new SeclumeEnvironmentPostProcessor(logs).postProcessEnvironment(environment, null);
    }

    // --------------------------------------------------------- secret-uri --

    @Test
    void aFileUriBecomesTheTwoSettingsTheStarterReads() {
        StandardEnvironment environment = environmentOf(Map.of(
                "seclume.datasources.main.url", "jdbc:seclume:postgresql://db:5432/app",
                "seclume.datasources.main.secret-uri", "file:/run/secrets/db"));
        run(environment);

        assertEquals("file", environment.getProperty("seclume.datasources.main.secret.provider"));
        assertEquals("/run/secrets/db",
                environment.getProperty("seclume.datasources.main.secret.path"));
    }

    @Test
    void aQueryBecomesTheRemainingSettings() {
        Map<String, String> settings =
                SeclumeEnvironmentPostProcessor.parse(
                        "env-file:/run/secrets/app.env?key=DB_PASSWORD&max-length=512", "main");

        assertEquals("env-file", settings.get("provider"));
        assertEquals("/run/secrets/app.env", settings.get("path"));
        assertEquals("DB_PASSWORD", settings.get("key"));
        assertEquals("512", settings.get("max-length"));
    }

    /** A provider with no path at all - the colon would be noise, so it is optional. */
    @Test
    void aProviderWithoutAPathNeedsNoColon() {
        Map<String, String> settings =
                SeclumeEnvironmentPostProcessor.parse("credential-manager?target=AppDb", "main");

        assertEquals("credential-manager", settings.get("provider"));
        assertEquals("AppDb", settings.get("target"));
        assertFalse(settings.containsKey("path"), "there was no path to record");
    }

    /**
     * For {@code encrypted} the leading path is the ciphertext, not "the path".
     *
     * <p>That provider has two sources, and the one worth spelling out in the
     * line is the key. The ciphertext is almost always a file, so that half is
     * filled in.
     */
    @Test
    void anEncryptedUriFillsInTheCiphertextSource() {
        Map<String, String> settings = SeclumeEnvironmentPostProcessor.parse(
                "encrypted:/run/secrets/db.enc?key-provider=dpapi&key-path=/run/secrets/kek"
                + "&aad=main", "main");

        assertEquals("encrypted", settings.get("provider"));
        assertEquals("file", settings.get("cipher-provider"));
        assertEquals("/run/secrets/db.enc", settings.get("cipher-path"));
        assertEquals("dpapi", settings.get("key-provider"));
        assertEquals("/run/secrets/kek", settings.get("key-path"));
        assertEquals("main", settings.get("aad"));
        assertFalse(settings.containsKey("path"), "the path went to cipher-path");
    }

    @Test
    void severalDataSourcesAreExpandedIndependently() {
        StandardEnvironment environment = environmentOf(Map.of(
                "seclume.datasources.main.secret-uri", "file:/run/secrets/main",
                "seclume.datasources.reporting.secret-uri", "file:/run/secrets/reporting"));
        run(environment);

        assertEquals("/run/secrets/main",
                environment.getProperty("seclume.datasources.main.secret.path"));
        assertEquals("/run/secrets/reporting",
                environment.getProperty("seclume.datasources.reporting.secret.path"));
    }

    /**
     * Both ways at once is an error, not a precedence rule.
     *
     * <p>A secret configuration where half the settings come from one place and
     * half from another is the kind of thing that works in the test environment
     * and picks the wrong key in production.
     */
    @Test
    void configuringItBothWaysIsRefused() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("seclume.datasources.main.secret-uri", "file:/run/secrets/db");
        properties.put("seclume.datasources.main.secret.provider", "dpapi");

        IllegalStateException refused = assertThrows(IllegalStateException.class,
                () -> run(environmentOf(properties)));
        assertTrue(refused.getMessage().contains("configured twice"), refused.getMessage());
        assertTrue(refused.getMessage().contains("secret.provider"), refused.getMessage());
    }

    @Test
    void anEmptyProviderIsRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> SeclumeEnvironmentPostProcessor.parse(":/run/secrets/db", "main"));
    }

    @Test
    void aSettingWithoutAValueIsRefused() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> SeclumeEnvironmentPostProcessor.parse("file:/x?key", "main"));
        assertTrue(refused.getMessage().contains("without a value"), refused.getMessage());
    }

    @Test
    void nothingIsAddedWhenNobodyUsesIt() {
        StandardEnvironment environment = environmentOf(Map.of(
                "seclume.datasources.main.secret.provider", "file",
                "seclume.datasources.main.secret.path", "/run/secrets/db"));
        run(environment);

        assertNull(environment.getPropertySources()
                .get(SeclumeEnvironmentPostProcessor.EXPANDED));
    }

    // -------------------------------------------------------------- guard --

    @Test
    void aPlaintextPasswordIsNamed() {
        run(environmentOf(Map.of("spring.mail.password", "hunter2")));

        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).contains("spring.mail.password"), warnings.get(0));
    }

    /** The one thing it must never do. */
    @Test
    void theValueIsNeverLogged() {
        run(environmentOf(Map.of(
                "spring.mail.password", "hunter2",
                "app.client-secret", "s3cr3t-value")));

        String reported = String.join("\n", warnings);
        assertFalse(reported.contains("hunter2"), reported);
        assertFalse(reported.contains("s3cr3t-value"), reported);
        assertTrue(reported.contains("spring.mail.password"));
        assertTrue(reported.contains("app.client-secret"));
    }

    @Test
    void whatIsOnTheAllowListIsNotReported() {
        run(environmentOf(Map.of(
                "spring.mail.password", "hunter2",
                "seclume.secret-guard-allow", "spring.mail.password")));

        assertTrue(warnings.isEmpty(), String.join("\n", warnings));
    }

    @Test
    void failTurnsTheWarningIntoARefusalToStart() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("spring.mail.password", "hunter2");
        properties.put("seclume.secret-guard", "fail");

        IllegalStateException refused = assertThrows(IllegalStateException.class,
                () -> run(environmentOf(properties)));
        assertTrue(refused.getMessage().contains("spring.mail.password"));
        assertFalse(refused.getMessage().contains("hunter2"), "not even when it aborts");
    }

    @Test
    void offMeansOff() {
        run(environmentOf(Map.of(
                "spring.mail.password", "hunter2",
                "seclume.secret-guard", "off")));

        assertTrue(warnings.isEmpty());
    }

    /**
     * An unresolved placeholder is a reference, not a password.
     *
     * <p>Reporting it would train people to ignore the warning, which is how a
     * guard stops working without anybody switching it off.
     */
    @Test
    void aPlaceholderIsNotAFinding() {
        run(environmentOf(Map.of("spring.mail.password", "${MAIL_PASSWORD}")));

        assertTrue(warnings.isEmpty(), String.join("\n", warnings));
    }

    @Test
    void anEmptyValueIsNotAFinding() {
        run(environmentOf(Map.of("spring.mail.password", "   ")));

        assertTrue(warnings.isEmpty(), String.join("\n", warnings));
    }

    /**
     * Seclume's own settings are configuration, not credentials.
     *
     * <p>{@code secret.provider} and {@code secret.path} say where a secret
     * lives. If the guard flagged those, it would fire on every correctly
     * configured application there is.
     */
    @Test
    void seclumesOwnSettingsAreNotFindings() {
        run(environmentOf(Map.of(
                "seclume.datasources.main.secret.provider", "file",
                "seclume.datasources.main.secret.path", "/run/secrets/db",
                "seclume.datasources.main.secret.key", "DB_PASSWORD")));

        assertTrue(warnings.isEmpty(), String.join("\n", warnings));
    }

    /** A name that merely contains the word is not a credential. */
    @Test
    void tokenUriAndFriendsAreNotFindings() {
        run(environmentOf(Map.of(
                "spring.security.oauth2.client.provider.x.token-uri", "https://example.invalid",
                "app.password-policy", "strict",
                "app.secretariat", "room 12")));

        assertTrue(warnings.isEmpty(), String.join("\n", warnings));
    }

    // ------------------------------------------------------- registration --

    /**
     * That Spring will actually find it.
     *
     * <p>Every test above calls the class directly, so all eighteen would stay
     * green with a registration file that Spring never reads - and the feature
     * would simply not happen. The key is compared against
     * {@code EnvironmentPostProcessor.class.getName()} rather than a literal,
     * because the interface has already moved once: it was
     * {@code org.springframework.boot.env.EnvironmentPostProcessor} before
     * Spring Boot 4. If it moves again this fails, which is the point.
     */
    @Test
    void springFactoriesNamesThisClassUnderTheRightKey() throws Exception {
        String key = org.springframework.boot.EnvironmentPostProcessor.class.getName();
        String expected = SeclumeEnvironmentPostProcessor.class.getName();

        java.util.Enumeration<java.net.URL> resources =
                getClass().getClassLoader().getResources("META-INF/spring.factories");
        boolean registered = false;
        while (resources.hasMoreElements()) {
            java.util.Properties factories = new java.util.Properties();
            try (java.io.InputStream in = resources.nextElement().openStream()) {
                factories.load(in);
            }
            String value = factories.getProperty(key);
            if (value != null && value.contains(expected)) {
                registered = true;
            }
        }
        assertTrue(registered,
                "no META-INF/spring.factories on the class path lists " + expected
                + " under " + key);
    }
}
