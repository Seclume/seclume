package space.seclume.spring;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;

import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.logging.DeferredLogFactory;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;

/**
 * Two things that have to happen before anything is bound.
 *
 * <p>Both work on the {@code Environment} and neither ever touches a secret.
 * That distinction is the whole reason this class is allowed to exist: a
 * post-processor that put a decrypted password into the {@code Environment}
 * would undo the library. Property values are {@code String}s held in a
 * {@code PropertySource} for the life of the application - not a value that is
 * briefly on the heap, but one that never leaves it. So what travels here is
 * the <b>description</b> of where a secret lives, never the secret.
 *
 * <h2>1. {@code secret-uri} - one line instead of four</h2>
 *
 * <pre>
 *   seclume.datasources.main.secret-uri=file:/run/secrets/db
 *   seclume.datasources.main.secret-uri=env-file:/run/secrets/app.env?key=DB_PASSWORD
 *   seclume.datasources.main.secret-uri=credential-manager?target=AppDb
 *   seclume.datasources.main.secret-uri=\
 *       encrypted:/run/secrets/db.enc?key-provider=dpapi&amp;key-path=/run/secrets/kek&amp;aad=main
 * </pre>
 *
 * <p>expands to exactly the {@code secret.*} keys the starter reads anyway. The
 * gain is not the saved typing: it is that a deployment has <b>one</b>
 * environment variable per data source instead of four that have to agree, and
 * that the spelling is now the same as in the JDBC URL, which has always taken
 * {@code ?provider=file&amp;path=...}.
 *
 * <p>Giving both {@code secret-uri} and {@code secret.*} for the same data
 * source is an error rather than a precedence rule. A half-overridden secret
 * configuration is the kind of mistake that is noticed in production.
 *
 * <h2>2. The guard - plaintext passwords, named</h2>
 *
 * <p>{@code SecretProviders} already refuses an inline password in seclume's
 * own settings. This sees the whole {@code Environment}, so it also finds the
 * ones in {@code spring.mail.password} and in whatever an application invented
 * for itself.
 *
 * <p>It <b>reports</b>; it does not forbid. For a good part of what it finds
 * there is no off-heap alternative at all - {@code spring.mail.password} ends
 * up a {@code String} in Jakarta Mail no matter where it came from - and a
 * guard that blocks what cannot be fixed is switched off after the second
 * failed start, at which point it protects nothing.
 *
 * <pre>
 *   seclume.secret-guard=warn        # warn (default), fail, off
 *   seclume.secret-guard-allow=spring.mail.password, app.legacy.api-key
 * </pre>
 *
 * <p>The allow-list is the point of the whole thing. It turns "we have three
 * plaintext passwords and nobody knows" into "we have three, they are written
 * down, and somebody decided on each" - and it is meant to get shorter.
 *
 * <p><b>Property names are logged, never values.</b> A guard that printed what
 * it found would be the leak it is looking for.
 *
 * <p>What it cannot see: a password the application reads from a file itself
 * and passes around. The {@code Environment} is not the heap. For that there is
 * {@code seclume-heapcheck}, which looks at the running process; the two
 * complement each other and neither replaces the other.
 */
public class SeclumeEnvironmentPostProcessor implements EnvironmentPostProcessor {

    /** Where the expanded keys are put, above the ones the user wrote. */
    static final String EXPANDED = "seclume-secret-uri";

    private static final String PREFIX = "seclume.datasources.";
    private static final String URI_KEY = ".secret-uri";

    private static final String GUARD = "seclume.secret-guard";
    private static final String GUARD_ALLOW = "seclume.secret-guard-allow";

    /**
     * Property name endings that mean "this is probably a credential".
     *
     * <p>Deliberately narrow. {@code token} is not here: half the OAuth
     * configuration keys end in it ({@code token-uri}, {@code token-type}), and
     * a guard that cries wolf is read once and ignored afterwards.
     */
    private static final List<String> SUSPECT = List.of(
            "password", "passwd", "secret", "private-key", "privatekey", "client-secret");

    private final Log log;

    public SeclumeEnvironmentPostProcessor(DeferredLogFactory logs) {
        this.log = logs.getLog(SeclumeEnvironmentPostProcessor.class);
    }

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment,
            SpringApplication application) {
        expandSecretUris(environment);
        guard(environment);
    }

    // ---------------------------------------------------------------- 1 ----

    private void expandSecretUris(ConfigurableEnvironment environment) {
        Map<String, Object> expanded = new LinkedHashMap<>();
        for (String name : dataSourceNames(environment)) {
            String uri = environment.getProperty(PREFIX + name + URI_KEY);
            if (uri == null || uri.isBlank()) {
                continue;
            }
            String base = PREFIX + name + ".secret.";
            rejectMixedConfiguration(environment, name, base);
            for (Map.Entry<String, String> setting : parse(uri, name).entrySet()) {
                expanded.put(base + setting.getKey(), setting.getValue());
            }
        }
        if (!expanded.isEmpty()) {
            environment.getPropertySources()
                    .addFirst(new MapPropertySource(EXPANDED, expanded));
        }
    }

    /**
     * The settings a {@code secret-uri} stands for.
     *
     * <p>Package-private so the parser can be tested without an application
     * context: the shapes it has to get right are worth more tests than
     * starting Spring ten times would be worth the seconds.
     */
    static Map<String, String> parse(String uri, String dataSource) {
        // One parser for every place a secret URI is read - see SecretProviders.
        try {
            return space.seclume.secret.SecretProviders.settingsOf(uri);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("secret-uri of data source '" + dataSource
                    + "': " + e.getMessage(), e);
        }
    }

    private void rejectMixedConfiguration(ConfigurableEnvironment environment, String dataSource,
            String base) {
        List<String> both = new ArrayList<>();
        for (PropertySource<?> source : environment.getPropertySources()) {
            if (EXPANDED.equals(source.getName())
                    || !(source instanceof EnumerablePropertySource<?> enumerable)) {
                continue;
            }
            for (String property : enumerable.getPropertyNames()) {
                if (property.startsWith(base)) {
                    both.add(property);
                }
            }
        }
        if (!both.isEmpty()) {
            throw new IllegalStateException(
                    "data source '" + dataSource + "' is configured twice: secret-uri and "
                    + both + ". Use one or the other - a secret configuration that is half "
                    + "overridden is the kind of mistake that is found in production.");
        }
    }

    private Set<String> dataSourceNames(ConfigurableEnvironment environment) {
        Set<String> names = new LinkedHashSet<>();
        for (PropertySource<?> source : environment.getPropertySources()) {
            if (!(source instanceof EnumerablePropertySource<?> enumerable)) {
                continue;
            }
            for (String property : enumerable.getPropertyNames()) {
                if (!property.startsWith(PREFIX)) {
                    continue;
                }
                int dot = property.indexOf('.', PREFIX.length());
                if (dot > 0) {
                    names.add(property.substring(PREFIX.length(), dot));
                }
            }
        }
        return names;
    }

    // ---------------------------------------------------------------- 2 ----

    private void guard(ConfigurableEnvironment environment) {
        String mode = environment.getProperty(GUARD, "warn").trim().toLowerCase(Locale.ROOT);
        if ("off".equals(mode) || "false".equals(mode)) {
            return;
        }
        Set<String> allowed = allowList(environment);
        List<String> found = new ArrayList<>();

        for (PropertySource<?> source : environment.getPropertySources()) {
            if (!(source instanceof EnumerablePropertySource<?> enumerable)) {
                continue;
            }
            for (String property : enumerable.getPropertyNames()) {
                if (!isSuspect(property) || allowed.contains(property)) {
                    continue;
                }
                Object value = source.getProperty(property);
                if (looksLikeAValue(value)) {
                    found.add(property + " (from " + source.getName() + ")");
                }
            }
        }

        if (found.isEmpty()) {
            return;
        }
        String message = "seclume: " + found.size() + " configuration "
                + (found.size() == 1 ? "property holds a secret" : "properties hold secrets")
                + " in plain text. They are Strings in the Environment and stay on the heap for "
                + "the lifetime of this application:\n  - " + String.join("\n  - ", found)
                + "\nMove what you can to a seclume secret source; for the rest, list the "
                + "property in " + GUARD_ALLOW + " so the exception is a decision and not an "
                + "oversight.";
        if ("fail".equals(mode)) {
            throw new IllegalStateException(message);
        }
        log.warn(message);
    }

    private Set<String> allowList(ConfigurableEnvironment environment) {
        Set<String> allowed = new LinkedHashSet<>();
        String configured = environment.getProperty(GUARD_ALLOW);
        if (configured != null) {
            for (String entry : configured.split(",")) {
                if (!entry.isBlank()) {
                    allowed.add(entry.trim());
                }
            }
        }
        return allowed;
    }

    private static boolean isSuspect(String property) {
        String lower = property.toLowerCase(Locale.ROOT);
        for (String ending : SUSPECT) {
            if (lower.endsWith("." + ending) || lower.equals(ending)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether there is anything there worth reporting.
     *
     * <p>An unresolved placeholder is not a password - it is a reference to one
     * somewhere else, and reporting it would train people to ignore the
     * warning.
     */
    private static boolean looksLikeAValue(Object value) {
        if (!(value instanceof String text)) {
            return value != null;
        }
        String trimmed = text.trim();
        return !trimmed.isEmpty() && !(trimmed.startsWith("${") && trimmed.endsWith("}"));
    }
}
