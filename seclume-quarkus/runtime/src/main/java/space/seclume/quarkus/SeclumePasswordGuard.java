package space.seclume.quarkus;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jakarta.enterprise.event.Observes;
import jakarta.inject.Singleton;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import io.quarkus.runtime.StartupEvent;
import io.quarkus.runtime.configuration.ConfigurationException;

/**
 * No password for a seclume datasource where Agroal would keep it:
 * {@code quarkus.datasource.password} would be a {@code String} in Agroal's
 * connection factory for the life of the application - in every heap dump.
 *
 * <p>Checked twice. The build refuses one in the build's configuration; the
 * start refuses one that only the running application sees - and that is
 * where a password usually is: {@code QUARKUS_DATASOURCE_PASSWORD} in the
 * container's environment, a {@code config/application.properties} beside the
 * jar, a Kubernetes secret mounted as configuration. The datasource password
 * is a runtime property, so the build never saw any of them, and the check
 * stopped only the password that someone had committed with the source.
 */
@Singleton
public class SeclumePasswordGuard {

    /** {@code quarkus.datasource.password} or {@code quarkus.datasource."name".password}. */
    static final Pattern PASSWORD = Pattern.compile(
            "quarkus\\.datasource(?:\\.(\"[^\"]+\"|[^.\"]+))?\\.password");

    /**
     * The same as an environment variable: {@code QUARKUS_DATASOURCE_PASSWORD},
     * {@code QUARKUS_DATASOURCE_USERS_PASSWORD}, and for a quoted name
     * {@code QUARKUS_DATASOURCE__USERS__PASSWORD}.
     */
    static final Pattern VARIABLE = Pattern.compile("QUARKUS_DATASOURCE(?:_(.+))?_PASSWORD");

    /** Refuses the start; the observer is the moment, the check is {@link #refused}. */
    void onStart(@Observes StartupEvent start) {
        java.util.Objects.requireNonNull(start, "the start-up event");
        refuse(ConfigProvider.getConfig());
    }

    /** {@link #refused} as an exception, or nothing. */
    public static void refuse(Config config) {
        List<String> refused = refused(config);
        if (!refused.isEmpty()) {
            throw new ConfigurationException(String.join(", ", refused) + " is set for a seclume "
                    + "datasource. Agroal would keep that password as a String for as "
                    + "long as the application runs, and it would be in every heap dump - "
                    + "the one thing seclume exists to prevent. Remove it and name the "
                    + "secret in the JDBC URL instead, e.g. provider=file&path=/run/secrets/db "
                    + "or provider=vault&address=...; the driver then reads it into "
                    + "native memory at each login.");
        }
    }

    /** The names - never the values - of the passwords set for a seclume datasource. */
    public static List<String> refused(Config config) {
        List<String> refused = new ArrayList<>();
        for (String name : config.getPropertyNames()) {
            Set<String> datasources = new LinkedHashSet<>();
            Matcher dotted = PASSWORD.matcher(name);
            Matcher variable = VARIABLE.matcher(name);
            if (dotted.matches()) {
                datasources.add(dotted.group(1) == null ? "" : dotted.group(1));
            } else if (variable.matches()) {
                datasources.addAll(variableNames(variable.group(1)));
            } else {
                continue;
            }
            for (String datasource : datasources) {
                String prefix = datasource.isEmpty() ? "quarkus.datasource"
                        : "quarkus.datasource." + datasource;
                Optional<String> kind = kind(config, prefix);
                if (kind.isPresent() && kind.get().startsWith("seclume-")) {
                    refused.add(name);
                    break;
                }
            }
        }
        return refused;
    }

    /**
     * The datasources {@code QUARKUS_DATASOURCE_<middle>_PASSWORD} may be: the
     * default one for no middle, a quoted name for {@code _NAME_}, and the
     * name in lower case with {@code _} as itself, {@code -} or {@code .}
     * otherwise - whichever has a seclume db-kind decides.
     */
    static Set<String> variableNames(String middle) {
        Set<String> names = new LinkedHashSet<>();
        if (middle == null) {
            names.add("");
            return names;
        }
        String lower = middle.toLowerCase(Locale.ROOT);
        if (lower.length() > 2 && lower.startsWith("_") && lower.endsWith("_")) {
            String inner = lower.substring(1, lower.length() - 1);
            for (String spelling : spellings(inner)) {
                names.add("\"" + spelling + "\"");
            }
            return names;
        }
        for (String spelling : spellings(lower)) {
            names.add(spelling);
            names.add("\"" + spelling + "\"");
        }
        return names;
    }

    private static Set<String> spellings(String lower) {
        Set<String> spellings = new LinkedHashSet<>();
        spellings.add(lower);
        spellings.add(lower.replace('_', '-'));
        spellings.add(lower.replace('_', '.'));
        return spellings;
    }

    private static Optional<String> kind(Config config, String prefix) {
        try {
            return config.getOptionalValue(prefix + ".db-kind", String.class);
        } catch (RuntimeException notAName) {
            return Optional.empty();
        }
    }
}
