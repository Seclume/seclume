package space.seclume.micronaut;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.micronaut.context.annotation.Context;
import io.micronaut.context.env.Environment;
import io.micronaut.context.env.PropertySource;

/**
 * Refuses to start with a password in the configuration where seclume would
 * otherwise have kept it off the heap:
 *
 * <ul>
 *   <li>{@code datasources.<name>.password} - or a password among the data
 *       source's further keys, such as
 *       {@code datasources.<name>.data-source-properties.password} - for a
 *       data source whose URL is a seclume URL: Micronaut's Hikari would keep
 *       it as a {@code String} for the life of the application, in every heap
 *       dump;</li>
 *   <li>{@code seclume.datasources.<name>.password} - there is no such
 *       setting, and a password there is a mistake worth stopping for.</li>
 * </ul>
 *
 * <p>Both as properties and as environment variables
 * ({@code DATASOURCES_DEFAULT_PASSWORD}): Micronaut reads an environment
 * variable as the property it spells, so it is the same password on the heap.
 *
 * <p>The message names the property and what to write instead - never its value.
 */
@Context
public class SeclumeConfigurationGuard {

    private static final Pattern HIKARI = Pattern.compile("datasources\\.([^.]+)\\.(?:.+\\.)?password");
    private static final Pattern OWN = Pattern.compile("seclume\\.datasources\\.([^.]+)\\.(?:.+\\.)?password");
    /** The same, as an environment variable; the data source's name may hold {@code _} itself. */
    private static final Pattern OWN_ENV = Pattern.compile("seclume_datasources_.+_password");

    public SeclumeConfigurationGuard(Environment environment) {
        List<String> refused = new ArrayList<>();
        for (PropertySource source : environment.getPropertySources()) {
            boolean variables = source.getConvention() == PropertySource.PropertyConvention.ENVIRONMENT_VARIABLE;
            for (String key : source) {
                if (variables ? refusedVariable(environment, key) : refusedProperty(environment, key)) {
                    refused.add(key);
                }
            }
        }
        if (!refused.isEmpty()) {
            throw new IllegalStateException("a password stands in the configuration (" + String.join(", ", refused)
                    + "): it would be a String on the heap for the life of the application. Remove it and "
                    + "name where the secret comes from in the URL instead - provider=file&path=/run/secrets/db, "
                    + "provider=vault&..., provider=kms-decrypt&...");
        }
    }

    private static boolean refusedProperty(Environment environment, String key) {
        String normalized = key.toLowerCase(Locale.ROOT).replace('_', '-');
        if (OWN.matcher(normalized).matches()) {
            return true;
        }
        Matcher hikari = HIKARI.matcher(normalized);
        return hikari.matches() && seclumeUrl(environment, Set.of(hikari.group(1)));
    }

    /**
     * {@code DATASOURCES_ORDERS_DB_PASSWORD}: the data source may be
     * {@code orders}, {@code orders-db} or {@code orders.db} - refused if any
     * of them has a seclume URL.
     */
    private static boolean refusedVariable(Environment environment, String key) {
        String lower = key.toLowerCase(Locale.ROOT);
        if (OWN_ENV.matcher(lower).matches()) {
            return true;
        }
        if (!lower.startsWith("datasources_") || !lower.endsWith("_password")
                || lower.length() <= "datasources__password".length()) {
            return false;
        }
        String middle = lower.substring("datasources_".length(), lower.length() - "_password".length());
        Set<String> names = new LinkedHashSet<>();
        String[] parts = middle.split("_");
        // Every prefix of the parts is a candidate name, joined as - or _ (a
        // dotted name cannot be one: a data source name has no dots).
        for (int i = 1; i <= parts.length; i++) {
            String[] head = Arrays.copyOf(parts, i);
            names.add(String.join("-", head));
            names.add(String.join("_", head));
        }
        return seclumeUrl(environment, names);
    }

    private static boolean seclumeUrl(Environment environment, Set<String> names) {
        for (String name : names) {
            String url = environment.getProperty("datasources." + name + ".url", String.class).orElse("");
            if (url.regionMatches(true, 0, "jdbc:seclume:", 0, "jdbc:seclume:".length())) {
                return true;
            }
        }
        return false;
    }
}
