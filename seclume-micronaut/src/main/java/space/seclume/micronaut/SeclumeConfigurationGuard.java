package space.seclume.micronaut;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
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
 *   <li>{@code datasources.<name>.password} for a data source whose URL is a
 *       seclume URL - Micronaut's Hikari would keep it as a {@code String} for
 *       the life of the application, in every heap dump;</li>
 *   <li>{@code seclume.datasources.<name>.password} - there is no such
 *       setting, and a password there is a mistake worth stopping for.</li>
 * </ul>
 *
 * <p>The message names the property and what to write instead - never its value.
 */
@Context
public class SeclumeConfigurationGuard {

    private static final Pattern HIKARI = Pattern.compile("datasources\\.([^.]+)\\.password");
    private static final Pattern OWN = Pattern.compile("seclume\\.datasources\\.([^.]+)\\.password");

    public SeclumeConfigurationGuard(Environment environment) {
        List<String> refused = new ArrayList<>();
        for (PropertySource source : environment.getPropertySources()) {
            for (String key : source) {
                String normalized = key.toLowerCase(Locale.ROOT).replace('_', '-');
                Matcher own = OWN.matcher(normalized);
                if (own.matches()) {
                    refused.add(key);
                    continue;
                }
                Matcher hikari = HIKARI.matcher(normalized);
                if (hikari.matches()) {
                    String url = environment.getProperty("datasources." + hikari.group(1) + ".url", String.class)
                            .orElse("");
                    if (url.startsWith("jdbc:seclume:")) {
                        refused.add(key);
                    }
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
}
