package space.seclume.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * One line at start that names every setting weakening what seclume does -
 * each of them reasonable on its own somewhere, none of them said anywhere:
 * a data source without a checked server certificate, the secret guard or the
 * crypto policy off, checkpoint secrets not held, an unverified secret
 * source, a lowered SCRAM floor, the debug switches.
 *
 * <pre>
 * seclume: weakened settings: datasource orders: tls not verify-full (prefer), seclume.secret-guard=off
 * </pre>
 */
@AutoConfiguration
public class SeclumeWeakenedSettingsAutoConfiguration {

    private static final System.Logger LOG =
            System.getLogger(SeclumeWeakenedSettingsAutoConfiguration.class.getName());

    @Bean
    SmartInitializingSingleton seclumeWeakenedSettings(Environment environment) {
        return () -> {
            Map<String, String> urls = Binder.get(environment)
                    .bind("seclume.datasources", Bindable.mapOf(String.class, Object.class))
                    .map(SeclumeWeakenedSettingsAutoConfiguration::urls)
                    .orElse(Map.of());
            List<String> weakened = weakened(environment::getProperty, System::getProperty, urls);
            if (!weakened.isEmpty()) {
                LOG.log(System.Logger.Level.WARNING,
                        "seclume: weakened settings: " + String.join(", ", weakened));
            }
        };
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> urls(Map<String, Object> sources) {
        Map<String, String> urls = new java.util.TreeMap<>();
        for (Map.Entry<String, Object> source : sources.entrySet()) {
            if (source.getValue() instanceof Map<?, ?> settings
                    && ((Map<String, Object>) settings).get("url") instanceof String url) {
                urls.put(source.getKey(), url);
            }
        }
        return urls;
    }

    /**
     * What weakens the defaults, from the application's settings, the JVM's
     * system properties and the data sources' URLs - in a fixed order.
     */
    static List<String> weakened(Function<String, String> setting,
            Function<String, String> systemProperty, Map<String, String> urls) {
        List<String> found = new ArrayList<>();
        for (Map.Entry<String, String> source : urls.entrySet()) {
            String tls = tlsOf(source.getValue());
            if (!"verify-full".equals(tls)) {
                found.add("datasource " + source.getKey() + ": tls not verify-full ("
                        + (tls == null ? "the driver's default" : tls) + ")");
            }
        }
        flag(found, setting, "seclume.secret-guard", "off");
        flag(found, setting, "seclume.crypto-policy.enabled", "false");
        flag(found, setting, "seclume.crypto-policy.on-start", "off");
        flag(found, systemProperty, "seclume.crac.holdSecrets", "false");
        flag(found, systemProperty, "seclume.allowUnverifiedSecretSources", "true");
        flag(found, systemProperty, "seclume.secret.process.allowed", "true");
        flag(found, systemProperty, "seclume.shamir.allowUnprotected", "true");
        flag(found, systemProperty, "seclume.debug.unsafe", "true");
        String scram = systemProperty.apply("seclume.scram.minIterations");
        if (scram != null && scram.strip().matches("[0-9]{1,8}")
                && Integer.parseInt(scram.strip()) < 4096) {
            found.add("seclume.scram.minIterations=" + scram.strip());
        }
        return found;
    }

    private static void flag(List<String> found, Function<String, String> source, String name,
            String weak) {
        String value = source.apply(name);
        if (value != null && weak.equalsIgnoreCase(value.strip())) {
            found.add(name + "=" + value.strip());
        }
    }

    /** The URL's tls option, or null when it sets none. */
    static String tlsOf(String url) {
        int question = url.indexOf('?');
        if (question < 0) {
            return null;
        }
        int hash = url.indexOf('#', question);
        String query = hash < 0 ? url.substring(question + 1) : url.substring(question + 1, hash);
        for (String pair : query.split("&")) {
            int equals = pair.indexOf('=');
            if (equals > 0 && "tls".equalsIgnoreCase(pair.substring(0, equals))) {
                return java.net.URLDecoder.decode(pair.substring(equals + 1),
                        java.nio.charset.StandardCharsets.UTF_8).toLowerCase(java.util.Locale.ROOT);
            }
        }
        return null;
    }
}
