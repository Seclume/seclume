package space.seclume.quarkus;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Disposes;
import jakarta.enterprise.inject.Instance;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import io.quarkus.runtime.StartupEvent;

import space.seclume.field.FieldKeys;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/**
 * Field encryption's key ring from the Quarkus configuration, as the Spring
 * Boot starter makes it: each data key a secret provider's settings under its
 * number, or one {@code uri}, and the primary.
 *
 * <pre>
 * seclume.field-encryption.keys.1.provider=vault-transit
 * seclume.field-encryption.keys.1.address=https://vault:8200
 * seclume.field-encryption.keys.1.key-name=field-data
 * seclume.field-encryption.keys.1.ciphertext=vault:v1:...
 * seclume.field-encryption.keys.1.auth-method=kubernetes
 * seclume.field-encryption.primary=1
 * </pre>
 *
 * <p>The ring is a {@code @Singleton} to inject, built at start-up when keys
 * are configured, {@link FieldKeys#install installed} for seclume-jpa's
 * converters, and wiped when the application stops. A key that cannot be read
 * stops the start. Without keys there is no ring.
 */
@Singleton
public class SeclumeFieldKeys {

    static final String PREFIX = "seclume.field-encryption.";

    /** Builds the ring at start-up, so that a wrong key stops it there and converters find it. */
    void onStart(@Observes StartupEvent start, Instance<FieldKeys> keys) {
        if (!keys(ConfigProvider.getConfig()).isEmpty()) {
            keys.get().primary();
        }
    }

    @Produces
    @Singleton
    FieldKeys fieldKeys() {
        Config config = ConfigProvider.getConfig();
        Map<Integer, Map<String, String>> byId = keys(config);
        if (byId.isEmpty()) {
            throw new IllegalStateException("no field encryption keys are configured: "
                    + PREFIX + "keys.<number>.<provider setting>");
        }
        FieldKeys.Builder builder = FieldKeys.builder();
        Map<Integer, SecretProvider> made = new LinkedHashMap<>();
        try {
            byId.forEach((id, settings) -> {
                SecretProvider provider = settings.size() == 1 && settings.containsKey("uri")
                        ? SecretProviders.fromUri(settings.get("uri"))
                        : SecretProviders.of(settings);
                made.put(id, provider);
                builder.key(id, provider);
            });
            config.getOptionalValue(PREFIX + "primary", Integer.class).ifPresent(builder::primary);
        } catch (RuntimeException e) {
            made.values().forEach(SecretProvider::close);
            throw e;
        }
        FieldKeys keys = builder.build();
        FieldKeys.install(keys);
        return keys;
    }

    void close(@Disposes FieldKeys keys) {
        keys.close();
    }

    /** {@code keys.<n>.<setting>} by number. */
    static Map<Integer, Map<String, String>> keys(Config config) {
        Map<Integer, Map<String, String>> byId = new TreeMap<>();
        for (String name : config.getPropertyNames()) {
            if (!name.startsWith(PREFIX + "keys.")) {
                continue;
            }
            String rest = name.substring((PREFIX + "keys.").length());
            int dot = rest.indexOf('.');
            int id;
            try {
                id = dot <= 0 ? -1 : Integer.parseInt(rest.substring(0, dot));
            } catch (NumberFormatException e) {
                id = -1;
            }
            if (id <= 0) {
                throw new IllegalArgumentException(name + ": a key is " + PREFIX
                        + "keys.<number>.<provider setting>, the number positive and never "
                        + "reused - it is stored with every value");
            }
            byId.computeIfAbsent(id, ignored -> new LinkedHashMap<>()).put(rest.substring(dot + 1),
                    config.getValue(name, String.class));
        }
        return byId;
    }
}
