package space.seclume.micronaut;

import java.util.Map;
import java.util.TreeMap;

import io.micronaut.context.annotation.Context;
import io.micronaut.context.env.Environment;
import jakarta.annotation.PreDestroy;

import space.seclume.field.FieldKeys;
import space.seclume.secret.SecretProviders;

/**
 * The field encryption key ring from the configuration, built when the
 * application starts - a key that cannot be read stops it there - installed
 * for the JPA converters, and wiped when the context closes:
 *
 * <pre>
 *   seclume:
 *     field-encryption:
 *       keys:
 *         1:
 *           provider: vault-transit
 *           ...
 *         2:
 *           uri: kms-decrypt?kms=aws-kms&amp;key=alias/orders&amp;...
 *       primary: 2
 * </pre>
 *
 * <p>Without keys configured there is no ring, and nothing is installed.
 * Inject {@link FieldKeys} where it is used; see {@link SeclumeFieldKeysFactory}.
 */
@Context
public class SeclumeFieldEncryption {

    static final String PREFIX = "seclume.field-encryption";

    private final FieldKeys keys;

    public SeclumeFieldEncryption(Environment environment) {
        Map<Integer, Map<String, String>> byId = keys(environment.getProperties(PREFIX + ".keys"));
        if (byId.isEmpty()) {
            this.keys = null;
            return;
        }
        FieldKeys.Builder builder = FieldKeys.builder();
        for (Map.Entry<Integer, Map<String, String>> key : byId.entrySet()) {
            Map<String, String> settings = key.getValue();
            String uri = settings.get("uri");
            builder.key(key.getKey(), uri != null ? SecretProviders.fromUri(uri) : SecretProviders.of(settings));
        }
        environment.getProperty(PREFIX + ".primary", Integer.class).ifPresent(builder::primary);
        this.keys = builder.build();
        FieldKeys.install(keys);
    }

    /** The configured keys, by number: {@code 1.provider -> file} becomes {@code 1 -> {provider=file}}. */
    static Map<Integer, Map<String, String>> keys(Map<String, Object> properties) {
        Map<String, Object> flat = new TreeMap<>();
        flatten("", properties, flat);
        Map<Integer, Map<String, String>> byId = new TreeMap<>();
        for (Map.Entry<String, Object> entry : flat.entrySet()) {
            String key = entry.getKey();
            int dot = key.indexOf('.');
            if (dot <= 0) {
                throw new IllegalArgumentException(PREFIX + ".keys." + key + " is not a key's setting - "
                        + "use " + PREFIX + ".keys.<number>.<provider setting>");
            }
            int id;
            try {
                id = Integer.parseInt(key.substring(0, dot));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(PREFIX + ".keys." + key + ": a key is named by its "
                        + "number, not '" + key.substring(0, dot) + "'", e);
            }
            byId.computeIfAbsent(id, ignored -> new TreeMap<>())
                    .put(key.substring(dot + 1), String.valueOf(entry.getValue()));
        }
        return byId;
    }

    /** Nested maps - as some property sources give them - as dotted keys. */
    private static void flatten(String prefix, Map<?, ?> nested, Map<String, Object> flat) {
        for (Map.Entry<?, ?> entry : nested.entrySet()) {
            String key = prefix + entry.getKey();
            if (entry.getValue() instanceof Map<?, ?> inner) {
                flatten(key + ".", inner, flat);
            } else {
                flat.put(key, entry.getValue());
            }
        }
    }

    /** The ring, or {@code null} when no keys are configured. */
    public FieldKeys keys() {
        return keys;
    }

    @PreDestroy
    void close() {
        if (keys != null) {
            keys.close();
        }
    }
}
