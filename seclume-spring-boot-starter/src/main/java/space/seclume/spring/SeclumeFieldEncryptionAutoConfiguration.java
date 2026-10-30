package space.seclume.spring;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;

import space.seclume.field.FieldKeys;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/**
 * Field encryption's key ring from {@code application.properties}: each data
 * key a secret provider's settings under its number, the ring a bean and
 * {@link FieldKeys#install installed}, so that seclume-jpa's converters find
 * it.
 *
 * <pre>
 * seclume.field-encryption.keys.1.provider=vault-transit
 * seclume.field-encryption.keys.1.address=https://vault:8200
 * seclume.field-encryption.keys.1.key-name=field-data
 * seclume.field-encryption.keys.1.ciphertext=vault:v1:...
 * seclume.field-encryption.keys.1.auth-method=kubernetes
 * seclume.field-encryption.keys.1.auth-role=app
 * # or one line: seclume.field-encryption.keys.2.uri=kms-decrypt?kms=aws-kms&amp;...
 * seclume.field-encryption.primary=1             # the highest number when left out
 * </pre>
 *
 * <p>The keys are read once, when the ring is made, into locked native memory;
 * the ring is wiped and uninstalled when the context closes. Without
 * {@code seclume.field-encryption.keys.*} there is no ring and nothing is
 * installed.
 */
@AutoConfiguration
@Conditional(SeclumeFieldEncryptionAutoConfiguration.KeysConfigured.class)
public class SeclumeFieldEncryptionAutoConfiguration {

    static final String PREFIX = "seclume.field-encryption";

    @Bean(destroyMethod = "close")
    @ConditionalOnMissingBean
    FieldKeys seclumeFieldKeys(Environment environment) {
        Binder binder = Binder.get(environment);
        Map<Integer, Map<String, String>> byId = keys(binder);
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
            binder.bind(PREFIX + ".primary", Integer.class).ifBound(builder::primary);
        } catch (RuntimeException e) {
            made.values().forEach(SecretProvider::close);
            throw e;
        }
        FieldKeys keys = builder.build();
        FieldKeys.install(keys);
        return keys;
    }

    /** {@code keys.<n>.<setting>}, flat as spring.mail.properties is bound, by number. */
    static Map<Integer, Map<String, String>> keys(Binder binder) {
        Map<String, String> flat = binder.bind(PREFIX + ".keys",
                Bindable.mapOf(String.class, String.class)).orElse(Map.of());
        Map<Integer, Map<String, String>> byId = new TreeMap<>();
        flat.forEach((key, value) -> {
            int dot = key.indexOf('.');
            String number = dot < 0 ? key : key.substring(0, dot);
            int id;
            try {
                id = Integer.parseInt(number);
            } catch (NumberFormatException e) {
                id = -1;
            }
            if (dot <= 0 || id <= 0) {
                throw new IllegalArgumentException(PREFIX + ".keys." + key + ": a key is "
                        + PREFIX + ".keys.<number>.<provider setting>, the number positive and "
                        + "never reused - it is stored with every value");
            }
            byId.computeIfAbsent(id, ignored -> new LinkedHashMap<>())
                    .put(key.substring(dot + 1), value);
        });
        return byId;
    }

    /** True when at least one key is configured. */
    static final class KeysConfigured implements Condition {

        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            return !Binder.get(context.getEnvironment()).bind(PREFIX + ".keys",
                    Bindable.mapOf(String.class, String.class)).orElse(Map.of()).isEmpty();
        }
    }
}
