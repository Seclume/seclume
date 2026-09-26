package space.seclume.kafka;

import java.util.LinkedHashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.spi.LoginModule;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/**
 * The JAAS login module for Kafka's SASL/SCRAM that names where the password
 * comes from instead of the password:
 *
 * <pre>
 * sasl.mechanism=SCRAM-SHA-512
 * sasl.jaas.config=space.seclume.kafka.SeclumeScramLoginModule required \
 *     username="orders" provider="file" path="/run/secrets/kafka";
 * </pre>
 *
 * <p>Kafka's own {@code ScramLoginModule} takes {@code password="..."}: the
 * password sits in the client configuration as a {@code String}, is copied
 * into the JAAS subject, and is turned into a {@code char[]} for every login.
 * All three stay on the heap. Here the options other than {@code username}
 * are a secret provider's settings - the same ones a seclume JDBC URL takes
 * ({@code file}, {@code vault}, {@code aws-secrets-manager}, ...) - and the
 * secret is read by {@link ScramClient} into native memory for the one step
 * that needs it, and wiped after. It is read again at every login, so a
 * rotated password takes effect without a restart.
 *
 * <p>{@code password} is refused rather than accepted: a configuration that
 * names it has already put the secret on the heap.
 */
public final class SeclumeScramLoginModule implements LoginModule {

    private static final String USERNAME = "username";

    /** For JAAS, which makes one per login context. */
    public SeclumeScramLoginModule() {
    }

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler,
                           Map<String, ?> sharedState, Map<String, ?> options) {
        ScramProvider.install();
        Object username = options.get(USERNAME);
        if (!(username instanceof String name) || name.isEmpty()) {
            throw new IllegalArgumentException(
                    "SeclumeScramLoginModule needs username=\"...\" in sasl.jaas.config");
        }
        if (options.containsKey("tokenauth")) {
            throw new IllegalArgumentException("tokenauth: a delegation token is a secret Kafka "
                    + "hands out itself - use Kafka's ScramLoginModule for it");
        }
        Map<String, String> settings = new LinkedHashMap<>();
        for (Map.Entry<String, ?> option : options.entrySet()) {
            if (!option.getKey().equals(USERNAME) && option.getValue() instanceof String value) {
                settings.put(option.getKey(), value);
            }
        }
        // Refuses password=..., and names what it takes instead.
        SecretProvider provider = SecretProviders.of(settings);
        subject.getPublicCredentials().add(name);
        subject.getPublicCredentials().add(new ScramSecret(provider));
    }

    @Override
    public boolean login() {
        return true;
    }

    @Override
    public boolean commit() {
        return true;
    }

    @Override
    public boolean abort() {
        return false;
    }

    @Override
    public boolean logout() {
        return true;
    }
}
