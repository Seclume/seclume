package space.seclume.kafka;

import java.security.Provider;
import java.security.Security;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import space.seclume.crypto.HashAlgorithm;

/**
 * Puts {@link ScramClient} in front of every other SCRAM client in this JVM -
 * for the logins that were configured through {@link SeclumeScramLoginModule}
 * only. A login configured any other way finds no {@link ScramSecret} in its
 * subject, and the factory steps aside for the next provider (Kafka's own).
 *
 * <p>The service makes its factory itself instead of naming a class for the
 * JDK to load by reflection.
 */
final class ScramProvider extends Provider {

    private static final long serialVersionUID = 1L;
    private static final String NAME = "seclume-scram";

    private ScramProvider() {
        super(NAME, "1.0", "SASL/SCRAM client with the password off the heap");
        for (String mechanism : new String[] {"SCRAM-SHA-256", "SCRAM-SHA-512"}) {
            putService(new Service(this, "SaslClientFactory", mechanism,
                    Factory.class.getName(), null, null) {
                @Override
                public Object newInstance(Object parameter) {
                    return new Factory();
                }
            });
        }
    }

    /** Once per JVM, at the first login module that needs it. */
    static synchronized void install() {
        if (Security.getProvider(NAME) == null) {
            Security.insertProviderAt(new ScramProvider(), 1);
        }
    }

    static final class Factory implements SaslClientFactory {

        @Override
        public SaslClient createSaslClient(String[] mechanisms, String authorizationId,
                                           String protocol, String serverName,
                                           Map<String, ?> properties, CallbackHandler callbacks)
                throws SaslException {
            // Kafka creates the client inside Subject.callAs with the subject
            // the login module filled.
            Subject subject = Subject.current();
            if (subject == null) {
                return null;
            }
            ScramSecret secret = subject.getPublicCredentials(ScramSecret.class).stream()
                    .findFirst().orElse(null);
            if (secret == null) {
                return null;                          // not ours: the next provider
            }
            for (String mechanism : mechanisms) {
                HashAlgorithm algorithm = switch (mechanism) {
                    case "SCRAM-SHA-256" -> HashAlgorithm.SHA_256;
                    case "SCRAM-SHA-512" -> HashAlgorithm.SHA_512;
                    default -> null;
                };
                if (algorithm != null) {
                    return new ScramClient(mechanism, algorithm, username(callbacks),
                            secret.provider());
                }
            }
            return null;
        }

        @Override
        public String[] getMechanismNames(Map<String, ?> properties) {
            return new String[] {"SCRAM-SHA-256", "SCRAM-SHA-512"};
        }

        private static String username(CallbackHandler callbacks) throws SaslException {
            NameCallback name = new NameCallback("user name");
            try {
                callbacks.handle(new Callback[] {name});
            } catch (java.io.IOException | UnsupportedCallbackException e) {
                throw new SaslException("no user name for SCRAM: " + e.getMessage(), e);
            }
            if (name.getName() == null || name.getName().isEmpty()) {
                throw new SaslException("no user name for SCRAM");
            }
            return name.getName();
        }
    }
}
