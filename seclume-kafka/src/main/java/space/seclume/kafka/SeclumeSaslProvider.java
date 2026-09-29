package space.seclume.kafka;

import java.security.Provider;
import java.security.Security;
import java.util.LinkedHashMap;
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
 * Puts seclume's SASL clients in front of every other in this JVM - for the
 * logins configured through this package's login modules only. A login
 * configured any other way finds no {@link ScramSecret} or
 * {@link LoginSecret} in its subject, and the factory steps aside for the
 * next provider (Kafka's own).
 *
 * <p>The service makes its factory itself instead of naming a class for the
 * JDK to load by reflection.
 */
final class SeclumeSaslProvider extends Provider {

    private static final long serialVersionUID = 1L;
    private static final String NAME = "seclume-sasl";
    private static final String[] MECHANISMS =
            {"SCRAM-SHA-256", "SCRAM-SHA-512", "PLAIN", "OAUTHBEARER"};

    private SeclumeSaslProvider() {
        super(NAME, "1.0", "SASL clients with the secret off the heap");
        for (String mechanism : MECHANISMS) {
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
            Security.insertProviderAt(new SeclumeSaslProvider(), 1);
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
            for (String mechanism : mechanisms) {
                switch (mechanism) {
                    case "SCRAM-SHA-256", "SCRAM-SHA-512" -> {
                        ScramSecret secret = first(subject, ScramSecret.class);
                        if (secret != null) {
                            return new ScramClient(mechanism, mechanism.endsWith("256")
                                    ? HashAlgorithm.SHA_256 : HashAlgorithm.SHA_512,
                                    username(callbacks, mechanism), secret.provider());
                        }
                    }
                    case "PLAIN" -> {
                        LoginSecret secret = login(subject, "PLAIN");
                        if (secret != null) {
                            return new PlainClient(username(callbacks, mechanism),
                                    secret.provider());
                        }
                    }
                    case "OAUTHBEARER" -> {
                        LoginSecret secret = login(subject, "OAUTHBEARER");
                        if (secret != null) {
                            return new OAuthBearerClient(secret.provider(),
                                    new LinkedHashMap<>(secret.extensions()));
                        }
                    }
                    default -> {
                        // not one of ours
                    }
                }
            }
            return null;                              // not ours: the next provider
        }

        @Override
        public String[] getMechanismNames(Map<String, ?> properties) {
            return MECHANISMS.clone();
        }

        private static <T> T first(Subject subject, Class<T> type) {
            return subject.getPublicCredentials(type).stream().findFirst().orElse(null);
        }

        private static LoginSecret login(Subject subject, String mechanism) {
            return subject.getPublicCredentials(LoginSecret.class).stream()
                    .filter(secret -> secret.mechanism().equals(mechanism))
                    .findFirst().orElse(null);
        }

        private static String username(CallbackHandler callbacks, String mechanism)
                throws SaslException {
            NameCallback name = new NameCallback("user name");
            try {
                callbacks.handle(new Callback[] {name});
            } catch (java.io.IOException | UnsupportedCallbackException e) {
                throw new SaslException("no user name for " + mechanism + ": " + e.getMessage(),
                        e);
            }
            if (name.getName() == null || name.getName().isEmpty()) {
                throw new SaslException("no user name for " + mechanism);
            }
            return name.getName();
        }
    }
}
