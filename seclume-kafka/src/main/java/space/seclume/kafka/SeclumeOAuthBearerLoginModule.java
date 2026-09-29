package space.seclume.kafka;

import java.util.LinkedHashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.spi.LoginModule;

import space.seclume.secret.SecretProvider;

/**
 * The JAAS login module for Kafka's SASL/OAUTHBEARER with the token off the
 * heap:
 *
 * <pre>
 * security.protocol=SASL_SSL
 * ssl.engine.factory.class=space.seclume.kafka.SeclumeSslEngineFactory
 * sasl.mechanism=OAUTHBEARER
 * sasl.jaas.config=space.seclume.kafka.SeclumeOAuthBearerLoginModule required \
 *     token-url="https://login.example.com/oauth2/token" client-id="orders" \
 *     scope="kafka" provider="file" path="/run/secrets/client-secret";
 * </pre>
 *
 * <p>Where the token comes from:
 * <ul>
 *   <li>with {@code token-url}: the OAuth 2.0 client credentials grant, as
 *       {@code auth=oauth2} in seclume-http - {@code client-id},
 *       {@code scope}, {@code client-auth} and the rest, the client secret
 *       named by the provider options; the token is fetched into native
 *       memory and again shortly before it expires. Needs seclume-http;
 *   <li>without it: the provider options name the token itself -
 *       {@code provider=file} for a token another process keeps fresh,
 *       {@code azure-managed-identity} or {@code gcp-metadata} for the cloud's.
 * </ul>
 * {@code extension_<name>="value"} options go to the broker as SASL
 * extensions beside the token (Confluent Cloud's {@code logicalCluster} and
 * {@code identityPoolId}).
 *
 * <p>Kafka's own {@code OAuthBearerLoginModule} keeps the token as a
 * {@code String} in the subject and sends it through its buffers and JSSE's.
 * Here Kafka gets a placeholder, and {@link SeclumeSslEngineFactory}'s engine
 * writes the token in its place as the request is encrypted - so this module
 * refuses to log in without {@code SASL_SSL} and that engine factory.
 */
public final class SeclumeOAuthBearerLoginModule implements LoginModule {

    private static final String EXTENSION = "extension_";

    /** For JAAS, which makes one per login context. */
    public SeclumeOAuthBearerLoginModule() {
    }

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler,
                           Map<String, ?> sharedState, Map<String, ?> options) {
        Map<String, Object> rest = new LinkedHashMap<>(options);
        Map<String, String> extensions = new LinkedHashMap<>();
        for (Map.Entry<String, ?> option : options.entrySet()) {
            if (option.getKey().startsWith(EXTENSION) && option.getValue() instanceof String value) {
                String name = option.getKey().substring(EXTENSION.length());
                if (!name.matches("[A-Za-z]+") || name.equals("auth")) {
                    throw new IllegalArgumentException("a SASL extension's name is letters only, "
                            + "and not 'auth': " + option.getKey());
                }
                if (!value.matches("[\\x21-\\x7E \\t\\r\\n]+")) {
                    throw new IllegalArgumentException("the SASL extension " + name
                            + " holds characters RFC 7628 does not allow");
                }
                extensions.put(name, value);
                rest.remove(option.getKey());
            }
        }
        LoginOptions.Parsed parsed = LoginOptions.parse("SeclumeOAuthBearerLoginModule", rest,
                false);
        Map<String, String> settings = parsed.settings();
        if (!settings.containsKey("token-url") && !settings.containsKey("max-length")
                && !settings.containsKey("maxLength")) {
            settings.put("max-length", "16384");        // a JWT, not a password
        }
        SecretProvider token = settings.containsKey("token-url")
                ? clientCredentials(settings)
                : LoginOptions.provider(settings);
        subject.getPublicCredentials().add(new LoginSecret("OAUTHBEARER", token, extensions));
    }

    private static SecretProvider clientCredentials(Map<String, String> settings) {
        try {
            return space.seclume.http.OAuthClientCredentials.of(settings);
        } catch (NoClassDefFoundError missing) {
            throw new IllegalArgumentException("token-url fetches the token with seclume-http, "
                    + "which is not on the class path - add space.seclume:seclume-http", missing);
        }
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
