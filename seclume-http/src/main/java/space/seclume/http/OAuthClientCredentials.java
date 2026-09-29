package space.seclume.http;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.util.LinkedHashMap;
import java.util.Map;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;
import space.seclume.secret.SecretUnavailableException;

/**
 * An OAuth 2.0 access token from the client credentials grant, as a
 * {@link SecretProvider} - for the protocols that carry a bearer token
 * without HTTP: Kafka's SASL/OAUTHBEARER.
 *
 * <p>The same grant as {@code auth=oauth2} in a seclume HTTP URL, with the
 * same options ({@code token-url}, {@code client-id}, {@code scope},
 * {@code client-auth}, ... - see {@link OAuthSettings}) and the same
 * guarantees: the client secret goes from its provider into the token request
 * in native memory, the token comes back into native memory, and it is
 * fetched again shortly before it expires. Each {@link #writeSecret} copies
 * the current token into the caller's segment.
 */
public final class OAuthClientCredentials implements SecretProvider {

    private final OAuthToken token;

    private OAuthClientCredentials(OAuthToken token) {
        this.token = token;
    }

    /**
     * From options such as {@code token-url}, {@code client-id} and
     * {@code scope}; the rest are the client secret's provider options.
     * {@code connectTimeout} and {@code timeout} (milliseconds) bound the
     * token request.
     */
    public static OAuthClientCredentials of(Map<String, String> options) {
        Map<String, String> rest = new LinkedHashMap<>(options);
        int connectTimeout = Integer.parseInt(remove(rest, "connectTimeout", "10000"));
        int timeout = Integer.parseInt(remove(rest, "timeout", "30000"));
        OAuthSettings settings = OAuthSettings.take(rest, connectTimeout, timeout);
        if (!rest.containsKey("provider")) {
            throw new IllegalArgumentException("the client secret is named by provider= and "
                    + "its options (provider=file&path=/run/secrets/client-secret, ...)");
        }
        return new OAuthClientCredentials(new OAuthToken(settings, SecretProviders.of(rest)));
    }

    @Override
    public int writeSecret(MemorySegment target) {
        try {
            return token.writeToken(target);
        } catch (IOException e) {
            throw new SecretUnavailableException("no access token: " + e.getMessage(), e);
        }
    }

    @Override
    public int maxSecretLength() {
        return OAuthToken.maxTokenLength();
    }

    /** The token was refused: the next {@link #writeSecret} fetches a new one. */
    public void invalidate() {
        token.invalidate();
    }

    @Override
    public void close() {
        token.close();
    }

    private static String remove(Map<String, String> options, String name, String fallback) {
        String value = options.remove(name);
        return value == null ? fallback : value;
    }
}
