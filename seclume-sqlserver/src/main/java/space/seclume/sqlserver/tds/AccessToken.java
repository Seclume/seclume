package space.seclume.sqlserver.tds;

import java.lang.foreign.MemorySegment;
import java.time.Instant;

import space.seclume.secret.ExpiringCredentials;
import space.seclume.secret.SecretProvider;

/**
 * A secret that is a Microsoft Entra access token, not a password: the login
 * sends it in LOGIN7's {@code FEDAUTH} feature (security-token flavour) and
 * leaves the user name and password fields empty.
 *
 * <p>It only marks the provider - the token itself still comes from it, an
 * {@code azure-managed-identity} asked for {@code https://database.windows.net/}
 * or any other source, and goes from its scope straight into the send buffer.
 * URL: {@code authentication=token}.
 */
public final class AccessToken implements SecretProvider, ExpiringCredentials {

    private final SecretProvider source;

    private AccessToken(SecretProvider source) {
        this.source = source;
    }

    /** The provider, marked as one that delivers an access token. */
    public static SecretProvider of(SecretProvider source) {
        return source instanceof AccessToken ? source : new AccessToken(source);
    }

    /** Whether the login is to send this provider's secret as an access token. */
    public static boolean is(SecretProvider provider) {
        return provider instanceof AccessToken;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        return source.writeSecret(target);
    }

    @Override
    public int maxSecretLength() {
        return source.maxSecretLength();
    }

    @Override
    public Instant credentialsValidUntil() {
        return source instanceof ExpiringCredentials expiring
                ? expiring.credentialsValidUntil() : null;
    }

    @Override
    public void close() {
        try {
            source.close();
        } catch (Exception e) {
            throw new IllegalStateException("closing the token's provider failed", e);
        }
    }
}
