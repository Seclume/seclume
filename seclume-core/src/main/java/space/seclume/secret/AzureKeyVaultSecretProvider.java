package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import space.seclume.internal.JsonOff;
import space.seclume.internal.SecretFetch;

/**
 * A secret from Azure Key Vault, read without it becoming a {@code String}.
 *
 * <p>{@code SecretClient.getSecret(name).getValue()} is a {@code String}, and
 * the Azure SDK has made several more on the way to it. Here the HTTPS is
 * {@link SecretFetch} and the JSON is {@link JsonOff}, so what lands on the
 * heap is nothing.
 *
 * <h2>The token</h2>
 *
 * <p>Key Vault takes a bearer token, and unlike AWS it does not sign anything
 * - which makes this the easiest of the three to keep honest: the token is a
 * secret, it comes from another {@link SecretProvider}, and it is written into
 * the {@code Authorization} header straight out of native memory. It is never
 * part of a string.
 *
 * <p>Where the token comes from is deliberately not this class's business. A
 * managed identity writes one to the IMDS endpoint, a workload identity to a
 * file, a service principal gets one from a token request - all three are
 * providers, and {@code token-provider=file} covers the two that matter in a
 * container.
 *
 * <h2>Expiry</h2>
 *
 * <p>Key Vault returns {@code attributes.exp} when a secret has one, so a
 * rotating secret reports its own end and the pool retires connections before
 * it - see {@link ExpiringCredentials}. Most Key Vault secrets have no
 * expiry set, and then the answer is {@code null} and nothing changes.
 */
public final class AzureKeyVaultSecretProvider implements SecretProvider, ExpiringCredentials {

    /** The oldest version that has everything needed, and is still current. */
    private static final String API_VERSION = "7.4";

    private final String host;
    private final int port;
    private final boolean verify;
    private final int timeoutMillis;
    private final String name;
    private final String version;
    private final SecretProvider token;
    private final int maxLength;

    private Instant expiresAt;

    /**
     * @param vaultUri {@code https://my-vault.vault.azure.net}
     * @param name     the secret's name
     * @param version  a specific version, or {@code null} for the current one
     * @param token    where the bearer token comes from
     */
    public AzureKeyVaultSecretProvider(String vaultUri, String name, String version,
            SecretProvider token, int maxLength) {
        this(vaultUri, name, version, token, true, 10_000, maxLength);
    }

    /** The same with the transport under the caller's control - for tests. */
    public AzureKeyVaultSecretProvider(String vaultUri, String name, String version,
            SecretProvider token, boolean verify, int timeoutMillis, int maxLength) {
        java.net.URI uri = java.net.URI.create(vaultUri);
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("the Key Vault address must be https://, not "
                    + vaultUri + " - a bearer token over plain http is a token given away");
        }
        this.host = uri.getHost();
        this.port = uri.getPort() > 0 ? uri.getPort() : 443;
        this.verify = verify;
        this.timeoutMillis = timeoutMillis;
        this.name = name;
        this.version = version;
        this.token = token;
        this.maxLength = maxLength;
    }

    @Override
    public int maxSecretLength() {
        return maxLength;
    }

    @Override
    public synchronized int writeSecret(MemorySegment target) {
        String path = "/secrets/" + name + (version == null || version.isEmpty() ? "" : "/" + version)
                + "?api-version=" + API_VERSION;

        try (Arena arena = Arena.ofConfined();
             SecretScope answer = SecretScope.in(arena, SecretFetch.MAX_RESPONSE);
             SecretScope bearer = SecretScope.fromProvider(token)) {

            SecretFetch.Response response = SecretFetch.send(host, port, verify, timeoutMillis,
                    "GET", path, Map.of(),
                    List.of(new SecretFetch.SecretHeader("Authorization",
                            prefixed(arena, bearer), 7 + bearer.length())),
                    null, answer.segment());
            if (!response.ok()) {
                throw new SecretUnavailableException("Azure Key Vault answered "
                        + response.status() + " for " + name + ". 401 means the token is not "
                        + "accepted, 403 that it may not read this secret, 404 that the secret "
                        + "or the vault does not exist");
            }
            answer.length(response.bodyLength());

            expiresAt = JsonOff.has(answer.segment(), answer.length(), "attributes", "exp")
                    ? Instant.ofEpochSecond(
                            JsonOff.number(answer.segment(), answer.length(), "attributes", "exp"))
                    : null;
            return JsonOff.string(answer.segment(), answer.length(), target, "value");
        } catch (IOException e) {
            throw new SecretUnavailableException(
                    "cannot reach Azure Key Vault at " + host + ": " + e.getMessage(), e);
        } catch (JsonOff.NotFound e) {
            throw new SecretUnavailableException(
                    "Azure Key Vault answered, but not in a shape this understands: "
                    + e.getMessage(), e);
        }
    }

    @Override
    public synchronized Instant credentialsValidUntil() {
        return expiresAt;
    }

    /**
     * {@code Bearer } and the token, in one segment.
     *
     * <p>The word has to sit in front of the token and the token may not
     * become a {@code String}, so the two are joined in native memory rather
     * than by concatenation.
     */
    private static MemorySegment prefixed(Arena arena, SecretScope bearer) {
        MemorySegment value = arena.allocate(7L + bearer.length());
        byte[] word = {'B', 'e', 'a', 'r', 'e', 'r', ' '}; // seclume-allow: a constant word, not a secret
        MemorySegment.copy(word, 0, value, java.lang.foreign.ValueLayout.JAVA_BYTE, 0, 7);
        MemorySegment.copy(bearer.segment(), 0, value, 7, bearer.length());
        return value;
    }

    @Override
    public void close() {
        token.close();
    }
}
