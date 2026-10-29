package space.seclume.secret;

import java.lang.foreign.MemorySegment;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * No password at all: Cloud SQL accepts this workload's Google identity.
 *
 * <p>Cloud SQL for PostgreSQL and for MySQL support <b>IAM database
 * authentication</b>: the login's password is an OAuth access token of a
 * service account, and the database user is that account. On Compute Engine,
 * GKE with Workload Identity, Cloud Run and App Engine the token comes from
 * the <b>metadata server</b>, which answers only to the workload itself - so
 * there is no credential to keep anywhere.
 *
 * <pre>
 * user=app-sa@project.iam        (PostgreSQL: the account without .gserviceaccount.com)
 * provider=gcp-metadata
 * account=default                (or the e-mail of another attached account)
 * </pre>
 *
 * <p>It works as the {@code token-provider} of {@code gcp-secret-manager} as
 * well, which then reads with the workload's identity and nothing else.
 *
 * <p>With {@code audience=...} it is the account's <b>identity token</b>
 * instead - a JWT naming that audience, for a service that checks who the
 * caller is rather than what it may do: MongoDB's {@code MONGODB-OIDC} login
 * ({@code ENVIRONMENT:gcp}). The metadata server answers it as plain text,
 * which goes from the socket to the target as it is.
 *
 * <p><b>The token never becomes a {@code String}</b>, where
 * {@code GoogleCredentials.getAccessToken().getTokenValue()} is one. The
 * answer lands in native memory and only {@code access_token} is copied out.
 *
 * <p><b>No expiry is reported to the pool</b>, for the reason
 * {@link AzureManagedIdentitySecretProvider} gives: the token is checked at
 * login only, so a connection outlives it. The metadata server caches tokens
 * and answers every new connection locally.
 */
public final class GcpMetadataSecretProvider implements SecretProvider {

    /** The metadata server's name; it resolves to 169.254.169.254 inside Google Cloud. */
    public static final String METADATA_HOST = "metadata.google.internal";

    private final String host;
    private final int port;
    private final int timeoutMillis;
    private final String account;
    private final String scopes;
    private final String audience;
    /** An identity token with the instance's details in it ({@code format=full}). */
    private final boolean full;
    private final int maxLength;

    /**
     * @param account the service account, or {@code null} for {@code default}
     * @param scopes  comma-separated OAuth scopes, or {@code null} for the
     *                account's own
     */
    public GcpMetadataSecretProvider(String account, String scopes, int maxLength) {
        this(METADATA_HOST, 80, 5_000, account, scopes, null, maxLength);
    }

    /** @param audience for an identity token instead of an access token, or {@code null} */
    public GcpMetadataSecretProvider(String account, String scopes, String audience,
            int maxLength) {
        this(METADATA_HOST, 80, 5_000, account, scopes, audience, maxLength);
    }

    /** The same against another address - for tests, which run a stand-in on loopback. */
    public GcpMetadataSecretProvider(String host, int port, int timeoutMillis, String account,
            String scopes, int maxLength) {
        this(host, port, timeoutMillis, account, scopes, null, maxLength);
    }

    /** The same against another address, for an identity token - for tests. */
    public GcpMetadataSecretProvider(String host, int port, int timeoutMillis, String account,
            String scopes, String audience, int maxLength) {
        this(host, port, timeoutMillis, account, scopes, audience, false, maxLength);
    }

    /**
     * An identity token with {@code format=full}: the project, zone and
     * instance in its claims, which Vault's {@code gce} login checks the role's
     * bounds against.
     */
    public static GcpMetadataSecretProvider fullIdentity(String account, String audience,
            int maxLength) {
        return new GcpMetadataSecretProvider(METADATA_HOST, 80, 5_000, account, null, audience,
                true, maxLength);
    }

    /** {@link #fullIdentity} against another address - for tests. */
    static GcpMetadataSecretProvider fullIdentity(String host, int port, String account,
            String audience, int maxLength) {
        return new GcpMetadataSecretProvider(host, port, 5_000, account, null, audience, true,
                maxLength);
    }

    private GcpMetadataSecretProvider(String host, int port, int timeoutMillis, String account,
            String scopes, String audience, boolean full, int maxLength) {
        if (audience != null && scopes != null && !scopes.isBlank()) {
            throw new IllegalArgumentException("gcp-metadata takes scopes for an access token "
                    + "or audience for an identity token, not both");
        }
        this.audience = audience == null || audience.isBlank() ? null : audience;
        if (full && this.audience == null) {
            throw new IllegalArgumentException("format=full is for an identity token, which "
                    + "needs an audience");
        }
        this.full = full;
        this.host = host;
        this.port = port;
        this.timeoutMillis = timeoutMillis;
        this.account = account == null || account.isBlank() ? "default" : account;
        this.scopes = scopes;
        this.maxLength = maxLength;
    }

    @Override
    public int maxSecretLength() {
        return maxLength;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        if (audience != null) {
            String identity = "/computeMetadata/v1/instance/service-accounts/"
                    + URLEncoder.encode(account, StandardCharsets.UTF_8) + "/identity?audience="
                    + URLEncoder.encode(audience, StandardCharsets.UTF_8)
                    + (full ? "&format=full" : "");
            return MetadataToken.fetchRaw("the GCP metadata server", host, port, timeoutMillis,
                    identity, Map.of("Metadata-Flavor", "Google"), target);
        }
        String path = "/computeMetadata/v1/instance/service-accounts/"
                + URLEncoder.encode(account, StandardCharsets.UTF_8) + "/token"
                + (scopes == null || scopes.isBlank() ? ""
                        : "?scopes=" + URLEncoder.encode(scopes, StandardCharsets.UTF_8));
        // The metadata server refuses a request without this header - its
        // guard against being reached through a proxy or a redirect.
        return MetadataToken.fetch("the GCP metadata server", host, port, timeoutMillis, path,
                Map.of("Metadata-Flavor", "Google"), target);
    }
}
