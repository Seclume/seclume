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
    private final int maxLength;

    /**
     * @param account the service account, or {@code null} for {@code default}
     * @param scopes  comma-separated OAuth scopes, or {@code null} for the
     *                account's own
     */
    public GcpMetadataSecretProvider(String account, String scopes, int maxLength) {
        this(METADATA_HOST, 80, 5_000, account, scopes, maxLength);
    }

    /** The same against another address - for tests, which run a stand-in on loopback. */
    public GcpMetadataSecretProvider(String host, int port, int timeoutMillis, String account,
            String scopes, int maxLength) {
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
