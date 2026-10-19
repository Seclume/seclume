package space.seclume.secret;

import java.lang.foreign.MemorySegment;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * No password at all: the database accepts this machine's Azure identity.
 *
 * <p>Azure Database for PostgreSQL and for MySQL, and Azure SQL, can
 * authenticate a login with a Microsoft Entra ID access token in place of a
 * password. On a VM, a scale set, AKS with a pod identity or Azure Container
 * Instances, that token is handed out by the <b>Instance Metadata Service</b>
 * to whatever runs on the machine - so there is no credential to store,
 * rotate, leak or forget to revoke. The identity is the machine's.
 *
 * <pre>
 * provider=azure-managed-identity
 * resource=https://ossrdbms-aad.database.windows.net     (PostgreSQL, MySQL)
 * client-id=...                                           (a user-assigned identity; optional)
 * </pre>
 *
 * <p>It works as a {@code token-provider} too - {@code azure-key-vault} with
 * {@code token-provider=azure-managed-identity} and
 * {@code token-resource=https://vault.azure.net} reads a Key Vault secret with
 * the machine's identity and nothing configured beside it.
 *
 * <p><b>The token never becomes a {@code String}.</b> The Azure SDK's
 * {@code ManagedIdentityCredential} returns an {@code AccessToken} whose
 * {@code getToken()} is one, and a token is a credential for as long as it is
 * valid - an hour, in a heap dump. Here the answer lands in native memory and
 * {@code access_token} is copied out of it into the target segment.
 *
 * <p><b>No expiry is reported to the pool, deliberately.</b> The database
 * checks the token at login and never again, so a connection opened with a
 * token outlives it and needs no replacing when it expires. Telling the pool
 * about the expiry would retire healthy connections once an hour for nothing.
 * Each new connection simply asks for a token; IMDS caches it and answers
 * locally.
 *
 * <p><b>App Service, Functions and Container Apps</b> have no IMDS: they
 * give the process an endpoint of their own on loopback,
 * {@code IDENTITY_ENDPOINT}, and a header value it has to send,
 * {@code IDENTITY_HEADER}. When both are set, that endpoint is asked instead
 * - as the Azure SDK decides it too. The header value is the platform's guard
 * against server-side request forgery, valid only on that loopback address,
 * and it is a {@code String} already, in the process environment; the token
 * still goes from the socket into native memory.
 *
 * <p><b>Not covered:</b> Azure Arc, whose endpoint answers with a challenge
 * file to read first.
 */
public final class AzureManagedIdentitySecretProvider implements SecretProvider {

    /** Where IMDS lives on every Azure VM - link-local, never leaving the host. */
    public static final String IMDS_HOST = "169.254.169.254";

    /** The resource Azure Database for PostgreSQL and MySQL accept tokens for. */
    public static final String OSSRDBMS_RESOURCE = "https://ossrdbms-aad.database.windows.net";

    private static final String API_VERSION = "2018-02-01";
    private static final String APP_SERVICE_API_VERSION = "2019-08-01";

    private final String host;
    private final int port;
    private final int timeoutMillis;
    private final String resource;
    private final String clientId;
    private final int maxLength;
    /** App Service and the like: the endpoint's path and the header to send; null for IMDS. */
    private final String appServicePath;
    private final String appServiceHeader;

    /**
     * @param resource the audience the token is for - see {@link #OSSRDBMS_RESOURCE}
     * @param clientId a user-assigned identity, or {@code null} for the
     *                 system-assigned one
     */
    public AzureManagedIdentitySecretProvider(String resource, String clientId, int maxLength) {
        this(environment("IDENTITY_ENDPOINT"), environment("IDENTITY_HEADER"), resource,
                clientId, maxLength);
    }

    /**
     * App Service, Functions, Container Apps: their endpoint and header, as
     * the platform sets {@code IDENTITY_ENDPOINT} and {@code IDENTITY_HEADER}.
     * With either missing, IMDS.
     */
    public AzureManagedIdentitySecretProvider(String endpoint, String header, String resource,
            String clientId, int maxLength) {
        this(endpoint == null || header == null ? IMDS_HOST : uri(endpoint).getHost(),
                endpoint == null || header == null ? 80 : port(uri(endpoint)), 5_000, resource,
                clientId, maxLength, endpoint == null || header == null ? null
                        : uri(endpoint).getRawPath(), header);
    }

    /** The same against another address - for tests, which run a stand-in on loopback. */
    public AzureManagedIdentitySecretProvider(String host, int port, int timeoutMillis,
            String resource, String clientId, int maxLength) {
        this(host, port, timeoutMillis, resource, clientId, maxLength, null, null);
    }

    private AzureManagedIdentitySecretProvider(String host, int port, int timeoutMillis,
            String resource, String clientId, int maxLength, String appServicePath,
            String appServiceHeader) {
        if (resource == null || resource.isBlank()) {
            throw new IllegalArgumentException("azure-managed-identity needs 'resource' - the "
                    + "audience of the token, for example " + OSSRDBMS_RESOURCE);
        }
        this.host = host;
        this.port = port;
        this.timeoutMillis = timeoutMillis;
        this.resource = resource;
        this.clientId = clientId;
        this.maxLength = maxLength;
        this.appServicePath = appServicePath == null || appServicePath.isEmpty() ? null
                : appServicePath;
        this.appServiceHeader = appServiceHeader;
    }

    private static String environment(String variable) {
        // seclume-allow: an endpoint on loopback and the platform's request guard for it, not a credential
        String value = System.getenv(variable);
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static java.net.URI uri(String endpoint) {
        java.net.URI uri;
        try {
            uri = new java.net.URI(endpoint);
        } catch (java.net.URISyntaxException e) {
            throw new IllegalArgumentException("IDENTITY_ENDPOINT is not a URL", e);
        }
        if (!"http".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
            // The platform's endpoint is plain HTTP on loopback; anything else is not it.
            throw new IllegalArgumentException("IDENTITY_ENDPOINT is not an http:// URL with a "
                    + "host - App Service's identity endpoint is plain HTTP on loopback");
        }
        return uri;
    }

    private static int port(java.net.URI uri) {
        return uri.getPort() < 0 ? 80 : uri.getPort();
    }

    @Override
    public int maxSecretLength() {
        return maxLength;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        if (appServicePath != null) {
            String path = appServicePath + "?api-version=" + APP_SERVICE_API_VERSION
                    + "&resource=" + URLEncoder.encode(resource, StandardCharsets.UTF_8)
                    + (clientId == null || clientId.isBlank() ? ""
                            : "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8));
            // Loopback only - SecretFetch refuses plain HTTP anywhere else.
            return MetadataToken.fetch("the App Service identity endpoint", host, port,
                    timeoutMillis, path, Map.of("X-IDENTITY-HEADER", appServiceHeader), target);
        }
        String path = "/metadata/identity/oauth2/token?api-version=" + API_VERSION
                + "&resource=" + URLEncoder.encode(resource, StandardCharsets.UTF_8)
                + (clientId == null || clientId.isBlank() ? ""
                        : "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8));
        // "Metadata: true" is IMDS's guard against being reached through a
        // redirect or a proxy: a request without it is refused.
        return MetadataToken.fetch("Azure IMDS", host, port, timeoutMillis, path,
                Map.of("Metadata", "true"), target);
    }
}
