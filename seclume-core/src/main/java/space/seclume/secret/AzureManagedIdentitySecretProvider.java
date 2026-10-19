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
 * <p><b>Azure Arc</b> machines set {@code IDENTITY_ENDPOINT} and
 * {@code IMDS_ENDPOINT} but no header: their agent first answers 401 and
 * names, in {@code WWW-Authenticate}, a file only an administrator (or the
 * {@code himds} group) can read; its content is the challenge that the second
 * request carries as {@code Authorization: Basic ...}. The file is read into
 * native memory and the header written from there - and only a file in the
 * agent's token directory, ending in {@code .key} and at most 4 KiB, as the
 * Azure SDK checks, so that an endpoint cannot make this read any other file.
 */
public final class AzureManagedIdentitySecretProvider implements SecretProvider {

    /** Where IMDS lives on every Azure VM - link-local, never leaving the host. */
    public static final String IMDS_HOST = "169.254.169.254";

    /** The resource Azure Database for PostgreSQL and MySQL accept tokens for. */
    public static final String OSSRDBMS_RESOURCE = "https://ossrdbms-aad.database.windows.net";

    private static final String API_VERSION = "2018-02-01";
    private static final String APP_SERVICE_API_VERSION = "2019-08-01";
    private static final String ARC_API_VERSION = "2020-06-01";
    private static final int ARC_CHALLENGE_MAX = 4096;

    private final String host;
    private final int port;
    private final int timeoutMillis;
    private final String resource;
    private final String clientId;
    private final int maxLength;
    /** App Service and the like: the endpoint's path and the header to send; null for IMDS. */
    private final String appServicePath;
    private final String appServiceHeader;
    /** Azure Arc: the endpoint's path and the directory its challenge files are in; null otherwise. */
    private final String arcPath;
    private final java.nio.file.Path arcTokens;

    /**
     * @param resource the audience the token is for - see {@link #OSSRDBMS_RESOURCE}
     * @param clientId a user-assigned identity, or {@code null} for the
     *                 system-assigned one
     */
    public AzureManagedIdentitySecretProvider(String resource, String clientId, int maxLength) {
        this(environment("IDENTITY_ENDPOINT"), environment("IDENTITY_HEADER"), resource,
                clientId, maxLength, environment("IMDS_ENDPOINT") != null
                        && environment("IDENTITY_HEADER") == null);
    }

    private AzureManagedIdentitySecretProvider(String endpoint, String header, String resource,
            String clientId, int maxLength, boolean arc) {
        this(arc && endpoint != null ? uri(endpoint).getHost()
                        : endpoint == null || header == null ? IMDS_HOST : uri(endpoint).getHost(),
                arc && endpoint != null ? port(uri(endpoint))
                        : endpoint == null || header == null ? 80 : port(uri(endpoint)),
                5_000, resource, clientId, maxLength,
                !arc && endpoint != null && header != null ? uri(endpoint).getRawPath() : null,
                arc ? null : header,
                arc && endpoint != null ? uri(endpoint).getRawPath() : null,
                arc && endpoint != null ? arcTokenDirectory() : null);
    }

    /**
     * Azure Arc: the agent's endpoint, and the directory its challenge files
     * are in - for tests, which run a stand-in on loopback with a directory
     * of their own.
     */
    public static AzureManagedIdentitySecretProvider arc(String endpoint, String resource,
            java.nio.file.Path tokenDirectory, int maxLength) {
        return new AzureManagedIdentitySecretProvider(uri(endpoint).getHost(),
                port(uri(endpoint)), 5_000, resource, null, maxLength, null, null,
                uri(endpoint).getRawPath(), tokenDirectory);
    }

    /** Where the Connected Machine agent writes its challenges. */
    private static java.nio.file.Path arcTokenDirectory() {
        if (space.seclume.internal.Platform.isWindows()) {
            String programData = environment("ProgramData");
            return java.nio.file.Path.of(programData == null ? "C:\\ProgramData" : programData,
                    "AzureConnectedMachineAgent", "Tokens");
        }
        return java.nio.file.Path.of("/var/opt/azcmagent/tokens");
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
                        : uri(endpoint).getRawPath(), header, null, null);
    }

    /** The same against another address - for tests, which run a stand-in on loopback. */
    public AzureManagedIdentitySecretProvider(String host, int port, int timeoutMillis,
            String resource, String clientId, int maxLength) {
        this(host, port, timeoutMillis, resource, clientId, maxLength, null, null, null, null);
    }

    private AzureManagedIdentitySecretProvider(String host, int port, int timeoutMillis,
            String resource, String clientId, int maxLength, String appServicePath,
            String appServiceHeader, String arcPath, java.nio.file.Path arcTokens) {
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
        this.arcPath = arcPath;
        this.arcTokens = arcTokens;
        if (arcPath != null && clientId != null && !clientId.isBlank()) {
            throw new IllegalArgumentException("an Azure Arc machine has one identity, its own - "
                    + "no client-id");
        }
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

    /** Azure Arc: ask, read the challenge the 401 names, ask again with it. */
    private int arc(MemorySegment target) {
        String path = arcPath + "?api-version=" + ARC_API_VERSION + "&resource="
                + URLEncoder.encode(resource, StandardCharsets.UTF_8);
        java.nio.file.Path challenge;
        try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
            space.seclume.internal.SecretFetch.Response first =
                    space.seclume.internal.SecretFetch.sendLinkLocal(host, port, timeoutMillis,
                            "GET", path, Map.of("Metadata", "true"), arena.allocate(16 * 1024));
            if (first.status() != 401 || first.challenge() == null) {
                throw new SecretUnavailableException("the Azure Arc agent answered "
                        + first.status() + " instead of naming its challenge - is this an Arc "
                        + "machine with the agent running?");
            }
            challenge = challengeFile(first.challenge());
        } catch (java.io.IOException unreachable) {
            throw new SecretUnavailableException("the Azure Arc agent could not be reached at "
                    + host + ":" + port + " - " + unreachable.getMessage(), unreachable);
        }
        try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined();
             FileSecretProvider file = new FileSecretProvider(challenge, ARC_CHALLENGE_MAX)) {
            MemorySegment header = arena.allocate(6 + ARC_CHALLENGE_MAX);
            try {
                MemorySegment.copy(new byte[] {'B', 'a', 's', 'i', 'c', ' '}, 0, header,
                        java.lang.foreign.ValueLayout.JAVA_BYTE, 0, 6);
                int length = file.writeSecret(header.asSlice(6));
                return MetadataToken.fetch("the Azure Arc agent", host, port, timeoutMillis,
                        path, Map.of("Metadata", "true"),
                        java.util.List.of(new space.seclume.internal.SecretFetch.SecretHeader(
                                "Authorization", header, 6 + length)), target);
            } finally {
                header.fill((byte) 0);
            }
        }
    }

    /**
     * The file a {@code Basic realm=...} names - only one in the agent's
     * token directory, ending in {@code .key}, not larger than 4 KiB.
     */
    private java.nio.file.Path challengeFile(String header) {
        String authenticate = header.trim();
        int equals = authenticate.indexOf('=');
        if (!authenticate.regionMatches(true, 0, "Basic realm=", 0, 12) || equals < 0) {
            throw new SecretUnavailableException("the Azure Arc agent's challenge is not "
                    + "'Basic realm=<file>'");
        }
        java.nio.file.Path file;
        try {
            file = java.nio.file.Path.of(authenticate.substring(equals + 1).trim())
                    .toAbsolutePath().normalize();
        } catch (java.nio.file.InvalidPathException e) {
            throw new SecretUnavailableException("the Azure Arc agent named no file it may", e);
        }
        if (!file.startsWith(arcTokens.toAbsolutePath().normalize())
                || !file.getFileName().toString().endsWith(".key")) {
            throw new SecretUnavailableException("the Azure Arc agent named a file outside its "
                    + "token directory " + arcTokens + " - refused, nothing was read");
        }
        try {
            if (java.nio.file.Files.size(file) > ARC_CHALLENGE_MAX) {
                throw new SecretUnavailableException("the Azure Arc challenge file is larger than "
                        + ARC_CHALLENGE_MAX + " bytes - refused");
            }
        } catch (java.io.IOException e) {
            throw new SecretUnavailableException("the Azure Arc challenge file cannot be read - "
                    + "the process needs to be an administrator or in the himds group", e);
        }
        return file;
    }

    @Override
    public int maxSecretLength() {
        return maxLength;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        if (arcPath != null) {
            return arc(target);
        }
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
