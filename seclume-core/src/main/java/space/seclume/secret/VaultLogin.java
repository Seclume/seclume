package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import space.seclume.internal.JsonOff;
import space.seclume.internal.SecretFetch;

/**
 * A Vault token obtained by logging in, held in native memory - the token
 * source for {@link VaultSecretProvider} when there is no Vault Agent to
 * write one into a file.
 *
 * <p>Without this the Vault token had to come from somewhere else: a file a
 * sidecar keeps fresh, or a long-lived token handed to the application. The
 * first is a second process to run, the second is a password with more
 * power than the one it protects. A login method turns the identity the
 * workload already has into a short-lived token, and here that happens
 * without the token ever being a {@code String}:
 *
 * <ul>
 *   <li><b>{@code kubernetes}</b> - the pod's service-account JWT, read from
 *       {@value #KUBERNETES_TOKEN} by default, against a Vault role bound to
 *       that service account.
 *   <li><b>{@code jwt}</b> - any JWT Vault's JWT auth method has been told to
 *       trust: a projected token with its own audience, a SPIFFE JWT-SVID, a
 *       CI system's OIDC token.
 *   <li><b>{@code approle}</b> - a role id, which is an identifier, and a
 *       secret id, which is a secret and comes from a provider of its own.
 *   <li><b>{@code aws}</b> ({@code iam} type) - an {@code sts:GetCallerIdentity}
 *       request signed with the workload's AWS credentials, which Vault
 *       replays to AWS to learn who is asking. The secret access key, the
 *       session token and the signature all stay in native memory.
 *   <li><b>{@code gcp}</b> ({@code gce} type) - the VM's identity token from
 *       the metadata server, for audience {@code http://vault/<role>}.
 *   <li><b>{@code azure}</b> - the managed identity's token from IMDS, with
 *       the machine's subscription, resource group and name.
 * </ul>
 *
 * <p>The request body carries the JWT or the secret id; it is assembled in
 * native memory and sent with {@link SecretFetch#sendSecretBody}. The answer
 * carries the client token; it lands in native memory and only
 * {@code auth.client_token} is copied out, into a locked, shared
 * {@link SecretScope} that is wiped when it is replaced or closed.
 *
 * <h2>Lifetime</h2>
 *
 * <p>A token from a login has a TTL. Halfway through it, or thirty seconds
 * before its end, it is renewed ({@code auth/token/renew-self}) if Vault said
 * it is renewable and still grants at least half the TTL; otherwise the login
 * is done again - with the JWT read anew, since a projected service-account
 * token is rotated by the kubelet. Closing revokes the token
 * ({@code auth/token/revoke-self}).
 *
 * <p><b>Vault ties leases to the token that created them</b>: when a token
 * expires or is revoked, every database credential it fetched is revoked
 * with it. {@link VaultSecretProvider} therefore asks {@link #validUntil(long)}
 * for the token a credential was fetched with and treats the earlier of the
 * two ends as the credential's end. A new login is a new {@linkplain
 * #generation() generation}, and credentials of an older one are fetched
 * again rather than renewed.
 */
public final class VaultLogin implements SecretProvider, ExpiringCredentials {

    /** Where Kubernetes mounts the service-account token into every pod. */
    public static final String KUBERNETES_TOKEN =
            "/var/run/secrets/kubernetes.io/serviceaccount/token";

    /**
     * Room for a client token. A service token is about a hundred bytes, a
     * batch token a few hundred; this leaves headroom without being a buffer
     * that anything fits into.
     */
    static final int TOKEN_ROOM = 4096;

    /** Fetch again once the remaining TTL is under this fraction of its length. */
    private static final double REFRESH_AT = 0.5;
    /** And never later than this before the end. */
    private static final Duration LATEST_REFRESH = Duration.ofSeconds(30);

    /** How a token is obtained. */
    public enum Method {
        /** {@code auth/kubernetes/login} with the pod's service-account JWT. */
        KUBERNETES("kubernetes"),
        /** {@code auth/jwt/login} with any JWT the mount trusts. */
        JWT("jwt"),
        /** {@code auth/approle/login} with a role id and a secret id. */
        APPROLE("approle"),
        /** {@code auth/aws/login} with a signed {@code sts:GetCallerIdentity} request. */
        AWS("aws"),
        /** {@code auth/gcp/login} with the VM's identity token. */
        GCP("gcp"),
        /** {@code auth/azure/login} with the managed identity's token. */
        AZURE("azure");

        private final String defaultMount;

        Method(String defaultMount) {
            this.defaultMount = defaultMount;
        }

        /** The mount Vault enables this method at unless told otherwise. */
        public String defaultMount() {
            return defaultMount;
        }

        /** {@code kubernetes}, {@code jwt} or {@code approle}, in any case. */
        public static Method of(String name) {
            return switch (name.trim().toLowerCase(Locale.ROOT)) {
                case "kubernetes", "k8s" -> KUBERNETES;
                case "jwt", "oidc" -> JWT;
                case "approle", "app-role" -> APPROLE;
                case "aws", "aws-iam" -> AWS;
                case "gcp", "gce" -> GCP;
                case "azure" -> AZURE;
                default -> throw new IllegalArgumentException("unknown Vault auth-method '" + name
                        + "' - known are token (the default: a token from token-provider), "
                        + "kubernetes, jwt, approle, aws, gcp and azure");
            };
        }
    }

    private final String host;
    private final int port;
    private final boolean verify;
    private final int timeoutMillis;
    private final String namespace;
    private final Method method;
    private final String mount;
    /** The Vault role; for approle the role id. Neither is a secret. */
    private final String role;
    /** What the login request carries - a JWT, a secret id, a signed AWS request. */
    private final VaultLoginBody body;
    private final Clock clock;

    private SecretScope token;
    private Instant obtainedAt;
    private Instant validUntil;
    private long ttlSeconds;
    private boolean renewable;
    private boolean closed;
    /** Counts logins; a credential fetched under an older one dies with that token. */
    private long generation;
    /** When the token of {@code generation - 1} ends - it is not revoked when replaced. */
    private Instant retiredUntil;

    /**
     * @param address    the Vault address, {@code https://} only
     * @param method     how to log in
     * @param mount      the path the auth method is enabled at, or {@code null}
     *                   for the method's default
     * @param role       the Vault role ({@code kubernetes}: required,
     *                   {@code jwt}: optional, the mount's default role
     *                   otherwise); for {@code approle} the role id
     * @param credential the JWT, or AppRole's secret id
     * @param namespace  a Vault Enterprise namespace, or {@code null}
     * @param verify     whether to check Vault's certificate
     */
    public VaultLogin(String address, Method method, String mount, String role,
            SecretProvider credential, String namespace, boolean verify, int timeoutMillis) {
        this(address, method, mount, role, credential, namespace, verify, timeoutMillis,
                Clock.systemUTC());
    }

    /** The same with a clock of the caller's choosing - for the tests. */
    public VaultLogin(String address, Method method, String mount, String role,
            SecretProvider credential, String namespace, boolean verify, int timeoutMillis,
            Clock clock) {
        this(address, method, mount, role, simpleBody(method, role, credential), namespace,
                verify, timeoutMillis, clock);
    }

    /** For kubernetes, jwt and approle: a role and a secret in a JSON object. */
    private static VaultLoginBody simpleBody(Method method, String role,
            SecretProvider credential) {
        if (method == null || credential == null) {
            throw new IllegalArgumentException("a Vault login needs a method and a credential");
        }
        String named = role == null || role.isBlank() ? null : role;
        return switch (method) {
            case KUBERNETES -> new VaultLoginBody.Simple("role", named, "jwt", credential, null,
                    "JWT", "400 or 403 usually means the role '" + named + "' does not exist "
                    + "or is not bound to this service account and namespace, or Vault cannot "
                    + "review the token (token_reviewer_jwt, kubernetes_host)");
            case JWT -> new VaultLoginBody.Simple("role", named, "jwt", credential, null, "JWT",
                    "400 or 403 usually means the JWT is not accepted: its audience, issuer or "
                    + "subject does not match the role, or it has expired");
            case APPROLE -> new VaultLoginBody.Simple("role_id", named, "secret_id", credential,
                    null, "secret id", "400 or 403 usually means the role id is wrong or the "
                    + "secret id has expired or been used up (secret_id_num_uses)");
            default -> throw new IllegalArgumentException("a " + method.name()
                    .toLowerCase(Locale.ROOT) + " login is made with VaultLogin." + method.name()
                    .toLowerCase(Locale.ROOT) + "(...), not with a credential provider");
        };
    }

    /**
     * {@code aws}, {@code iam} type: signs {@code sts:GetCallerIdentity} with
     * the workload's credentials and lets Vault replay it.
     *
     * @param role      the Vault role, or {@code null} for the one named after
     *                  the IAM principal
     * @param stsHost   the STS endpoint Vault is configured for
     *                  ({@code sts_endpoint}), {@code sts.amazonaws.com} by default
     * @param stsRegion its region ({@code sts_region}), {@code us-east-1} for
     *                  the global endpoint
     * @param serverId  Vault's {@code iam_server_id_header_value}, or {@code null}
     */
    public static VaultLogin aws(String address, String mount, String role,
            AwsInstanceRole credentials, String stsHost, String stsRegion, String serverId,
            String namespace, boolean verify, int timeoutMillis) {
        return aws(address, mount, role, VaultLoginBody.AwsIam.Credentials.of(credentials),
                stsHost, stsRegion, serverId, namespace, verify, timeoutMillis,
                Clock.systemUTC());
    }

    /** The same with a key pair, and a session token for temporary credentials. */
    public static VaultLogin aws(String address, String mount, String role, String accessKeyId,
            SecretProvider secretKey, SecretProvider sessionToken, String stsHost,
            String stsRegion, String serverId, String namespace, boolean verify,
            int timeoutMillis) {
        return aws(address, mount, role, VaultLoginBody.AwsIam.Credentials.of(accessKeyId,
                secretKey, sessionToken), stsHost, stsRegion, serverId, namespace, verify,
                timeoutMillis, Clock.systemUTC());
    }

    static VaultLogin aws(String address, String mount, String role,
            VaultLoginBody.AwsIam.Credentials credentials, String stsHost, String stsRegion,
            String serverId, String namespace, boolean verify, int timeoutMillis, Clock clock) {
        String named = role == null || role.isBlank() ? null : role;
        return new VaultLogin(address, Method.AWS, mount, named, new VaultLoginBody.AwsIam(
                named, credentials, stsHost == null || stsHost.isBlank() ? "sts.amazonaws.com"
                        : stsHost.trim(),
                stsRegion == null || stsRegion.isBlank() ? "us-east-1" : stsRegion.trim(),
                serverId, clock), namespace, verify, timeoutMillis, clock);
    }

    /**
     * {@code gcp}, {@code gce} type: the VM's identity token, in full format,
     * for audience {@code http://vault/<role>} unless another is given.
     */
    public static VaultLogin gcp(String address, String mount, String role, String account,
            String audience, String namespace, boolean verify, int timeoutMillis) {
        requireRole(Method.GCP, role);
        return gcp(address, mount, role, GcpMetadataSecretProvider.fullIdentity(account,
                gcpAudience(role, audience), 16_384), namespace, verify, timeoutMillis,
                Clock.systemUTC());
    }

    static String gcpAudience(String role, String audience) {
        return audience == null || audience.isBlank() ? "http://vault/" + role : audience;
    }

    static VaultLogin gcp(String address, String mount, String role, SecretProvider identity,
            String namespace, boolean verify, int timeoutMillis, Clock clock) {
        requireRole(Method.GCP, role);
        return new VaultLogin(address, Method.GCP, mount, role, new VaultLoginBody.Simple(
                "role", role, "jwt", identity, null, "GCP identity token",
                "400 or 403 usually means the role '" + role + "' is not a gce role, or does not "
                + "bind this VM's project, zone, labels or service account, or the token's "
                + "audience is not the one Vault expects (http://vault/<role>)"),
                namespace, verify, timeoutMillis, clock);
    }

    /**
     * {@code azure}: the managed identity's token for {@code resource} (what
     * Vault's azure auth is configured with), and where the machine lives -
     * from {@code vm}, or the instance metadata service when it is
     * {@code null}.
     */
    public static VaultLogin azure(String address, String mount, String role, String resource,
            String clientId, String subscriptionId, String resourceGroup, String vmName,
            String vmScaleSetName, String namespace, boolean verify, int timeoutMillis) {
        requireRole(Method.AZURE, role);
        return azure(address, mount, role, new AzureManagedIdentitySecretProvider(
                resource == null || resource.isBlank() ? "https://management.azure.com/"
                        : resource, clientId, 16_384),
                azureVm(subscriptionId, resourceGroup, vmName, vmScaleSetName,
                        AzureManagedIdentitySecretProvider.IMDS_HOST, 80),
                namespace, verify, timeoutMillis, Clock.systemUTC());
    }

    /** Configured when all of it is given, from IMDS - once, then kept - otherwise. */
    static java.util.function.Supplier<Map<String, String>> azureVm(String subscriptionId,
            String resourceGroup, String vmName, String vmScaleSetName, String imdsHost,
            int imdsPort) {
        boolean configured = subscriptionId != null && !subscriptionId.isBlank()
                && resourceGroup != null && !resourceGroup.isBlank()
                && ((vmName != null && !vmName.isBlank())
                        || (vmScaleSetName != null && !vmScaleSetName.isBlank()));
        if (configured) {
            Map<String, String> fields = new VaultLoginBody.AzureVm(subscriptionId,
                    resourceGroup, vmName, vmScaleSetName).fields();
            fields.values().forEach(VaultLoginBody.Json::printable);
            return () -> fields;
        }
        if ((subscriptionId != null && !subscriptionId.isBlank())
                || (resourceGroup != null && !resourceGroup.isBlank())
                || (vmName != null && !vmName.isBlank())
                || (vmScaleSetName != null && !vmScaleSetName.isBlank())) {
            throw new IllegalArgumentException("an Azure login takes azure-subscription-id, "
                    + "azure-resource-group and azure-vm-name (or azure-vmss-name) together, "
                    + "or none of them to read them from the instance metadata service");
        }
        return new java.util.function.Supplier<>() {
            private Map<String, String> fields;

            @Override
            public synchronized Map<String, String> get() {
                if (fields == null) {
                    fields = VaultLoginBody.AzureVm.fromMetadata(imdsHost, imdsPort, 5_000)
                            .fields();
                }
                return fields;
            }
        };
    }

    static VaultLogin azure(String address, String mount, String role, SecretProvider token,
            java.util.function.Supplier<Map<String, String>> vm, String namespace,
            boolean verify, int timeoutMillis, Clock clock) {
        requireRole(Method.AZURE, role);
        return new VaultLogin(address, Method.AZURE, mount, role, new VaultLoginBody.Simple(
                "role", role, "jwt", token, vm, "Azure managed identity token",
                "400 or 403 usually means the role '" + role + "' does not bind this identity "
                + "(bound_service_principal_ids, bound_subscription_ids, bound_resource_groups), "
                + "or the token is for another resource than Vault's azure auth is configured "
                + "with (azure-resource)"), namespace, verify, timeoutMillis, clock);
    }

    private static void requireRole(Method method, String role) {
        if (role == null || role.isBlank()) {
            throw new IllegalArgumentException("a " + method.name().toLowerCase(Locale.ROOT)
                    + " login needs auth-role, the Vault role to log in as");
        }
    }

    private VaultLogin(String address, Method method, String mount, String role,
            VaultLoginBody body, String namespace, boolean verify, int timeoutMillis,
            Clock clock) {
        URI uri = URI.create(address);
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("a Vault login goes over https only, not "
                    + address + ": the request carries the JWT or the secret id, and the "
                    + "answer the token");
        }
        if ((method == Method.KUBERNETES || method == Method.APPROLE)
                && (role == null || role.isBlank())) {
            throw new IllegalArgumentException(method == Method.APPROLE
                    ? "an AppRole login needs auth-role-id"
                    : "a Kubernetes login needs auth-role, the Vault role bound to this "
                            + "service account");
        }
        String chosenMount = mount == null || mount.isBlank() ? method.defaultMount()
                : stripSlashes(mount);
        if (!chosenMount.matches("[A-Za-z0-9._/-]+") || chosenMount.contains("..")) {
            throw new IllegalArgumentException("not an auth mount path: '" + mount + "'");
        }
        this.host = uri.getHost();
        this.port = uri.getPort() > 0 ? uri.getPort() : 8200;
        this.verify = verify;
        this.timeoutMillis = timeoutMillis;
        this.namespace = namespace;
        this.method = method;
        this.mount = chosenMount;
        this.role = role == null || role.isBlank() ? null : role;
        if (this.role != null) {
            jsonText(this.role);                // refused now rather than at the first login
        }
        this.body = body;
        this.clock = clock;
        space.seclume.internal.Checkpoint.register(this, login -> login.forget(false));
    }

    private static String stripSlashes(String path) {
        String trimmed = path.trim();
        while (trimmed.startsWith("/")) {
            trimmed = trimmed.substring(1);
        }
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    /** How this login is made. */
    public Method method() {
        return method;
    }

    /** The path the method is mounted at, as in {@code auth/<mount>/login}. */
    public String mount() {
        return mount;
    }

    @Override
    public int maxSecretLength() {
        return TOKEN_ROOM;
    }

    /** Writes the current client token, logging in or renewing first when it is due. */
    @Override
    public synchronized int writeSecret(MemorySegment target) {
        ensureFresh();
        int length = token.length();
        if (length > target.byteSize()) {
            throw new SecretUnavailableException("the Vault token is " + length
                    + " bytes and does not fit into the " + target.byteSize() + " provided");
        }
        MemorySegment.copy(token.segment(), 0, target, 0, length);
        return length;
    }

    /**
     * Logs in, or renews or replaces the token, when that is due - without
     * handing the token out. {@link VaultSecretProvider} calls it before it
     * decides whether to renew a lease: a lease of a token that is about to
     * be replaced is not worth renewing.
     */
    synchronized void ensureFresh() {
        if (closed) {
            throw new SecretUnavailableException("this Vault login is closed");
        }
        if (token == null) {
            login();
        } else if (due()) {
            if (!renewable || !renewSelf()) {
                login();
            }
        }
    }

    /** When the current token ends, or {@code null} for one without a TTL or before the first login. */
    @Override
    public synchronized Instant credentialsValidUntil() {
        return validUntil;
    }

    /** Which login the current token comes from; it goes up with every new login. */
    public synchronized long generation() {
        return generation;
    }

    /**
     * When the token of the given {@link #generation()} ends: the current
     * one's end, the end the previous one had when it was replaced, or the
     * epoch for anything older - a token that has certainly gone, and with it
     * whatever it fetched. {@code null} for a token without a TTL.
     */
    public synchronized Instant validUntil(long ofGeneration) {
        if (ofGeneration == generation && token != null) {
            return validUntil;
        }
        if (ofGeneration == generation - 1 || (ofGeneration == generation && token == null)) {
            return retiredUntil;
        }
        return Instant.EPOCH;
    }

    /**
     * Drops the token in hand; the next {@link #writeSecret} logs in again.
     *
     * @param refused whether Vault refused it - revoked from outside, or
     *                expired early. Then what it fetched is gone now, not at
     *                the end of its TTL.
     */
    synchronized void forget(boolean refused) {
        if (token == null) {
            return;
        }
        retiredUntil = refused ? clock.instant() : validUntil;
        SecretScope wiped = token;
        token = null;
        wiped.close();
    }

    private boolean due() {
        if (validUntil == null) {
            return false;                       // a token without a TTL does not expire
        }
        Instant now = clock.instant();
        Duration whole = Duration.between(obtainedAt, validUntil);
        Instant half = obtainedAt.plus(Duration.ofMillis((long) (whole.toMillis() * REFRESH_AT)));
        Duration margin = whole.dividedBy(2).compareTo(LATEST_REFRESH) < 0 ? whole.dividedBy(2)
                : LATEST_REFRESH;
        return now.isAfter(half) || now.isAfter(validUntil.minus(margin));
    }

    // ------------------------------------------------------------ the login --

    private void login() {
        try (Arena arena = Arena.ofConfined();
             SecretScope request = body.write(arena);
             SecretScope answer = SecretScope.in(arena, SecretFetch.MAX_RESPONSE)) {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Content-Type", "application/json");
            if (namespace != null && !namespace.isEmpty()) {
                headers.put("X-Vault-Namespace", namespace);
            }
            SecretFetch.Response response;
            try {
                response = SecretFetch.sendSecretBody(host, port, verify, timeoutMillis, "POST",
                        "/v1/auth/" + mount + "/login", headers, List.of(),
                        new SecretFetch.SecretBody(request.segment(), request.length()),
                        answer.segment());
            } catch (IOException e) {
                throw new SecretUnavailableException("cannot reach Vault at " + host + ":" + port
                        + " to log in: " + e.getMessage(), e);
            }
            answer.length(response.bodyLength());
            if (!response.ok()) {
                // The answer is not quoted: an error from a login endpoint is
                // not a place to go looking for what is in it.
                throw new SecretUnavailableException("Vault refused the " + method.name()
                        .toLowerCase(Locale.ROOT) + " login at auth/" + mount + " with "
                        + response.status() + ". " + body.hint(role)
                        + (response.status() == 404 ? "; 404 that nothing is mounted at auth/"
                                + mount : ""));
            }
            take(answer, "auth");
        } catch (JsonOff.NotFound e) {
            throw new SecretUnavailableException("Vault answered the login, but not in a shape "
                    + "this understands: " + e.getMessage(), e);
        }
    }

    /**
     * Renews the token in hand. False when Vault will not, or grants too
     * little to be worth keeping - a token near its max TTL - and a new login
     * is the answer.
     */
    private boolean renewSelf() {
        try (Arena arena = Arena.ofConfined();
             SecretScope answer = SecretScope.in(arena, 64 * 1024)) {
            SecretFetch.Response response = send("POST", "/v1/auth/token/renew-self",
                    "{\"increment\":" + ttlSeconds + "}", answer.segment());
            if (!response.ok()) {
                return false;
            }
            answer.length(response.bodyLength());
            long granted = Math.min(JsonOff.number(answer.segment(), answer.length(),
                    "auth", "lease_duration"), VaultSecretProvider.MAX_LEASE_SECONDS);
            if (granted * 2 < ttlSeconds) {
                return false;
            }
            obtainedAt = clock.instant();
            validUntil = obtainedAt.plusSeconds(granted);
            return true;
        } catch (IOException | JsonOff.NotFound | SecretUnavailableException e) {
            return false;                       // a renewal that failed is a login, not an outage
        }
    }

    /** Takes {@code <root>.client_token} and its lease out of an answer. */
    private void take(SecretScope answer, String root) {
        SecretScope fresh = SecretScope.allocateShared(TOKEN_ROOM);
        try {
            int length = JsonOff.string(answer.segment(), answer.length(), fresh.segment(),
                    root, "client_token");
            if (length == 0) {
                throw new SecretUnavailableException("Vault answered the login with an empty "
                        + "token");
            }
            fresh.length(length);
            long ttl = JsonOff.has(answer.segment(), answer.length(), root, "lease_duration")
                    ? JsonOff.number(answer.segment(), answer.length(), root, "lease_duration")
                    : 0;
            ttl = Math.max(0, Math.min(ttl, VaultSecretProvider.MAX_LEASE_SECONDS));
            boolean canRenew = JsonOff.has(answer.segment(), answer.length(), root, "renewable")
                    && JsonOff.bool(answer.segment(), answer.length(), root, "renewable");

            SecretScope previous = token;
            Instant previousUntil = validUntil;
            Instant now = clock.instant();
            token = fresh;
            obtainedAt = now;
            validUntil = ttl > 0 ? now.plusSeconds(ttl) : null;
            ttlSeconds = ttl;
            renewable = canRenew;
            if (previous != null) {
                retiredUntil = previousUntil;
                previous.close();
            }
            generation++;
        } catch (Throwable e) {
            fresh.close();
            throw e;
        }
    }

    /** A request made with the token in hand, written from native memory. */
    private SecretFetch.Response send(String httpMethod, String path, String body,
            MemorySegment into) throws IOException {
        Map<String, String> headers = new LinkedHashMap<>();
        if (body != null) {
            headers.put("Content-Type", "application/json");
        }
        if (namespace != null && !namespace.isEmpty()) {
            headers.put("X-Vault-Namespace", namespace);
        }
        return SecretFetch.send(host, port, verify, timeoutMillis, httpMethod, path, headers,
                List.of(new SecretFetch.SecretHeader("X-Vault-Token", token.segment(),
                        token.length())),
                body, into);
    }

    // ------------------------------------------------------------ encoding --

    /** A role name or a role id in a JSON string: printable ASCII, quotes and backslashes escaped. */
    private static String jsonText(String text) {
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < 0x20 || c > 0x7e) {
                throw new IllegalArgumentException("a Vault role name or role id is printable "
                        + "ASCII; this one has a character outside it at " + i);
            }
        }
        return text.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    // ------------------------------------------------------------- closing --

    /** Revokes the token in hand - best effort - wipes it, and closes the credential's source. */
    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            if (token != null) {
                try (Arena arena = Arena.ofConfined();
                     SecretScope answer = SecretScope.in(arena, 16 * 1024)) {
                    send("POST", "/v1/auth/token/revoke-self", null, answer.segment());
                } catch (IOException | RuntimeException unreachable) {
                    // the token ends with its TTL
                }
                token.close();
                token = null;
            }
        } finally {
            body.close();
        }
    }

    @Override
    public String toString() {
        return "VaultLogin[" + method.name().toLowerCase(Locale.ROOT) + " at auth/" + mount
                + (role == null || method == Method.APPROLE ? "" : ", role " + role) + "]";
    }
}
