package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import space.seclume.internal.JsonOff;
import space.seclume.internal.SecretFetch;

/**
 * A secret from HashiCorp Vault, read without it becoming a {@code String}.
 *
 * <p>The Vault Java driver, like every other client, answers with a
 * {@code Map<String, String>}. The password is in it, on the heap, for as long
 * as the garbage collector takes - which for a library whose whole point is
 * that it is not there is a strange way to end. So the HTTP is
 * {@link SecretFetch} and the JSON is {@link JsonOff}: the answer lands in
 * native memory and the one field asked for is copied out of it into the
 * caller's segment. The rest of the response is wiped when the fetch returns.
 *
 * <h2>Both engines</h2>
 *
 * <p>The path decides, and the shape of the answer is detected rather than
 * configured:
 *
 * <ul>
 *   <li>{@code secret/data/app} - KV v2, a static secret at
 *       {@code data.data.<field>}, no lease.
 *   <li>{@code database/creds/app} - the <b>database secrets engine</b>, at
 *       {@code data.<field>}, with a {@code lease_duration}. Each request
 *       creates a new database user.
 * </ul>
 *
 * <h2>Why it caches, and why that is not laziness</h2>
 *
 * <p>A provider is normally asked once per physical connection. Against
 * {@code database/creds} that would create <b>one database user per
 * connection</b> and leave every one of them behind until its lease ran out -
 * a pool of sixteen would quietly accumulate hundreds of roles. So the
 * credential is fetched once and reused until it is close to expiring, which
 * is also how Vault expects its clients to behave.
 *
 * <p>The cached credential lives in a {@link SecretScope} - native, locked,
 * zeroed when this provider is closed or when it is replaced by a newer one.
 *
 * <h2>The part nobody else has</h2>
 *
 * <p>{@link #credentialsValidUntil()} reports when the credential stops
 * working, so {@code seclume-pool} can retire connections <b>before</b> they
 * start failing instead of after. Dynamic credentials without that are a
 * scheduled outage; with it they are just credentials.
 *
 * <p>The Vault token itself is a secret and comes from another provider - a
 * file, an agent socket, the Kubernetes service-account path. It is written
 * into the request from native memory and never concatenated into a header
 * string.
 */
public final class VaultSecretProvider implements SecretProvider, ExpiringCredentials {

    /** Fetch again once the remaining lease is under this fraction of its length. */
    private static final double REFRESH_AT = 0.5;
    /** And never later than this before the end, however long the lease is. */
    private static final Duration LATEST_REFRESH = Duration.ofSeconds(30);

    private final String host;
    private final int port;
    private final boolean verify;
    private final int timeoutMillis;
    private final String path;
    private final String field;
    private final String namespace;
    private final SecretProvider token;
    private final int maxLength;
    private final Clock clock;

    /** The credential in hand, or {@code null} before the first fetch. */
    private SecretScope cached;
    private Instant fetchedAt;
    private Instant validUntil;
    private boolean closed;

    /**
     * @param address   the Vault address, e.g. {@code https://vault:8200}
     * @param path      the secret path without the {@code /v1/} prefix
     * @param field     which field of the answer holds the secret
     * @param token     where the Vault token comes from
     * @param namespace a Vault Enterprise namespace, or {@code null}
     * @param verify    whether to check Vault's certificate - {@code false}
     *                  only for a development server, and it has to be said
     */
    public VaultSecretProvider(String address, String path, String field, SecretProvider token,
            String namespace, boolean verify, int timeoutMillis, int maxLength) {
        this(address, path, field, token, namespace, verify, timeoutMillis, maxLength,
                Clock.systemUTC());
    }

    /** The same with a clock of the caller's choosing - for the tests. */
    public VaultSecretProvider(String address, String path, String field, SecretProvider token,
            String namespace, boolean verify, int timeoutMillis, int maxLength, Clock clock) {
        URI uri = URI.create(address);
        if (!"https".equalsIgnoreCase(uri.getScheme()) && !"http".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException(
                    "the Vault address must be http:// or https://, not " + address);
        }
        if ("http".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("refusing to fetch a secret over plain http. "
                    + "Vault over http means the token and the password travel in the clear, "
                    + "which is worse than the file this was meant to replace");
        }
        this.host = uri.getHost();
        this.port = uri.getPort() > 0 ? uri.getPort() : 8200;
        this.verify = verify;
        this.timeoutMillis = timeoutMillis;
        this.path = path.startsWith("/") ? path.substring(1) : path;
        this.field = field;
        this.namespace = namespace;
        this.token = token;
        this.maxLength = maxLength;
        this.clock = clock;
    }

    @Override
    public int maxSecretLength() {
        return maxLength;
    }

    @Override
    public synchronized int writeSecret(MemorySegment target) {
        if (closed) {
            throw new SecretUnavailableException("this Vault provider is closed");
        }
        if (cached == null || dueForRefresh()) {
            refresh();
        }
        int length = cached.length();
        if (length > target.byteSize()) {
            throw new SecretUnavailableException("the secret from " + path + " is " + length
                    + " bytes and does not fit into the " + target.byteSize() + " provided");
        }
        MemorySegment.copy(cached.segment(), 0, target, 0, length);
        return length;
    }

    @Override
    public synchronized Instant credentialsValidUntil() {
        return validUntil;
    }

    /**
     * Halfway through the lease, or thirty seconds before the end.
     *
     * <p>Halfway is what Vault's own agent does and it leaves room for a
     * failed fetch to be retried. The absolute floor matters for a long lease,
     * where half of twenty-four hours would still be twelve hours of
     * confidence in a credential that might have been revoked.
     */
    private boolean dueForRefresh() {
        if (validUntil == null) {
            return false;                       // no lease: a static secret does not go stale
        }
        Instant now = clock.instant();
        Duration whole = Duration.between(fetchedAt, validUntil);
        Instant half = fetchedAt.plus(Duration.ofMillis((long) (whole.toMillis() * REFRESH_AT)));
        Instant latest = validUntil.minus(LATEST_REFRESH);
        return now.isAfter(half) || now.isAfter(latest);
    }

    private void refresh() {
        try (Arena arena = Arena.ofConfined();
             SecretScope answer = SecretScope.in(arena, SecretFetch.MAX_RESPONSE)) {

            SecretFetch.Response response = fetch(answer.segment());
            if (!response.ok()) {
                throw new SecretUnavailableException("Vault answered " + response.status()
                        + " for " + path + ". 403 means the token may not read this path, "
                        + "404 that the path or the mount does not exist");
            }
            answer.length(response.bodyLength());

            SecretScope fresh = SecretScope.allocate(maxLength);
            try {
                int length = extract(answer, fresh.segment());
                fresh.length(length);
                Instant now = clock.instant();
                long lease = JsonOff.has(answer.segment(), answer.length(), "lease_duration")
                        ? JsonOff.number(answer.segment(), answer.length(), "lease_duration")
                        : 0;

                SecretScope previous = cached;
                cached = fresh;
                fetchedAt = now;
                validUntil = lease > 0 ? now.plusSeconds(lease) : null;
                if (previous != null) {
                    previous.close();           // the old credential is wiped, not dropped
                }
            } catch (RuntimeException e) {
                fresh.close();
                throw e;
            }
        } catch (IOException e) {
            throw new SecretUnavailableException("cannot reach Vault at " + host + ":" + port
                    + ": " + e.getMessage(), e);
        } catch (JsonOff.NotFound e) {
            throw new SecretUnavailableException(
                    "Vault answered, but not in a shape this understands: " + e.getMessage(), e);
        }
    }

    /** KV v2 nests the data one level deeper than everything else does. */
    private int extract(SecretScope answer, MemorySegment out) {
        if (JsonOff.has(answer.segment(), answer.length(), "data", "data", field)) {
            return JsonOff.string(answer.segment(), answer.length(), out, "data", "data", field);
        }
        return JsonOff.string(answer.segment(), answer.length(), out, "data", field);
    }

    /** The request, with the token written in from native memory. */
    private SecretFetch.Response fetch(MemorySegment into) throws IOException {
        try (SecretScope vaultToken = SecretScope.fromProvider(token)) {
            Map<String, String> headers = namespace == null || namespace.isEmpty()
                    ? Map.of()
                    : Map.of("X-Vault-Namespace", namespace);
            return SecretFetch.send(host, port, verify, timeoutMillis, "GET", "/v1/" + path,
                    headers,
                    List.of(new SecretFetch.SecretHeader("X-Vault-Token",
                            vaultToken.segment(), vaultToken.length())),
                    null, into);
        }
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            if (cached != null) {
                cached.close();
                cached = null;
            }
        } finally {
            token.close();
        }
    }
}
