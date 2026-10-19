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
 * <h2>The user, the renewal, the revocation</h2>
 *
 * <p>A credential from {@code database/creds} is a user and its password, and
 * the user is a new one each time: {@link #currentUser()} hands it to the
 * driver, which logs in with it ({@link DynamicUser}). Halfway through the
 * lease the lease is <b>renewed</b> ({@code sys/leases/renew}) - the same
 * user, longer - for as long as Vault extends it; only when the role's
 * {@code max_ttl} caps the renewal is a new user fetched. When the provider
 * is closed the lease is <b>revoked</b>, and Vault drops the user then rather
 * than at the end of its lease.
 *
 * <p>The Vault token itself is a secret and comes from another provider - a
 * file, an agent socket, the Kubernetes service-account path. It is written
 * into the request from native memory and never concatenated into a header
 * string.
 */
public final class VaultSecretProvider implements SecretProvider, ExpiringCredentials,
        DynamicUser {

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

    /** Ten years. See {@link #refresh}. */
    static final long MAX_LEASE_SECONDS = 10L * 366 * 24 * 3600;

    /** The credential in hand, or {@code null} before the first fetch. */
    private SecretScope cached;
    private Instant fetchedAt;
    private Instant validUntil;
    private boolean closed;
    /** The lease of the credential in hand - an id, not a secret - and its length as granted. */
    private String leaseId;
    private long leaseSeconds;
    /** The database user of the credential in hand, from {@code data.username}; or null. */
    private String username;
    /** Set when the user was handed out: the password read next is that user's, unchanged. */
    private boolean userHandedOut;

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
        space.seclume.internal.Checkpoint.register(this, VaultSecretProvider::forgetCached);
    }

    /**
     * Wipes the cached credential; the next read fetches it again. Called
     * before a checkpoint, so that the image does not carry it.
     */
    private synchronized void forgetCached() {
        if (cached != null) {
            SecretScope wiped = cached;
            cached = null;
            validUntil = null;
            wiped.close();
        }
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
        if (cached == null || (dueForRefresh() && !userHandedOut)) {
            renewOrRefresh();
        }
        userHandedOut = false;
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
     * The database user of the credential the next {@link #writeSecret} will
     * write - renewed or replaced here, if it is due, so that the two belong
     * together.
     */
    @Override
    public synchronized String currentUser() {
        if (closed) {
            throw new SecretUnavailableException("this Vault provider is closed");
        }
        if (cached == null || dueForRefresh()) {
            renewOrRefresh();
        }
        userHandedOut = true;
        return username;
    }

    /**
     * Extends the lease when there is one Vault will extend; fetches a new
     * credential when it will not, or no longer far enough - a lease capped
     * by its role's {@code max_ttl} ends whatever is asked for.
     */
    private void renewOrRefresh() {
        if (cached != null && leaseId != null && renew()) {
            return;
        }
        refresh();
    }

    private boolean renew() {
        try (Arena arena = Arena.ofConfined();
             SecretScope answer = SecretScope.in(arena, 64 * 1024)) {
            SecretFetch.Response response = send("PUT", "/v1/sys/leases/renew",
                    "{\"lease_id\":\"" + jsonText(leaseId) + "\",\"increment\":"
                            + leaseSeconds + "}", answer.segment());
            if (!response.ok()) {
                return false;                  // not renewable, or gone: a new credential
            }
            answer.length(response.bodyLength());
            long granted = Math.min(JsonOff.number(answer.segment(), answer.length(),
                    "lease_duration"), MAX_LEASE_SECONDS);
            Instant now = clock.instant();
            Instant until = now.plusSeconds(granted);
            // Worth keeping only if it grants at least half a lease more: near
            // max_ttl Vault grants what is left, and a renewal that was due
            // again at once would only put the new user off.
            if (granted * 2 < leaseSeconds) {
                return false;
            }
            fetchedAt = now;
            validUntil = until;
            return true;
        } catch (IOException | JsonOff.NotFound | SecretUnavailableException e) {
            return false;                      // a renewal that failed is a fetch, not an outage
        }
    }

    /** A lease id in a JSON string: it is Vault's own path-like id, quotes and backslashes escaped. */
    private static String jsonText(String text) {
        return text.replace("\\", "\\\\").replace("\"", "\\\"");
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
        // Thirty seconds, or half a lease shorter than a minute: thirty
        // seconds before the end of a twenty second lease lie before it began,
        // and every connection fetched a new user.
        Duration margin = whole.dividedBy(2).compareTo(LATEST_REFRESH) < 0 ? whole.dividedBy(2)
                : LATEST_REFRESH;
        Instant latest = validUntil.minus(margin);
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

            // Shared, not confined: the credential is fetched on whichever
            // thread happens to log in first - often the pool's housekeeper -
            // and read and closed by others. In a confined arena every read
            // from another thread threw WrongThreadException, and so did the
            // wipe in close(): the credential stayed in native memory, unwiped,
            // until the process ended.
            SecretScope fresh = SecretScope.allocateShared(maxLength);
            try {
                int length = extract(answer, fresh.segment());
                fresh.length(length);
                Instant now = clock.instant();
                long lease = JsonOff.has(answer.segment(), answer.length(), "lease_duration")
                        ? JsonOff.number(answer.segment(), answer.length(), "lease_duration")
                        : 0;
                // A lease longer than this is not one Vault hands out (its
                // max_ttl defaults to 32 days); taken at face value, it made
                // the refresh arithmetic overflow on every later read. Shorter
                // is the safe direction: the credential is only fetched sooner.
                lease = Math.min(lease, MAX_LEASE_SECONDS);

                SecretScope previous = cached;
                cached = fresh;
                fetchedAt = now;
                validUntil = lease > 0 ? now.plusSeconds(lease) : null;
                leaseSeconds = lease;
                leaseId = lease > 0 ? text(answer, "lease_id") : null;
                // The database engine's user, beside the password; a KV secret
                // nests its fields one level deeper and names no user here.
                username = text(answer, "data", "username");
                if (previous != null) {
                    previous.close();           // the old credential is wiped, not dropped
                }
            } catch (Throwable e) {
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

    /** A field that is no secret - a lease id, a user name - as text; null when absent or empty. */
    private static String text(SecretScope answer, String... field) {
        if (!JsonOff.has(answer.segment(), answer.length(), field)) {
            return null;
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(1024);
            int length = JsonOff.string(answer.segment(), answer.length(), out, field);
            // seclume-allow: a lease id or a database user name - neither is a secret
            String value = new String(out.asSlice(0, length).toArray(
                    java.lang.foreign.ValueLayout.JAVA_BYTE), java.nio.charset.StandardCharsets.UTF_8);
            return value.isEmpty() ? null : value;
        } catch (RuntimeException notText) {      // JsonOff.NotFound among them
            return null;
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
        return send("GET", "/v1/" + path, null, into);
    }

    /** Any request to Vault: the token from native memory, a body that is no secret. */
    private SecretFetch.Response send(String method, String requestPath, String body,
            MemorySegment into) throws IOException {
        try (SecretScope vaultToken = SecretScope.fromProvider(token)) {
            Map<String, String> headers = namespace == null || namespace.isEmpty()
                    ? Map.of()
                    : Map.of("X-Vault-Namespace", namespace);
            return SecretFetch.send(host, port, verify, timeoutMillis, method, requestPath,
                    headers,
                    List.of(new SecretFetch.SecretHeader("X-Vault-Token",
                            vaultToken.segment(), vaultToken.length())),
                    body, into);
        }
    }

    /**
     * Gives the lease back: Vault drops the database user now, not at the
     * end of its lease. Best effort - a Vault that cannot be reached lets the
     * lease run out by itself.
     */
    private void revoke() {
        if (leaseId == null) {
            return;
        }
        try (Arena arena = Arena.ofConfined();
             SecretScope answer = SecretScope.in(arena, 16 * 1024)) {
            send("PUT", "/v1/sys/leases/revoke", "{\"lease_id\":\"" + jsonText(leaseId)
                    + "\"}", answer.segment());
        } catch (IOException | RuntimeException unreachable) {
            // the lease ends on its own
        } finally {
            leaseId = null;
        }
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            revoke();
            if (cached != null) {
                cached.close();
                cached = null;
            }
        } finally {
            token.close();
        }
    }
}
