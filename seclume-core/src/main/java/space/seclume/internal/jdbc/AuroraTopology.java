package space.seclume.internal.jdbc;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Where an Aurora cluster's writer and readers are, as the cluster itself
 * last said - so that a failover does not wait for DNS.
 *
 * <pre>
 *   jdbc:seclume:postgresql://app.cluster-abc123.eu-central-1.rds.amazonaws.com/app
 *       ?aurora=true&amp;targetServerType=primary
 * </pre>
 *
 * <p>The cluster endpoint is a DNS name that points at the writer, and after a
 * failover it keeps pointing at the old one for as long as resolvers cache it
 * - half a minute and more. Every Aurora instance knows the whole cluster
 * ({@code aurora_replica_status()} on PostgreSQL,
 * {@code information_schema.replica_host_status} on MySQL). So after each
 * login the driver asks - at most once a second per cluster - and remembers
 * the instances; the next connect tries them directly, writer first for
 * {@code primary}, readers first for {@code secondary}, and the URL's own
 * hosts last. The server's own answer to "what are you" is still checked
 * after connecting, so a stale memory costs an attempt, never a wrong server.
 *
 * <p>An instance's host name is its identifier in the instance pattern:
 * {@code ?.abc123.eu-central-1.rds.amazonaws.com}, taken from a cluster
 * endpoint in the URL, or given as {@code auroraInstanceHost} (with
 * {@code :port} if the instances listen elsewhere than the URL says).
 */
public final class AuroraTopology implements ClusterTopology {

    /** The cluster as seen from PostgreSQL: {@code id=true,id=false,...}. */
    public static final String POSTGRESQL = "select string_agg(server_id || '=' || "
            + "(session_id = 'MASTER_SESSION_ID')::text, ',') from aurora_replica_status() "
            + "where session_id = 'MASTER_SESSION_ID' or last_update_timestamp is null "
            + "or last_update_timestamp > now() - interval '5 minutes'";

    /** The cluster as seen from MySQL: {@code id=1,id=0,...}. */
    public static final String MYSQL = "select group_concat(concat(server_id, '=', "
            + "session_id = 'MASTER_SESSION_ID')) from information_schema.replica_host_status "
            + "where session_id = 'MASTER_SESSION_ID' "
            + "or last_update_timestamp > now() - interval 5 minute";

    private static final Pattern CLUSTER_ENDPOINT = Pattern.compile(
            "[^.]+\\.cluster-(?:ro-|custom-)?(.+\\.rds\\.amazonaws\\.com(?:\\.cn)?)",
            Pattern.CASE_INSENSITIVE);
    private static final long REFRESH_NANOS = 1_000_000_000L;

    /** What each cluster said last, shared by every connection to it. */
    private static final Map<String, Known> CLUSTERS = new ConcurrentHashMap<>();

    private record Known(List<HostList.Host> writers, List<HostList.Host> readers, long at) {
    }

    private final String key;
    private final String pattern;
    private final int port;
    private final List<HostList.Host> urlHosts;

    private AuroraTopology(String key, String pattern, int port, List<HostList.Host> urlHosts) {
        this.key = key;
        this.pattern = pattern;
        this.port = port;
        this.urlHosts = List.copyOf(urlHosts);
    }

    /**
     * The {@code aurora} option, or null when it is off.
     *
     * @throws IllegalArgumentException when neither the URL nor
     *         {@code auroraInstanceHost} says how instances are named
     */
    public static AuroraTopology of(String option, String instanceHost,
                                    List<HostList.Host> urlHosts) {
        if (option == null || !(option.equalsIgnoreCase("true") || option.equals("1"))) {
            return null;
        }
        String pattern = instanceHost;
        int port = urlHosts.get(0).port();
        if (pattern == null) {
            Matcher cluster = CLUSTER_ENDPOINT.matcher(urlHosts.get(0).host());
            if (!cluster.matches()) {
                throw new IllegalArgumentException("aurora=true needs a cluster endpoint "
                        + "(name.cluster-id.region.rds.amazonaws.com) as the first host, or "
                        + "auroraInstanceHost=?.id.region.rds.amazonaws.com to name instances");
            }
            pattern = "?." + cluster.group(1);
        }
        if (!pattern.contains("?")) {
            throw new IllegalArgumentException("auroraInstanceHost needs a ? where the "
                    + "instance name goes: " + pattern);
        }
        int colon = pattern.lastIndexOf(':');
        if (colon > pattern.indexOf('?')) {
            port = Integer.parseInt(pattern.substring(colon + 1));
            pattern = pattern.substring(0, colon);
        }
        return new AuroraTopology(pattern.toLowerCase(Locale.ROOT) + ":" + port, pattern, port,
                urlHosts);
    }

    @Override
    public List<HostList.Host> hosts(TargetServer wanted) {
        Known known = CLUSTERS.get(key);
        if (known == null) {
            return List.of();
        }
        List<HostList.Host> ordered = new ArrayList<>();
        if (wanted == TargetServer.SECONDARY) {
            ordered.addAll(known.readers());
            ordered.addAll(known.writers());
        } else {
            ordered.addAll(known.writers());
            ordered.addAll(known.readers());
        }
        for (HostList.Host own : urlHosts) {
            if (!ordered.contains(own)) {
                ordered.add(own);                   // the cluster endpoint, last
            }
        }
        return ordered;
    }

    /** When each cluster last refused the question - not Aurora, or no right to ask. */
    private static final Map<String, Long> REFUSED = new ConcurrentHashMap<>();

    /**
     * Whether it is time to ask again - once a second per cluster at most, and
     * not for a minute after a server refused the question.
     */
    public boolean due() {
        Long refused = REFUSED.get(key);
        if (refused != null && System.nanoTime() - refused < 60 * REFRESH_NANOS) {
            return false;
        }
        Known known = CLUSTERS.get(key);
        return known == null || System.nanoTime() - known.at() > REFRESH_NANOS;
    }

    /** The server did not answer the question - asked again in a minute. */
    public void refused() {
        REFUSED.put(key, System.nanoTime());
    }

    /**
     * Takes what an instance answered to {@link #POSTGRESQL} or {@link #MYSQL}.
     * An empty or unreadable answer changes nothing: the last good one stays.
     */
    public void learn(String answer) {
        if (answer == null || answer.isBlank()) {
            return;
        }
        List<HostList.Host> writers = new ArrayList<>();
        List<HostList.Host> readers = new ArrayList<>();
        for (String entry : answer.split(",")) {
            int equals = entry.lastIndexOf('=');
            if (equals <= 0) {
                continue;
            }
            String id = entry.substring(0, equals).trim();
            if (!id.matches("[A-Za-z0-9._-]+")) {
                continue;                           // not an instance name
            }
            String flag = entry.substring(equals + 1).trim().toLowerCase(Locale.ROOT);
            HostList.Host host = new HostList.Host(pattern.replace("?", id), port);
            if (flag.equals("true") || flag.equals("t") || flag.equals("1")) {
                writers.add(host);
            } else {
                readers.add(host);
            }
        }
        if (!writers.isEmpty() || !readers.isEmpty()) {
            CLUSTERS.put(key, new Known(List.copyOf(writers), List.copyOf(readers),
                    System.nanoTime()));
        }
    }

    /** For tests: forgets every cluster. */
    static void forgetAll() {
        CLUSTERS.clear();
        REFUSED.clear();
    }
}
