package space.seclume.internal.jdbc;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * What this process has learned about each server it connects to.
 *
 * <p>Per server, not per URL or per pool: how fast a server answers and how
 * often it fails are facts about the server, and two pools pointing at the
 * same cluster should not each have to find out on their own that one node is
 * down. It is keyed by {@code host:port}, so it is bounded by the
 * configuration, the same argument {@code ClientIdentities} makes for its
 * cache.
 *
 * <p>Four things are kept, and only things that were measured:
 * <ul>
 *   <li><b>connect time</b> - an exponentially weighted moving average of how
 *       long a successful open took, TLS and login included, which is what a
 *       caller waits for;</li>
 *   <li><b>failure rate</b> - the same average over "did the open fail with a
 *       connection error", 0 or 1 per attempt. A rejected password is not
 *       counted: it says nothing about the server;</li>
 *   <li><b>consecutive failures</b> and when the last one was, which put a
 *       server that has just failed into a back-off - 1 s, doubling, at most
 *       30 s - during which it is tried last rather than first. Never
 *       skipped: when everything else is down, the last resort is still
 *       tried;</li>
 *   <li><b>the role</b> the server last reported, so a list looking for a
 *       primary asks the one that was the primary first.</li>
 * </ul>
 *
 * <p><b>Exploration.</b> A policy that always takes the best-known server
 * never finds out that another one got better. So a measurement older than
 * {@link #STALE_NANOS} counts as none, and a server without a measurement is
 * tried <em>first</em> - once, which renews it. On a list of three with one
 * slow node that costs one slow connect per minute, and it is how a node that
 * was slow during a restart gets its traffic back. A server that is down
 * costs the same: one failed attempt a minute, which is the price of noticing
 * when it is back.
 */
public final class HostQuality {

    /** Weight of the newest sample; 0.3 forgets a spike within a handful of connects. */
    static final double ALPHA = 0.3;

    /** After this long without a sample, a server is re-measured. */
    static final long STALE_NANOS = 60_000_000_000L;

    static final long FIRST_BACKOFF_NANOS = 1_000_000_000L;
    static final long MAX_BACKOFF_NANOS = 30_000_000_000L;

    /**
     * How much a failure weighs against speed: a server failing half its
     * connects scores as if it were three times slower. A number has to be
     * picked; this one makes an unreliable fast node lose to a reliable one
     * that is not much slower, which is the trade anyone would make by hand.
     */
    static final double FAILURE_WEIGHT = 4.0;

    private static final Map<HostList.Host, Stats> STATS = new ConcurrentHashMap<>();

    /** Replaced by tests, which need time to pass on command. */
    static volatile LongSupplier clock = System::nanoTime;

    private HostQuality() {
    }

    /** One server's figures, as they stand. */
    public record Sample(HostList.Host host, double connectMillis, double failureRate,
            int consecutiveFailures, ServerRole role, long samples) {
    }

    private static final class Stats {
        double connectNanos;
        double failureRate;
        int consecutiveFailures;
        long lastFailure;
        long lastSample;
        long samples;
        ServerRole role = ServerRole.UNKNOWN;
    }

    static void succeeded(HostList.Host host, long nanos) {
        Stats stats = STATS.computeIfAbsent(host, ignored -> new Stats());
        synchronized (stats) {
            long at = clock.getAsLong();
            forgetIfStale(stats, at);
            stats.connectNanos = stats.connectNanos == 0 ? nanos
                    : ALPHA * nanos + (1 - ALPHA) * stats.connectNanos;
            stats.failureRate = (1 - ALPHA) * stats.failureRate;
            stats.consecutiveFailures = 0;
            stats.lastSample = at;
            stats.samples++;
        }
    }

    static void failed(HostList.Host host) {
        Stats stats = STATS.computeIfAbsent(host, ignored -> new Stats());
        synchronized (stats) {
            forgetIfStale(stats, clock.getAsLong());
            stats.failureRate = ALPHA + (1 - ALPHA) * stats.failureRate;
            stats.consecutiveFailures++;
            stats.lastFailure = clock.getAsLong();
            stats.lastSample = stats.lastFailure;
            stats.samples++;
        }
    }

    /**
     * A stale figure is replaced by the next one, not averaged with it:
     * "counts as none" has to hold for the renewal too, or a server that was
     * slow a minute ago and fast now would still carry most of the old number.
     */
    private static void forgetIfStale(Stats stats, long at) {
        if (stats.samples > 0 && at - stats.lastSample >= STALE_NANOS) {
            stats.connectNanos = 0;
            stats.failureRate = 0;
        }
    }

    static void role(HostList.Host host, ServerRole role) {
        Stats stats = STATS.computeIfAbsent(host, ignored -> new Stats());
        synchronized (stats) {
            stats.role = role;
        }
    }

    /**
     * The order to try these servers in, best first.
     *
     * <p>In three bands - servers without a current measurement, then the
     * measured ones by score, then the ones in back-off - and within each
     * band the configured order breaks ties, so a list whose servers are all
     * equal behaves like the list as written. A server whose last known role
     * is not what the list is looking for goes behind the others of its band.
     *
     * @return indices into {@code hosts}
     */
    static int[] order(List<HostList.Host> hosts, TargetServer target) {
        long now = clock.getAsLong();
        record Ranked(int index, int band, int wrongRole, double score) {
        }
        List<Ranked> ranked = new ArrayList<>(hosts.size());
        for (int i = 0; i < hosts.size(); i++) {
            Stats stats = STATS.get(hosts.get(i));
            if (stats == null) {
                ranked.add(new Ranked(i, 0, 0, 0));
                continue;
            }
            synchronized (stats) {
                int wrongRole = target.accepts(stats.role) ? 0 : 1;
                if (stats.consecutiveFailures > 0
                        && now - stats.lastFailure < backoff(stats.consecutiveFailures)) {
                    ranked.add(new Ranked(i, 2, wrongRole, stats.consecutiveFailures));
                } else if (now - stats.lastSample >= STALE_NANOS) {
                    ranked.add(new Ranked(i, 0, wrongRole, 0));
                } else if (stats.connectNanos == 0) {
                    // Out of back-off but never once connected: behind every
                    // server that has, until its measurement goes stale.
                    ranked.add(new Ranked(i, 1, wrongRole, Double.MAX_VALUE));
                } else {
                    ranked.add(new Ranked(i, 1, wrongRole,
                            stats.connectNanos * (1 + FAILURE_WEIGHT * stats.failureRate)));
                }
            }
        }
        ranked.sort(Comparator.comparingInt(Ranked::band)
                .thenComparingInt(Ranked::wrongRole)
                .thenComparingDouble(Ranked::score)
                .thenComparingInt(Ranked::index));
        int[] order = new int[ranked.size()];
        for (int i = 0; i < order.length; i++) {
            order[i] = ranked.get(i).index();
        }
        return order;
    }

    /** 1 s after the first failure, doubling, at most 30 s. */
    static long backoff(int consecutiveFailures) {
        int doublings = Math.min(consecutiveFailures - 1, 5);
        return Math.min(FIRST_BACKOFF_NANOS << doublings, MAX_BACKOFF_NANOS);
    }

    /** Everything known, for metrics, a diagnostic page, or a test. */
    public static List<Sample> snapshot() {
        List<Sample> all = new ArrayList<>();
        STATS.forEach((host, stats) -> {
            synchronized (stats) {
                all.add(new Sample(host, stats.connectNanos / 1e6, stats.failureRate,
                        stats.consecutiveFailures, stats.role, stats.samples));
            }
        });
        all.sort(Comparator.comparing(sample -> sample.host().toString()));
        return all;
    }

    /** Forgets everything - for tests, and nothing else. */
    static void forget() {
        STATS.clear();
    }
}
