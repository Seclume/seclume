package space.seclume.spring;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLTransientConnectionException;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;

import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;

import space.seclume.Secured;
import space.seclume.pool.PoolStatistics;
import space.seclume.pool.SeclumePool;

/**
 * Whether the database is reachable - and what the pool looks like.
 *
 * <p>A health check that only says {@code UP} is worth little; the interesting
 * moment is the one just before it goes down, and that one is visible in the
 * numbers: a pool that is fully handed out with threads waiting is about to
 * become an incident.
 *
 * <p>What it does <b>not</b> do is run a query. Borrowing a connection is the
 * check: if none can be had within the pool's own timeout, that is exactly the
 * failure an application would hit. Adding a {@code select 1} on top would put
 * load on a server that is already struggling.
 *
 * <p>Nor does it borrow from a pool that has none to spare: with threads
 * waiting, or every connection handed out, a borrow would wait the pool's
 * full timeout and take a connection a request needed - and every probe,
 * every few seconds, would do it again. Such a pool is reported from its
 * numbers as {@code UNKNOWN}, which does not take the instance out; so is a
 * borrow that timed out, which says the pool is busy, not that the server is
 * gone. And the answer is kept for {@link #CACHED}: Kubernetes, a load
 * balancer and a dashboard asking at once borrow once.
 */
public final class SeclumePoolHealth implements HealthIndicator {

    /** How long one answer is given again. */
    static final Duration CACHED = Duration.ofSeconds(2);

    private final List<SeclumePool> pools;
    private final LongSupplier nanoTime;
    private Health last;
    private long lastAt;

    public SeclumePoolHealth(List<SeclumePool> pools) {
        this(pools, System::nanoTime);
    }

    SeclumePoolHealth(List<SeclumePool> pools, LongSupplier nanoTime) {
        this.pools = List.copyOf(pools);
        this.nanoTime = nanoTime;
    }

    @Override
    public synchronized Health health() {
        long now = nanoTime.getAsLong();
        if (last != null && now - lastAt < CACHED.toNanos()) {
            return last;
        }
        last = check();
        lastAt = now;
        return last;
    }

    /** Whether a borrow could only wait: threads already waiting, or none free and no room. */
    static boolean saturated(PoolStatistics statistics, int maximum) {
        return statistics.waiting() > 0
                || (statistics.idle() == 0 && statistics.total() >= maximum);
    }

    private Health check() {
        Health.Builder health = Health.up();
        int checked = 0;
        for (SeclumePool pool : pools) {
            PoolStatistics statistics = pool.statistics();
            String name = statistics.name();
            Map<String, Object> detail = new LinkedHashMap<>();
            detail.put("pool", describe(statistics));
            if (saturated(statistics, pool.settings().getMaximumPoolSize())) {
                detail.put("status", "UNKNOWN - no connection to spare, not borrowed for the check");
                health.withDetail(name, detail);
                continue;
            }
            try (Connection connection = pool.getConnection()) {
                if (connection.isClosed()) {
                    return down(health, name, statistics, "the pool handed out a closed "
                            + "connection");
                }
                // The grade goes along and never decides the status - see
                // SeclumeAssessment: a warning must not take the instance out.
                assess(pool, statistics, connection, detail);
            } catch (SQLException e) {
                if (busy(e)) {
                    // The pool's own timeout: every connection was in use for
                    // that long. Busy, not down - the next request may get one.
                    detail.put("status", "UNKNOWN - no connection free within the pool's timeout");
                    health.withDetail(name, detail);
                    continue;
                }
                // The server's words stay in the log: a health endpoint is
                // often anonymous, and "password authentication failed for
                // user app" or a host name is nothing to answer it with.
                return down(health, name, statistics, outward(e));
            }
            checked++;
            health.withDetail(name, detail);
        }
        if (checked == 0 && !pools.isEmpty()) {
            health.unknown();
        }
        return health.build();
    }

    /**
     * The pool's timeout with nothing behind it: every connection was in use.
     * One with a cause is the server refusing new connections - that is down.
     */
    static boolean busy(SQLException e) {
        return e instanceof SQLTransientConnectionException && "08003".equals(e.getSQLState())
                && e.getCause() == null;
    }

    /** What may leave the process about a failure: its kind and SQLState, not its text. */
    static String outward(SQLException e) {
        return e.getClass().getSimpleName()
                + (e.getSQLState() == null ? "" : " (SQLState " + e.getSQLState() + ")");
    }

    /**
     * The grade, where the driver can say how it is secured. A driver that
     * cannot - or answers the question wrongly - costs the grade, never the
     * health check: whether the database is reachable was already answered.
     */
    private static void assess(SeclumePool pool, PoolStatistics statistics,
                               Connection connection, Map<String, Object> detail) {
        try {
            if (!connection.isWrapperFor(Secured.class)) {
                return;
            }
            Secured secured = connection.unwrap(Secured.class);
            java.security.cert.X509Certificate shown = secured.serverCertificate();
            detail.putAll(SeclumeAssessment.of(secured.authenticationMethod(),
                    secured.tlsDescription(), secured.serverAuthenticated(),
                    shown == null ? null : shown.getNotAfter().toInstant(), statistics,
                    pool.settings().getMaximumPoolSize(), pool.resetsRefused(),
                    Instant.now()).asMap());
        } catch (SQLException | RuntimeException unknown) {
            detail.put("grade", "unknown - the driver cannot say how it is secured");
        }
    }

    private static Health down(Health.Builder health, String name,
                               PoolStatistics statistics, String reason) {
        return health.down()
                .withDetail(name, describe(statistics) + ", " + reason)
                .build();
    }

    /** Numbers only - never a statement, never a value, never a host. */
    private static String describe(PoolStatistics statistics) {
        return statistics.active() + " of " + statistics.total() + " in use, "
                + statistics.idle() + " free, " + statistics.waiting() + " waiting, "
                + statistics.timeouts() + " timeouts so far";
    }
}
