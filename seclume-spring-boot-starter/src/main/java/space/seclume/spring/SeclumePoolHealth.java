package space.seclume.spring;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;

import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;

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
 */
public final class SeclumePoolHealth implements HealthIndicator {

    private final List<SeclumePool> pools;

    public SeclumePoolHealth(List<SeclumePool> pools) {
        this.pools = List.copyOf(pools);
    }

    @Override
    public Health health() {
        Health.Builder health = Health.up();
        for (SeclumePool pool : pools) {
            PoolStatistics statistics = pool.statistics();
            String name = statistics.name();
            try (Connection connection = pool.getConnection()) {
                if (connection.isClosed()) {
                    return down(health, name, statistics, "the pool handed out a closed "
                            + "connection");
                }
            } catch (SQLException e) {
                return down(health, name, statistics, e.getMessage());
            }
            health.withDetail(name, describe(statistics));
        }
        return health.build();
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
