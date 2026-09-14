package space.seclume.spring;

import java.util.List;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.binder.MeterBinder;

import space.seclume.pool.SeclumePool;

/**
 * The pool's numbers, for whatever collects metrics.
 *
 * <p>Nothing here is new information - {@link SeclumePool#statistics()} has
 * it all. What this adds is that a dashboard finds it without anybody writing
 * glue code, which is the difference between a number that exists and a number
 * that is looked at.
 *
 * <p><b>Hikari-compatible names, if asked for.</b> Whoever migrates has
 * dashboards and alerts built on {@code hikaricp.connections.*}, and rebuilding
 * them is a reason not to migrate. So the same gauges can be registered a
 * second time under those names - switched on with
 * {@code seclume.metrics.hikari-names=true}, and off by default: a meter
 * called {@code hikaricp} that is not HikariCP should be a deliberate choice,
 * not a surprise.
 */
public final class SeclumePoolMetrics implements MeterBinder {

    private final List<SeclumePool> pools;
    private final boolean hikariNames;

    /**
     * @param pools       every pool of the application
     * @param hikariNames whether the same gauges also appear under the names
     *                    HikariCP uses
     */
    public SeclumePoolMetrics(List<SeclumePool> pools, boolean hikariNames) {
        this.pools = List.copyOf(pools);
        this.hikariNames = hikariNames;
    }

    @Override
    public void bindTo(MeterRegistry registry) {
        for (SeclumePool pool : pools) {
            Tags tags = Tags.of("pool", pool.statistics().name());
            gauge(registry, "seclume.pool.connections", tags, pool,
                    "connections this pool holds", p -> p.statistics().total());
            gauge(registry, "seclume.pool.connections.active", tags, pool,
                    "connections handed out right now", p -> p.statistics().active());
            gauge(registry, "seclume.pool.connections.idle", tags, pool,
                    "connections waiting to be handed out", p -> p.statistics().idle());
            gauge(registry, "seclume.pool.connections.pending", tags, pool,
                    "threads waiting for a connection", p -> p.statistics().waiting());
            gauge(registry, "seclume.pool.connections.max", tags, pool,
                    "the configured maximum", p -> p.statistics().total());
            gauge(registry, "seclume.pool.borrowed", tags, pool,
                    "connections handed out since the start", p -> p.statistics().borrowed());
            gauge(registry, "seclume.pool.created", tags, pool,
                    "connections opened since the start", p -> p.statistics().created());
            gauge(registry, "seclume.pool.retired", tags, pool,
                    "connections thrown away since the start", p -> p.statistics().retired());
            gauge(registry, "seclume.pool.timeouts", tags, pool,
                    "borrows that gave up waiting", p -> p.statistics().timeouts());
            gauge(registry, "seclume.pool.leaks", tags, pool,
                    "connections reported as forgotten", p -> p.statistics().leaksReported());
            gauge(registry, "seclume.pool.renewed", tags, pool,
                    "connections rebuilt under the application after they broke",
                    p -> p.statistics().renewed());
            gauge(registry, "seclume.pool.secret.rotations", tags, pool,
                    "how often the secret was rotated", SeclumePool::rotations);

            if (hikariNames) {
                // The same numbers under the names an existing dashboard asks
                // for. Deliberately the same set Hikari publishes, no more.
                gauge(registry, "hikaricp.connections", tags, pool,
                        "connections this pool holds", p -> p.statistics().total());
                gauge(registry, "hikaricp.connections.active", tags, pool,
                        "connections handed out right now", p -> p.statistics().active());
                gauge(registry, "hikaricp.connections.idle", tags, pool,
                        "connections waiting to be handed out", p -> p.statistics().idle());
                gauge(registry, "hikaricp.connections.pending", tags, pool,
                        "threads waiting for a connection", p -> p.statistics().waiting());
                gauge(registry, "hikaricp.connections.timeout", tags, pool,
                        "borrows that gave up waiting", p -> p.statistics().timeouts());
            }
        }
    }

    private static void gauge(MeterRegistry registry, String name, Tags tags,
                              SeclumePool pool, String description,
                              java.util.function.ToDoubleFunction<SeclumePool> value) {
        Gauge.builder(name, pool, value)
                .tags(tags)
                .description(description)
                .register(registry);
    }
}
