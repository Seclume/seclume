package space.seclume.spring;

import java.util.List;
import java.util.concurrent.TimeUnit;

import io.micrometer.core.instrument.FunctionCounter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.binder.MeterBinder;

import space.seclume.pool.PoolListener;
import space.seclume.pool.SeclumePool;

/**
 * The pool's numbers, for whatever collects metrics.
 *
 * <p>Most of it is in {@link SeclumePool#statistics()} already. What this adds
 * is that a dashboard finds it without anybody writing glue code, which is the
 * difference between a number that exists and a number that is looked at -
 * and the durations the statistics cannot give: how long a borrower waited,
 * how long a connection was held, how long opening one took, as timers with a
 * distribution (see {@link PoolListener}).
 *
 * <p><b>Hikari-compatible names, if asked for.</b> Whoever migrates has
 * dashboards and alerts built on {@code hikaricp.connections.*}, and rebuilding
 * them is a reason not to migrate. So the same meters can be registered a
 * second time under those names - switched on with
 * {@code seclume.metrics.hikari-names=true}, and off by default: a meter
 * called {@code hikaricp} that is not HikariCP should be a deliberate choice,
 * not a surprise.
 */
public final class SeclumePoolMetrics implements MeterBinder, AutoCloseable {

    private final List<SeclumePool> pools;
    private final boolean hikariNames;
    /** What bindTo() hung on the pools - taken off again in close(). */
    private final List<Registered> registered = new java.util.concurrent.CopyOnWriteArrayList<>();

    private record Registered(SeclumePool pool, PoolListener listener) {
    }

    /**
     * @param pools       every pool of the application
     * @param hikariNames whether the same meters also appear under the names
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
            // The configured maximum. It reported the connections held, so a
            // dashboard dividing active by max showed the wrong saturation.
            gauge(registry, "seclume.pool.connections.max", tags, pool,
                    "the configured maximum", p -> p.settings().getMaximumPoolSize());
            // Counters, not gauges: they only grow, and only a counter lets a
            // backend take a rate across a restart of the application.
            counter(registry, "seclume.pool.borrowed", tags, pool,
                    "connections handed out since the start", p -> p.statistics().borrowed());
            counter(registry, "seclume.pool.created", tags, pool,
                    "connections opened since the start", p -> p.statistics().created());
            counter(registry, "seclume.pool.retired", tags, pool,
                    "connections thrown away since the start", p -> p.statistics().retired());
            counter(registry, "seclume.pool.timeouts", tags, pool,
                    "borrows that gave up waiting", p -> p.statistics().timeouts());
            counter(registry, "seclume.pool.leaks", tags, pool,
                    "connections reported as forgotten", p -> p.statistics().leaksReported());
            counter(registry, "seclume.pool.renewed", tags, pool,
                    "connections rebuilt under the application after they broke",
                    p -> p.statistics().renewed());
            counter(registry, "seclume.pool.secret.rotations", tags, pool,
                    "how often the secret was rotated", SeclumePool::rotations);
            counter(registry, "seclume.pool.resets.refused", tags, pool,
                    "session resets refused or broken - each closed a connection",
                    SeclumePool::resetsRefused);

            Timer acquire = timer(registry, "seclume.pool.acquire", tags,
                    "time to get a connection, opening one included");
            Timer usage = timer(registry, "seclume.pool.usage", tags,
                    "time a connection was held by the application");
            Timer creation = timer(registry, "seclume.pool.creation", tags,
                    "time to open a connection, login included");
            Timer[] hikari = hikariNames ? new Timer[] {
                timer(registry, "hikaricp.connections.acquire", tags, "time to get a connection"),
                timer(registry, "hikaricp.connections.usage", tags, "time a connection was held"),
                timer(registry, "hikaricp.connections.creation", tags,
                        "time to open a connection")} : null;
            Timing timing = new Timing(acquire, usage, creation, hikari);
            pool.listen(timing);
            registered.add(new Registered(pool, timing));

            if (hikariNames) {
                // The same numbers under the names an existing dashboard asks
                // for. Deliberately the set Hikari publishes, no more.
                gauge(registry, "hikaricp.connections", tags, pool,
                        "connections this pool holds", p -> p.statistics().total());
                gauge(registry, "hikaricp.connections.active", tags, pool,
                        "connections handed out right now", p -> p.statistics().active());
                gauge(registry, "hikaricp.connections.idle", tags, pool,
                        "connections waiting to be handed out", p -> p.statistics().idle());
                gauge(registry, "hikaricp.connections.pending", tags, pool,
                        "threads waiting for a connection", p -> p.statistics().waiting());
                gauge(registry, "hikaricp.connections.max", tags, pool,
                        "the configured maximum", p -> p.settings().getMaximumPoolSize());
                gauge(registry, "hikaricp.connections.min", tags, pool,
                        "the configured minimum idle", p -> p.settings().getMinimumIdle());
                counter(registry, "hikaricp.connections.timeout", tags, pool,
                        "borrows that gave up waiting", p -> p.statistics().timeouts());
            }
        }
    }

    /**
     * Takes the timers off the pools. Spring calls this when the context
     * closes or is refreshed, so a pool that outlives it does not keep
     * recording into a registry nobody reads any more.
     */
    @Override
    public void close() {
        for (Registered one : registered) {
            one.pool().unlisten(one.listener());
        }
        registered.clear();
    }

    /** The pool's durations into the timers - on the hot path, so nothing else. */
    private record Timing(Timer acquire, Timer usage, Timer creation, Timer[] hikari)
            implements PoolListener {

        @Override
        public void acquired(long waitedNanos) {
            acquire.record(waitedNanos, TimeUnit.NANOSECONDS);
            if (hikari != null) {
                hikari[0].record(waitedNanos, TimeUnit.NANOSECONDS);
            }
        }

        @Override
        public void released(long heldNanos) {
            usage.record(heldNanos, TimeUnit.NANOSECONDS);
            if (hikari != null) {
                hikari[1].record(heldNanos, TimeUnit.NANOSECONDS);
            }
        }

        @Override
        public void opened(long tookNanos) {
            creation.record(tookNanos, TimeUnit.NANOSECONDS);
            if (hikari != null) {
                hikari[2].record(tookNanos, TimeUnit.NANOSECONDS);
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

    private static void counter(MeterRegistry registry, String name, Tags tags,
                                SeclumePool pool, String description,
                                java.util.function.ToDoubleFunction<SeclumePool> value) {
        FunctionCounter.builder(name, pool, value)
                .tags(tags)
                .description(description)
                .register(registry);
    }

    private static Timer timer(MeterRegistry registry, String name, Tags tags,
                               String description) {
        return Timer.builder(name)
                .tags(tags)
                .description(description)
                .publishPercentileHistogram()
                .register(registry);
    }
}
