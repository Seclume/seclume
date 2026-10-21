package space.seclume.opentelemetry;

import java.util.List;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.metrics.DoubleHistogram;
import io.opentelemetry.api.metrics.Meter;

import space.seclume.pool.PoolListener;
import space.seclume.pool.PoolStatistics;
import space.seclume.pool.SeclumePool;

/**
 * A seclume pool under OpenTelemetry's semantic conventions for database
 * connection pools ({@code db.client.connection.*}), so a dashboard built for
 * those reads it without a mapping - plus the two numbers only this pool has:
 * secret rotations and refused session resets.
 *
 * <pre>
 *   AutoCloseable instruments = SeclumePoolInstruments.observe(otel, pool);
 *   ...
 *   instruments.close();                            // before the pool closes
 * </pre>
 *
 * <p>Counts are read from the pool's statistics when the SDK collects, so they
 * cost nothing between collections; the three times - waiting for a
 * connection, holding it, opening one - are recorded as they happen, through
 * the pool's listener.
 */
public final class SeclumePoolInstruments {

    private static final AttributeKey<String> POOL =
            AttributeKey.stringKey("db.client.connection.pool.name");
    private static final AttributeKey<String> STATE =
            AttributeKey.stringKey("db.client.connection.state");

    private SeclumePoolInstruments() {
    }

    /**
     * Instruments {@code pool} until the returned handle is closed.
     *
     * @return closes the observations and stops listening to the pool
     */
    public static AutoCloseable observe(OpenTelemetry openTelemetry, SeclumePool pool) {
        Meter meter = SeclumeMetrics.meter(openTelemetry);
        Attributes named = Attributes.of(POOL, pool.settings().getName());
        Attributes idle = named.toBuilder().put(STATE, "idle").build();
        Attributes used = named.toBuilder().put(STATE, "used").build();

        List<AutoCloseable> observations = List.of(
                meter.upDownCounterBuilder("db.client.connection.count")
                        .setUnit("{connection}")
                        .setDescription("connections the pool holds, by state")
                        .buildWithCallback(measurement -> {
                            PoolStatistics now = pool.statistics();
                            measurement.record(now.idle(), idle);
                            measurement.record(now.active(), used);
                        }),
                meter.upDownCounterBuilder("db.client.connection.idle.min")
                        .setUnit("{connection}")
                        .setDescription("the idle connections the pool keeps at least")
                        .buildWithCallback(measurement -> measurement.record(
                                pool.settings().getMinimumIdle(), named)),
                meter.upDownCounterBuilder("db.client.connection.max")
                        .setUnit("{connection}")
                        .setDescription("the connections the pool opens at most")
                        .buildWithCallback(measurement -> measurement.record(
                                pool.settings().getMaximumPoolSize(), named)),
                meter.upDownCounterBuilder("db.client.connection.pending_requests")
                        .setUnit("{request}")
                        .setDescription("threads waiting for a connection")
                        .buildWithCallback(measurement -> measurement.record(
                                pool.statistics().waiting(), named)),
                meter.counterBuilder("db.client.connection.timeouts")
                        .setUnit("{timeout}")
                        .setDescription("borrows that gave up waiting")
                        .buildWithCallback(measurement -> measurement.record(
                                pool.statistics().timeouts(), named)),
                meter.counterBuilder("seclume.pool.secret.rotations")
                        .setDescription("how often the pool's secret was rotated")
                        .buildWithCallback(measurement -> measurement.record(
                                pool.rotations(), named)),
                meter.counterBuilder("seclume.pool.resets.refused")
                        .setDescription("session resets refused or broken - each closed a "
                                + "connection")
                        .buildWithCallback(measurement -> measurement.record(
                                pool.resetsRefused(), named)));

        Timing timing = new Timing(named,
                seconds(meter, "db.client.connection.wait_time",
                        "time to get a connection, opening one included"),
                seconds(meter, "db.client.connection.use_time",
                        "time a connection was held by the application"),
                seconds(meter, "db.client.connection.create_time",
                        "time to open a connection, login included"));
        pool.listen(timing);

        return () -> {
            pool.unlisten(timing);
            for (AutoCloseable observation : observations) {
                observation.close();
            }
        };
    }

    private static DoubleHistogram seconds(Meter meter, String name, String description) {
        return meter.histogramBuilder(name).setUnit("s").setDescription(description).build();
    }

    /** The pool's timings, as they happen. */
    private record Timing(Attributes named, DoubleHistogram waitTime, DoubleHistogram useTime,
                          DoubleHistogram createTime) implements PoolListener {

        @Override
        public void acquired(long waitedNanos) {
            waitTime.record(waitedNanos / 1e9, named);
        }

        @Override
        public void released(long heldNanos) {
            useTime.record(heldNanos / 1e9, named);
        }

        @Override
        public void opened(long tookNanos) {
            createTime.record(tookNanos / 1e9, named);
        }
    }
}
