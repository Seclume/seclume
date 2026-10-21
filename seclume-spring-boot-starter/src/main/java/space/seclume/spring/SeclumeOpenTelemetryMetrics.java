package space.seclume.spring;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import io.opentelemetry.api.OpenTelemetry;

import space.seclume.opentelemetry.SeclumeMetrics;
import space.seclume.opentelemetry.SeclumePoolInstruments;
import space.seclume.pool.SeclumePool;

/**
 * {@code seclume-opentelemetry} for a Spring application: the events as
 * OpenTelemetry instruments and every pool under the connection-pool
 * conventions, through the application's own {@code OpenTelemetry} bean -
 * the counterpart of the Micrometer meters for an application that exports
 * with OpenTelemetry alone.
 *
 * <p>Started by {@code seclume.metrics.opentelemetry=true}; the query
 * threshold and the fingerprint bound are the Micrometer bridge's
 * properties. Closed with the context, which stops the recording stream and
 * every pool's observations.
 */
public final class SeclumeOpenTelemetryMetrics implements AutoCloseable {

    private final SeclumeMetrics events;
    private final List<AutoCloseable> pools = new ArrayList<>();

    SeclumeOpenTelemetryMetrics(OpenTelemetry openTelemetry, List<SeclumePool> pools,
                                Duration queryThreshold, int fingerprintBound) {
        this.events = SeclumeMetrics.start(openTelemetry, queryThreshold, fingerprintBound);
        for (SeclumePool pool : pools) {
            this.pools.add(SeclumePoolInstruments.observe(openTelemetry, pool));
        }
    }

    /** How many pools are observed - for the tests and the actuator. */
    public int pools() {
        return pools.size();
    }

    @Override
    public void close() {
        for (AutoCloseable pool : pools) {
            try {
                pool.close();
            } catch (Exception ignored) {
                // the next one is closed anyway
            }
        }
        pools.clear();
        events.close();
    }
}
