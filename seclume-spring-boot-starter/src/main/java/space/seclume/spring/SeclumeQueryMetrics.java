package space.seclume.spring;

import java.time.Duration;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.binder.MeterBinder;

import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingStream;

/**
 * The Flight Recorder's events, as meters an operator already has a dashboard
 * for.
 *
 * <p>JFR is the better recording - it costs nothing when nobody is listening,
 * it is in the JDK, and it carries more than a counter can. It is also read by
 * almost nobody, because reading it means somebody noticing a problem, dumping
 * a file and opening a tool. A counter is looked at by a graph that is already
 * on a wall.
 *
 * <p>So this is a bridge and not a second instrumentation: the drivers emit
 * exactly what they emitted before, and a {@link RecordingStream} in this
 * process turns those events into meters as they happen. Nothing was added to
 * the drivers for it, and nothing here can see a value the events do not carry
 * - which is the reason the fingerprint rule sits where it does, in
 * {@code SeclumeEvents}, rather than being restated at every consumer.
 *
 * <p><b>Off by default.</b> Starting a recording stream changes the state of
 * the process it runs in and costs a thread; a library that does that without
 * being asked has made a decision that belongs to whoever runs the
 * application. One property turns it on:
 *
 * <pre>
 * seclume.metrics.queries=true
 * seclume.metrics.query-threshold=10ms     # what counts as slow
 * seclume.metrics.query-fingerprints=100   # the cardinality bound, below
 * </pre>
 *
 * <p><b>The cardinality bound is the one real decision here.</b> A tag per
 * statement shape is what makes these meters worth having and is also the
 * classic way to bring down a metrics backend: an application with generated
 * SQL can have thousands of shapes, and each one is a time series kept
 * forever. So the number of distinct fingerprints that get a tag of their own
 * is bounded, first come first served, and everything after it is counted
 * under {@code other} - the totals stay right, the attribution stops. Whoever
 * wants no attribution at all sets the bound to zero and keeps the totals.
 */
public final class SeclumeQueryMetrics implements MeterBinder, AutoCloseable {

    /** What a fingerprint beyond the bound is counted as. */
    static final String OTHER = "other";

    private final Duration threshold;
    private final int fingerprintBound;

    /** The shapes that have a tag of their own, bounded by the above. */
    private final Set<String> named = ConcurrentHashMap.newKeySet();

    private volatile RecordingStream stream;

    /**
     * @param threshold        how slow a statement has to be to be recorded at
     *                         all - the event's own threshold, set on the
     *                         stream
     * @param fingerprintBound how many statement shapes get a tag of their
     *                         own before the rest become {@code other}
     */
    public SeclumeQueryMetrics(Duration threshold, int fingerprintBound) {
        this.threshold = threshold;
        this.fingerprintBound = Math.max(fingerprintBound, 0);
    }

    @Override
    public void bindTo(MeterRegistry registry) {
        RecordingStream opened = new RecordingStream();
        opened.enable("space.seclume.Query").withThreshold(threshold);
        opened.enable("space.seclume.StatementCache");
        opened.enable("space.seclume.ConnectionOpen");
        opened.enable("space.seclume.Failover");

        opened.onEvent("space.seclume.Query", event -> query(registry, event));
        opened.onEvent("space.seclume.StatementCache", event -> cache(registry, event));
        opened.onEvent("space.seclume.ConnectionOpen", event -> connection(registry, event));
        opened.onEvent("space.seclume.Failover", event -> failover(registry, event));

        // Not startAsync's own thread pool: the stream outlives this call and
        // has to be closable from close(), which is what the field is for.
        stream = opened;
        opened.startAsync();
    }

    /**
     * A statement that took longer than the threshold.
     *
     * <p>A timer rather than a counter, because the count is the least
     * interesting of the three numbers it keeps: total time is what a
     * dashboard divides by throughput, and the maximum is what somebody is
     * paged about.
     */
    private void query(MeterRegistry registry, RecordedEvent event) {
        Timer.builder("seclume.query.slow")
                .description("statements that took longer than the configured threshold")
                .tag("kind", string(event, "kind"))
                .tag("fingerprint", bounded(string(event, "fingerprint")))
                .tag("outcome", event.getBoolean("failed") ? "failed" : "ok")
                .register(registry)
                .record(event.getDuration().toNanos(), TimeUnit.NANOSECONDS);
    }

    /** Whether the server had the plan already. */
    private void cache(MeterRegistry registry, RecordedEvent event) {
        Counter.builder("seclume.statement.cache")
                .description("lookups in the driver's cache of server-side statements")
                .tag("fingerprint", bounded(string(event, "fingerprint")))
                .tag("result", event.getBoolean("hit") ? "hit" : "miss")
                .register(registry)
                .increment();
    }

    /** A physical connection - the expensive one, and what a warm-up is made of. */
    private void connection(MeterRegistry registry, RecordedEvent event) {
        Timer.builder("seclume.connection.open")
                .description("physical connections opened, including login and any handshake")
                .tag("kind", string(event, "kind"))
                .tag("outcome", event.getBoolean("succeeded") ? "ok" : "failed")
                .register(registry)
                .record(event.getDuration().toNanos(), TimeUnit.NANOSECONDS);
    }

    /**
     * A move to another server of the host list.
     *
     * <p>Without a tag for the reason. It is a server's message, it is
     * unbounded, and it is the field most likely to carry something nobody
     * meant to publish - the recording keeps it, a metric name must not.
     */
    private void failover(MeterRegistry registry, RecordedEvent event) {
        Counter.builder("seclume.failover")
                .description("a server of the host list could not be reached and the next "
                        + "was tried")
                .tag("from", string(event, "from"))
                .tag("to", string(event, "to"))
                .register(registry)
                .increment();
    }

    /**
     * The fingerprint, or {@code other} once the bound is reached.
     *
     * <p>First come, first served, and deliberately not an eviction scheme: a
     * bound that lets shapes take turns would rename series while a dashboard
     * is looking at them, which is worse than an honest {@code other}.
     */
    String bounded(String fingerprint) {
        if (fingerprint == null || fingerprint.isEmpty()) {
            return OTHER;
        }
        if (named.contains(fingerprint)) {
            return fingerprint;
        }
        if (named.size() >= fingerprintBound) {
            return OTHER;
        }
        // A race here can overshoot the bound by the number of threads racing,
        // which is a handful of series and not worth a lock on the statement
        // path.
        named.add(fingerprint);
        return fingerprint;
    }

    private static String string(RecordedEvent event, String field) {
        String value = event.getString(field);
        return value == null || value.isEmpty() ? "unknown" : value;
    }

    /** Stops the stream; called by the context when it shuts down. */
    @Override
    public void close() {
        RecordingStream open = stream;
        if (open != null) {
            stream = null;
            open.close();
        }
    }
}
