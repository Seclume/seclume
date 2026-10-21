package space.seclume.opentelemetry;

import java.time.Duration;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.metrics.DoubleHistogram;
import io.opentelemetry.api.metrics.LongCounter;
import io.opentelemetry.api.metrics.Meter;
import io.opentelemetry.api.metrics.MeterBuilder;

import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingStream;

/**
 * seclume's Flight Recorder events as OpenTelemetry instruments, for an
 * application that exports with OpenTelemetry and has no Micrometer.
 *
 * <p>The same bridge as the Spring Boot starter's Micrometer meters, with the
 * same names and attributes, so a dashboard reads either: the drivers emit
 * their events exactly as before, and a {@link RecordingStream} in this
 * process turns each one into a measurement as it happens. Nothing was added
 * to the drivers, and nothing here can see what the events do not carry - no
 * statement parameter, no secret, no server message.
 *
 * <pre>
 *   OpenTelemetry otel = ...;                       // the application's SDK or agent
 *   SeclumeMetrics metrics = SeclumeMetrics.start(otel);
 *   ...
 *   metrics.close();                                // on shutdown
 * </pre>
 *
 * <p><b>Off until started.</b> A recording stream changes the process it runs
 * in and costs a thread; that is the application's decision, so merely having
 * this module on the class path does nothing. The connection pool has
 * instruments of its own, under OpenTelemetry's semantic conventions for
 * connection pools - see {@link SeclumePoolInstruments}.
 *
 * <p>Durations are histograms in seconds, as the conventions ask. Statement
 * shapes are bounded as in the starter: the first {@code fingerprintBound}
 * get an attribute value of their own, the rest are counted as {@code other},
 * so generated SQL cannot flood the backend with time series.
 */
public final class SeclumeMetrics implements AutoCloseable {

    /** The instrumentation scope every instrument is created under. */
    public static final String SCOPE = "space.seclume";

    /** What a fingerprint beyond the bound is counted as. */
    static final String OTHER = "other";

    private static final AttributeKey<String> KIND = AttributeKey.stringKey("kind");
    private static final AttributeKey<String> OUTCOME = AttributeKey.stringKey("outcome");
    private static final AttributeKey<String> FINGERPRINT = AttributeKey.stringKey("fingerprint");

    private final int fingerprintBound;
    private final Set<String> named = ConcurrentHashMap.newKeySet();
    private final RecordingStream stream;

    private final DoubleHistogram slowQueries;
    private final LongCounter statementCache;
    private final DoubleHistogram connectionOpen;
    private final LongCounter secretRotations;
    private final DoubleHistogram authentications;
    private final LongCounter secretUses;
    private final DoubleHistogram signatures;
    private final DoubleHistogram secretReads;
    private final DoubleHistogram tlsHandshakes;
    private final DoubleHistogram failover;

    /**
     * Starts with the starter's defaults: statements slower than 10 ms, the
     * first 100 statement shapes named.
     */
    public static SeclumeMetrics start(OpenTelemetry openTelemetry) {
        return start(openTelemetry, Duration.ofMillis(10), 100);
    }

    /**
     * @param queryThreshold   how slow a statement has to be to be measured at
     *                         all - the event's own threshold on the stream
     * @param fingerprintBound how many statement shapes get an attribute value
     *                         of their own before the rest become {@code other}
     */
    public static SeclumeMetrics start(OpenTelemetry openTelemetry, Duration queryThreshold,
                                       int fingerprintBound) {
        SeclumeMetrics metrics = new SeclumeMetrics(meter(openTelemetry), queryThreshold,
                fingerprintBound);
        metrics.stream.startAsync();
        return metrics;
    }

    static Meter meter(OpenTelemetry openTelemetry) {
        MeterBuilder builder = openTelemetry.getMeterProvider().meterBuilder(SCOPE);
        String version = SeclumeMetrics.class.getPackage().getImplementationVersion();
        if (version != null) {
            builder.setInstrumentationVersion(version);
        }
        return builder.build();
    }

    private SeclumeMetrics(Meter meter, Duration queryThreshold, int fingerprintBound) {
        this.fingerprintBound = Math.max(fingerprintBound, 0);
        slowQueries = seconds(meter, "seclume.query.slow",
                "statements that took longer than the configured threshold");
        statementCache = meter.counterBuilder("seclume.statement.cache")
                .setDescription("lookups in the driver's cache of server-side statements")
                .build();
        connectionOpen = seconds(meter, "seclume.connection.open",
                "physical connections opened, including login and any handshake");
        secretRotations = meter.counterBuilder("seclume.secret.rotations")
                .setDescription("secrets that changed at their source, and whether taking up "
                        + "the new one worked")
                .build();
        authentications = seconds(meter, "seclume.authentications",
                "logins, by protocol and the method the server asked for");
        secretUses = meter.counterBuilder("seclume.secret.uses")
                .setDescription("secrets written into requests from native memory")
                .build();
        signatures = seconds(meter, "seclume.signatures",
                "signatures made or checked with keys held off the heap");
        secretReads = seconds(meter, "seclume.secret.reads",
                "secrets read from their providers into native memory");
        tlsHandshakes = seconds(meter, "seclume.tls.handshakes",
                "TLS handshakes, by the stack that made them");
        failover = seconds(meter, "seclume.failover",
                "a server of the host list could not be reached and the next was tried");

        RecordingStream opened = new RecordingStream();
        opened.enable("space.seclume.Query").withThreshold(queryThreshold);
        opened.enable("space.seclume.StatementCache");
        opened.enable("space.seclume.ConnectionOpen");
        opened.enable("space.seclume.Failover");
        opened.enable("space.seclume.SecretRotation");
        opened.enable("space.seclume.Authentication");
        opened.enable("space.seclume.SecretUse");
        opened.enable("space.seclume.Signature");
        opened.enable("space.seclume.CredentialRotation");
        opened.enable("space.seclume.TlsHandshake");
        opened.onEvent("space.seclume.Query", this::query);
        opened.onEvent("space.seclume.StatementCache", this::cache);
        opened.onEvent("space.seclume.ConnectionOpen", this::connection);
        opened.onEvent("space.seclume.Failover", this::failover);
        opened.onEvent("space.seclume.SecretRotation", this::rotation);
        opened.onEvent("space.seclume.Authentication", this::login);
        opened.onEvent("space.seclume.SecretUse", this::use);
        opened.onEvent("space.seclume.Signature", this::signature);
        opened.onEvent("space.seclume.CredentialRotation", this::read);
        opened.onEvent("space.seclume.TlsHandshake", this::handshake);
        stream = opened;
    }

    private static DoubleHistogram seconds(Meter meter, String name, String description) {
        return meter.histogramBuilder(name).setUnit("s").setDescription(description).build();
    }

    private void query(RecordedEvent event) {
        slowQueries.record(seconds(event), Attributes.of(KIND, string(event, "kind"),
                FINGERPRINT, bounded(string(event, "fingerprint")),
                OUTCOME, event.getBoolean("failed") ? "failed" : "ok"));
    }

    private void cache(RecordedEvent event) {
        statementCache.add(1, Attributes.of(FINGERPRINT, bounded(string(event, "fingerprint")),
                AttributeKey.stringKey("result"), event.getBoolean("hit") ? "hit" : "miss"));
    }

    private void connection(RecordedEvent event) {
        connectionOpen.record(seconds(event), Attributes.of(KIND, string(event, "kind"),
                OUTCOME, outcome(event)));
    }

    /**
     * Without the server's message: it is unbounded, and it is the field most
     * likely to carry something nobody meant to publish - the recording keeps
     * it, an attribute must not.
     */
    private void failover(RecordedEvent event) {
        failover.record(seconds(event), Attributes.of(
                AttributeKey.stringKey("from"), string(event, "from"),
                AttributeKey.stringKey("to"), string(event, "to")));
    }

    /** Without the reason, for the same reason as {@link #failover}. */
    private void rotation(RecordedEvent event) {
        secretRotations.add(1, Attributes.of(AttributeKey.stringKey("watch"),
                string(event, "watch"), OUTCOME, outcome(event)));
    }

    private void login(RecordedEvent event) {
        authentications.record(seconds(event), Attributes.of(KIND, string(event, "kind"),
                AttributeKey.stringKey("method"), string(event, "method"),
                OUTCOME, outcome(event)));
    }

    private void use(RecordedEvent event) {
        secretUses.add(1, Attributes.of(KIND, string(event, "kind"),
                AttributeKey.stringKey("mechanism"), string(event, "mechanism")));
    }

    private void signature(RecordedEvent event) {
        signatures.record(seconds(event), Attributes.of(
                AttributeKey.stringKey("algorithm"), string(event, "algorithm"),
                AttributeKey.stringKey("operation"), string(event, "operation"),
                OUTCOME, outcome(event)));
    }

    private void read(RecordedEvent event) {
        secretReads.record(seconds(event), Attributes.of(
                AttributeKey.stringKey("provider"), string(event, "provider"),
                OUTCOME, outcome(event)));
    }

    /** By stack, not by server: one series per server would grow without end. */
    private void handshake(RecordedEvent event) {
        tlsHandshakes.record(seconds(event), Attributes.of(
                AttributeKey.stringKey("stack"), string(event, "stack")));
    }

    /**
     * The fingerprint, or {@code other} once the bound is reached - first come,
     * first served, never an eviction that would rename series under a
     * dashboard.
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
        // A race can overshoot the bound by the threads racing - a handful of
        // series, not worth a lock on the statement path.
        named.add(fingerprint);
        return fingerprint;
    }

    private static double seconds(RecordedEvent event) {
        return event.getDuration().toNanos() / 1e9;
    }

    private static String outcome(RecordedEvent event) {
        return event.getBoolean("succeeded") ? "ok" : "failed";
    }

    private static String string(RecordedEvent event, String field) {
        String value = event.getString(field);
        return value == null || value.isEmpty() ? "unknown" : value;
    }

    /** Stops the stream; the instruments stay with the application's meter provider. */
    @Override
    public void close() {
        stream.close();
    }
}
