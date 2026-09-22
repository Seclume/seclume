package space.seclume.spring;

import java.util.Locale;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;

import space.seclume.jfr.Observed;
import space.seclume.jfr.StatementListener;

/**
 * Every statement as a span on the request that caused it.
 *
 * <p><b>Why this is not the metrics bridge with a different output.</b> The
 * meters are built from a Flight Recorder stream and need no hook anywhere -
 * see {@link SeclumeQueryMetrics}. A span cannot be: it belongs to a request,
 * and which request that is lives in the calling thread's context at the
 * moment the statement runs. A recording is read afterwards, on another
 * thread, and a span made there would have the right duration and no parent -
 * which is not a worse trace, it is not a trace. So tracing is the one thing
 * in this project that needed a hook in the drivers, and
 * {@link StatementListener} is that hook: one interface, no dependency, a
 * no-op until somebody installs one.
 *
 * <p><b>The statement in a span is the fingerprint.</b> OpenTelemetry's own
 * semantic conventions ask for {@code db.statement} to be sanitised, which is
 * the same conclusion this project reached for its recordings - and here the
 * sanitised form is the only one available: the listener is never given the
 * text. A trace leaves the building more readily than a heap dump does, so
 * this is the place where that rule matters most and costs least.
 *
 * <p>The span name is the operation and nothing else - {@code SELECT},
 * {@code INSERT} - because a span name is an index key in every backend that
 * stores them, and one per statement shape is the same cardinality problem the
 * meters have, in a place that has no bound to offer.
 */
public final class SeclumeTracing implements StatementListener, AutoCloseable {

    private static final AttributeKey<String> DB_SYSTEM =
            AttributeKey.stringKey("db.system");
    private static final AttributeKey<String> DB_STATEMENT =
            AttributeKey.stringKey("db.statement");
    private static final AttributeKey<String> DB_OPERATION =
            AttributeKey.stringKey("db.operation");
    private static final AttributeKey<Long> DB_ROWS =
            AttributeKey.longKey("db.response.returned_rows");

    private final Tracer tracer;

    public SeclumeTracing(OpenTelemetry openTelemetry) {
        this.tracer = openTelemetry.getTracer("space.seclume");
    }

    /** Installs this as the one listener; called by the auto-configuration. */
    public void install() {
        Observed.listen(this);
    }

    @Override
    public void close() {
        Observed.listen(null);
    }

    @Override
    public StatementListener.Span begin(String kind) {
        // Started without being made current: a JDBC call makes no nested
        // calls that would want this as their parent, and a scope that has to
        // be closed on the statement path is a leak waiting for the first
        // exception nobody thought about.
        // Fully qualified deliberately: this class implements StatementListener,
        // whose nested Span would otherwise shadow the imported one - and the
        // two would compile against each other in confusing ways.
        io.opentelemetry.api.trace.Span span = tracer.spanBuilder(kind)
                .setSpanKind(SpanKind.CLIENT)
                .setAttribute(DB_SYSTEM, kind)
                .startSpan();
        return new OpenTelemetrySpan(span);
    }

    /** One statement's span, ended with what the statement turned out to be. */
    private record OpenTelemetrySpan(io.opentelemetry.api.trace.Span span)
            implements StatementListener.Span {

        @Override
        public void end(String fingerprint, long rows, boolean failed) {
            String operation = operationOf(fingerprint);
            span.updateName(operation);
            span.setAttribute(DB_OPERATION, operation);
            span.setAttribute(DB_STATEMENT, fingerprint);
            span.setAttribute(DB_ROWS, rows);
            if (failed) {
                // Without a message. What went wrong is on the exception the
                // application already has, and a server's error text is the
                // field most likely to quote the statement back with its
                // values in it.
                span.setStatus(StatusCode.ERROR);
            }
            span.end();
        }
    }

    /**
     * The first word, upper-cased - {@code SELECT}, {@code INSERT}, and
     * {@code STATEMENT} when it is neither.
     *
     * <p>Taken from the fingerprint rather than the text, so there is nothing
     * in it that was not already safe to publish. A statement beginning with a
     * comment or a {@code with} gives {@code WITH}, which is honest: guessing
     * further would mean parsing SQL to name a span.
     */
    static String operationOf(String fingerprint) {
        if (fingerprint == null || fingerprint.isEmpty()) {
            return "STATEMENT";
        }
        int start = 0;
        while (start < fingerprint.length() && Character.isWhitespace(fingerprint.charAt(start))) {
            start++;
        }
        int end = start;
        while (end < fingerprint.length() && Character.isLetter(fingerprint.charAt(end))) {
            end++;
        }
        if (end == start) {
            return "STATEMENT";
        }
        return fingerprint.substring(start, end).toUpperCase(Locale.ROOT);
    }
}
