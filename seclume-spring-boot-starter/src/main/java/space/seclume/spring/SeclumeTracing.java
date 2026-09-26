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
 * <p><b>The stable database conventions.</b> {@code db.system.name},
 * {@code db.query.text} (the fingerprint), {@code db.operation.name} and
 * {@code db.query.summary} - the operation and the first table it names,
 * {@code SELECT orders} - which is also the span name: low in cardinality, one
 * per operation and table rather than per statement shape, the key every
 * backend indexes spans by. A failed statement carries {@code error.type}.
 * The names before the conventions were stable - {@code db.system},
 * {@code db.statement}, {@code db.operation} - come as well when
 * {@code OTEL_SEMCONV_STABILITY_OPT_IN} names {@code database/dup}, the
 * switch OpenTelemetry defines for the move from one to the other.
 */
public final class SeclumeTracing implements StatementListener, AutoCloseable {

    private static final AttributeKey<String> DB_SYSTEM_NAME =
            AttributeKey.stringKey("db.system.name");
    private static final AttributeKey<String> DB_QUERY_TEXT =
            AttributeKey.stringKey("db.query.text");
    private static final AttributeKey<String> DB_OPERATION_NAME =
            AttributeKey.stringKey("db.operation.name");
    private static final AttributeKey<String> DB_QUERY_SUMMARY =
            AttributeKey.stringKey("db.query.summary");
    private static final AttributeKey<Long> DB_ROWS =
            AttributeKey.longKey("db.response.returned_rows");
    private static final AttributeKey<String> ERROR_TYPE = AttributeKey.stringKey("error.type");

    // The names from before the conventions were stable - on request only.
    private static final AttributeKey<String> DB_SYSTEM = AttributeKey.stringKey("db.system");
    private static final AttributeKey<String> DB_STATEMENT =
            AttributeKey.stringKey("db.statement");
    private static final AttributeKey<String> DB_OPERATION =
            AttributeKey.stringKey("db.operation");

    private final Tracer tracer;
    private final boolean legacyToo;

    /** With the stable attribute names only. */
    public SeclumeTracing(OpenTelemetry openTelemetry) {
        this(openTelemetry, false);
    }

    /**
     * With the old attribute names beside the stable ones, or without - the
     * auto-configuration decides from {@code OTEL_SEMCONV_STABILITY_OPT_IN},
     * read through Spring's environment rather than the process's.
     */
    public SeclumeTracing(OpenTelemetry openTelemetry, boolean legacyToo) {
        this.tracer = openTelemetry.getTracer("space.seclume");
        this.legacyToo = legacyToo;
    }

    /** Whether the opt-in names {@code database/dup}: a comma-separated list. */
    static boolean optedIntoDuplicates(String optIn) {
        if (optIn == null) {
            return false;
        }
        for (String one : optIn.split(",")) {
            if (one.trim().equals("database/dup")) {
                return true;
            }
        }
        return false;
    }

    /** The conventions' name for each database. */
    static String systemName(String kind) {
        return switch (kind) {
            case "sqlserver" -> "microsoft.sql_server";
            case "oracle" -> "oracle.db";
            default -> kind;                     // postgresql, mysql
        };
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
        io.opentelemetry.api.trace.SpanBuilder builder = tracer.spanBuilder(kind)
                .setSpanKind(SpanKind.CLIENT)
                .setAttribute(DB_SYSTEM_NAME, systemName(kind));
        if (legacyToo) {
            builder.setAttribute(DB_SYSTEM, kind);
        }
        return new OpenTelemetrySpan(builder.startSpan(), legacyToo);
    }

    /** One statement's span, ended with what the statement turned out to be. */
    private record OpenTelemetrySpan(io.opentelemetry.api.trace.Span span, boolean legacyToo)
            implements StatementListener.Span {

        @Override
        public void end(String fingerprint, long rows, boolean failed) {
            String operation = operationOf(fingerprint);
            String summary = summaryOf(fingerprint);
            span.updateName(summary);
            span.setAttribute(DB_OPERATION_NAME, operation);
            span.setAttribute(DB_QUERY_TEXT, fingerprint);
            span.setAttribute(DB_QUERY_SUMMARY, summary);
            span.setAttribute(DB_ROWS, rows);
            if (legacyToo) {
                span.setAttribute(DB_OPERATION, operation);
                span.setAttribute(DB_STATEMENT, fingerprint);
            }
            if (failed) {
                // The conventions ask for a type; the class of the exception is
                // the application's to see, and "_OTHER" is what they define
                // for a failure described no further.
                span.setAttribute(ERROR_TYPE, "_OTHER");
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
     * The operation and the first table it names - {@code SELECT orders},
     * {@code INSERT ledger} - or the operation alone when there is none to
     * find. From the fingerprint, like the operation: nothing in it that was
     * not safe to publish already.
     */
    static String summaryOf(String fingerprint) {
        String operation = operationOf(fingerprint);
        if (fingerprint == null) {
            return operation;
        }
        String lower = fingerprint.toLowerCase(Locale.ROOT);
        String after = switch (operation) {
            case "SELECT", "DELETE" -> " from ";
            case "INSERT", "MERGE" -> " into ";
            case "UPDATE" -> "update ";
            default -> null;
        };
        if (after == null) {
            return operation;
        }
        int at = lower.indexOf(after);
        if (at < 0) {
            return operation;
        }
        int start = at + after.length();
        while (start < lower.length() && Character.isWhitespace(lower.charAt(start))) {
            start++;
        }
        int end = start;
        while (end < lower.length() && (Character.isLetterOrDigit(lower.charAt(end))
                || lower.charAt(end) == '_' || lower.charAt(end) == '.'
                || lower.charAt(end) == '"' || lower.charAt(end) == '`')) {
            end++;
        }
        if (end == start || lower.charAt(start) == '(') {
            return operation;
        }
        return operation + " " + fingerprint.substring(start, end).replace("\"", "")
                .replace("`", "");
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
