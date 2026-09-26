package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.context.Scope;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import io.opentelemetry.sdk.trace.data.SpanData;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.QueryFingerprint;
import space.seclume.jfr.Observed;

/**
 * Statements as spans, and the one property that makes them worth having.
 *
 * <p>The assertion this test exists for is the <b>parent</b>. Everything else
 * here - the name, the attributes, the status - could have been produced from
 * a Flight Recorder stream after the fact, the way the meters are. The parent
 * could not: it lives in the calling thread's context while the statement
 * runs, and it is the entire reason tracing needed a hook in the drivers when
 * nothing else did.
 */
@Timeout(60)
class TracingTest {

    private final InMemorySpanExporter exported = InMemorySpanExporter.create();
    private final OpenTelemetrySdk sdk = OpenTelemetrySdk.builder()
            .setTracerProvider(SdkTracerProvider.builder()
                    .addSpanProcessor(SimpleSpanProcessor.create(exported))
                    .build())
            .build();

    @AfterEach
    void removeTheListener() {
        Observed.listen(null);
    }

    @Test
    @SuppressWarnings("try")   // the scope is held for its effect, not its value
    void aStatementBecomesAChildOfTheRequestThatCausedIt() {
        SeclumeTracing tracing = new SeclumeTracing(sdk);
        tracing.install();

        Span request = sdk.getTracer("test").spanBuilder("GET /orders").startSpan();
        try (Scope held = request.makeCurrent()) {
            Observed.endQuery(Observed.beginQuery("postgresql"),
                    "postgresql", "select * from orders where customer = 4711",
                    QueryFingerprint.Dialect.POSTGRESQL, 7, false);
        } finally {
            request.end();
        }

        List<SpanData> spans = exported.getFinishedSpanItems();
        SpanData statement = spans.stream().filter(s -> s.getName().equals("SELECT orders")).findFirst()
                .orElseThrow(() -> new AssertionError("no statement span: "
                        + spans.stream().map(SpanData::getName).toList()));

        assertEquals(request.getSpanContext().getSpanId(), statement.getParentSpanId(),
                "the statement span is not on the request that caused it");
        assertEquals(request.getSpanContext().getTraceId(), statement.getTraceId());

        assertEquals("postgresql", statement.getAttributes()
                .get(io.opentelemetry.api.common.AttributeKey.stringKey("db.system.name")));
        assertEquals("SELECT", statement.getAttributes()
                .get(io.opentelemetry.api.common.AttributeKey.stringKey("db.operation.name")));
        assertEquals("SELECT orders", statement.getAttributes()
                .get(io.opentelemetry.api.common.AttributeKey.stringKey("db.query.summary")));
        assertEquals(null, statement.getAttributes()
                .get(io.opentelemetry.api.common.AttributeKey.stringKey("db.system")),
                "the old names came without being asked for");
        assertEquals(7L, statement.getAttributes()
                .get(io.opentelemetry.api.common.AttributeKey.longKey(
                        "db.response.returned_rows")));

        // The fingerprint, and nothing that was in the statement.
        String recorded = statement.getAttributes()
                .get(io.opentelemetry.api.common.AttributeKey.stringKey("db.query.text"));
        assertEquals("select * from orders where customer = ?", recorded);
        assertFalse(recorded.contains("4711"), "a value reached a trace: " + recorded);
    }

    /** A statement that threw is marked, and still without a message. */
    @Test
    void aFailedStatementIsMarkedWithoutSayingWhat() {
        SeclumeTracing tracing = new SeclumeTracing(sdk);
        tracing.install();

        Observed.endQuery(Observed.beginQuery("oracle"), "oracle",
                "insert into ledger values ('secret-value')",
                QueryFingerprint.Dialect.ORACLE, 0, true);

        SpanData statement = exported.getFinishedSpanItems().get(0);
        assertEquals("INSERT ledger", statement.getName());
        assertEquals("oracle.db", statement.getAttributes()
                .get(io.opentelemetry.api.common.AttributeKey.stringKey("db.system.name")));
        assertEquals("_OTHER", statement.getAttributes()
                .get(io.opentelemetry.api.common.AttributeKey.stringKey("error.type")));
        assertEquals(StatusCode.ERROR, statement.getStatus().getStatusCode());
        assertTrue(statement.getStatus().getDescription().isEmpty(),
                "the status carries a description, and a server's error text is the field "
                        + "most likely to quote the statement back: "
                        + statement.getStatus().getDescription());
    }

    /**
     * Removing the listener really removes it.
     *
     * <p>It is a process-wide static, which is the only shape a driver reached
     * through {@code DriverManager} can be given - so the way out of it has to
     * work, or a context that shuts down leaves spans being made against a
     * tracer nobody reads.
     */
    @Test
    void closingItStopsTheSpans() {
        SeclumeTracing tracing = new SeclumeTracing(sdk);
        tracing.install();
        Observed.endQuery(Observed.beginQuery("mysql"), "mysql", "select 1",
                QueryFingerprint.Dialect.MYSQL, 1, false);
        assertEquals(1, exported.getFinishedSpanItems().size());

        tracing.close();
        assertFalse(Observed.isListening(), "the listener survived the close");
        Observed.endQuery(Observed.beginQuery("mysql"), "mysql", "select 2",
                QueryFingerprint.Dialect.MYSQL, 1, false);
        assertEquals(1, exported.getFinishedSpanItems().size(),
                "a statement after the close produced a span");
    }

    /**
     * {@code OTEL_SEMCONV_STABILITY_OPT_IN=database/dup}: the old names come
     * beside the stable ones, for a backend still reading them.
     */
    @Test
    void theOldNamesComeWhenAskedFor() {
        SeclumeTracing tracing = new SeclumeTracing(sdk, true);
        tracing.install();
        Observed.endQuery(Observed.beginQuery("sqlserver"), "sqlserver",
                "update accounts set balance = 1 where id = 2",
                QueryFingerprint.Dialect.SQLSERVER, 1, false);
        SpanData statement = exported.getFinishedSpanItems().get(0);
        assertEquals("sqlserver", statement.getAttributes()
                .get(io.opentelemetry.api.common.AttributeKey.stringKey("db.system")));
        assertEquals("microsoft.sql_server", statement.getAttributes()
                .get(io.opentelemetry.api.common.AttributeKey.stringKey("db.system.name")));
        assertEquals(statement.getAttributes()
                        .get(io.opentelemetry.api.common.AttributeKey.stringKey("db.query.text")),
                statement.getAttributes()
                        .get(io.opentelemetry.api.common.AttributeKey.stringKey("db.statement")));
        assertTrue(SeclumeTracing.optedIntoDuplicates("http, database/dup"));
        assertFalse(SeclumeTracing.optedIntoDuplicates("database"));
        assertFalse(SeclumeTracing.optedIntoDuplicates(null));
    }

    /** The summary: the operation and the first table, nothing of the values. */
    @Test
    void theSummaryIsTheOperationAndItsTable() {
        assertEquals("SELECT orders", SeclumeTracing.summaryOf(
                "select * from orders where id = ?"));
        assertEquals("INSERT ledger", SeclumeTracing.summaryOf("insert into ledger values (?)"));
        assertEquals("UPDATE app.accounts", SeclumeTracing.summaryOf(
                "update app.accounts set b = ? where id = ?"));
        assertEquals("DELETE t", SeclumeTracing.summaryOf("delete from \"t\" where x = ?"));
        assertEquals("SELECT", SeclumeTracing.summaryOf("select ?"));
        assertEquals("SELECT", SeclumeTracing.summaryOf("select * from (select ?) x"));
        assertEquals("WITH", SeclumeTracing.summaryOf("with r as (select ?) select * from r"));
    }

    /** The operation, whatever the statement was. */
    @Test
    void theNameIsTheOperationAndNotTheShape() {
        assertEquals("SELECT", SeclumeTracing.operationOf("select * from t where id = ?"));
        assertEquals("INSERT", SeclumeTracing.operationOf("insert into t values (?)"));
        assertEquals("WITH", SeclumeTracing.operationOf("with r as (select ?) select * from r"));
        assertEquals("STATEMENT", SeclumeTracing.operationOf(""));
        assertEquals("STATEMENT", SeclumeTracing.operationOf("/* a comment first */ select ?"));
    }
}
