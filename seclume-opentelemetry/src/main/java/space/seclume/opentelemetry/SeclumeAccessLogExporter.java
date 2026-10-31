package space.seclume.opentelemetry;

import java.util.Map;
import java.util.function.Consumer;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.logs.Logger;
import io.opentelemetry.api.logs.Severity;

import space.seclume.audit.AccessLog;

/**
 * Every access log entry as an OpenTelemetry log record, as it is written -
 * so that a copy of the chain, and of every checkpoint's head, lives outside
 * the file it is written to. That copy is what tells a log whose last entries
 * were removed from one that was never longer.
 *
 * <pre>{@code
 * accessLog.addSink(SeclumeAccessLogExporter.of(openTelemetry));
 * }</pre>
 *
 * <p>The body is the entry's line, exactly as in the file, so the copy can be
 * checked with the same verifier; the attributes ({@code seclume.audit.seq},
 * {@code .event}, {@code .hash}, {@code .prev} and the entry's own fields) are
 * for searching. An entry holds facts, never a secret.
 */
public final class SeclumeAccessLogExporter implements Consumer<AccessLog.Entry> {

    static final AttributeKey<Long> SEQ = AttributeKey.longKey("seclume.audit.seq");
    static final AttributeKey<String> EVENT = AttributeKey.stringKey("seclume.audit.event");
    static final AttributeKey<String> HASH = AttributeKey.stringKey("seclume.audit.hash");
    static final AttributeKey<String> PREV = AttributeKey.stringKey("seclume.audit.prev");

    private final Logger logger;

    private SeclumeAccessLogExporter(Logger logger) {
        this.logger = logger;
    }

    /** An exporter through {@code openTelemetry}'s logs bridge, instrumentation scope {@code seclume}. */
    public static SeclumeAccessLogExporter of(OpenTelemetry openTelemetry) {
        return new SeclumeAccessLogExporter(openTelemetry.getLogsBridge().get("seclume"));
    }

    @Override
    public void accept(AccessLog.Entry entry) {
        AttributesBuilder attributes = Attributes.builder()
                .put(SEQ, entry.seq())
                .put(EVENT, entry.event())
                .put(HASH, entry.hash())
                .put(PREV, entry.prev());
        for (Map.Entry<String, String> field : entry.fields().entrySet()) {
            attributes.put(AttributeKey.stringKey("seclume.audit." + field.getKey()), field.getValue());
        }
        logger.logRecordBuilder()
                .setTimestamp(entry.time())
                .setSeverity("secret.read".equals(entry.event())
                        && "failed".equals(entry.fields().get("outcome")) ? Severity.WARN : Severity.INFO)
                .setSeverityText(entry.event())
                .setBody(entry.line())
                .setAllAttributes(attributes.build())
                .emit();
    }
}
