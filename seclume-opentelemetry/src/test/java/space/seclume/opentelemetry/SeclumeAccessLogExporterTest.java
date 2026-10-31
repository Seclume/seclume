package space.seclume.opentelemetry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.opentelemetry.api.logs.Severity;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.logs.SdkLoggerProvider;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import io.opentelemetry.sdk.logs.export.SimpleLogRecordProcessor;
import io.opentelemetry.sdk.testing.exporter.InMemoryLogRecordExporter;

import space.seclume.audit.AccessLog;
import space.seclume.audit.AccessLogVerifier;

/**
 * The access log's entries as log records: one each, the body the line as in
 * the file - so that the exported copy verifies on its own - and the fields as
 * attributes.
 */
class SeclumeAccessLogExporterTest {

    @TempDir
    Path directory;

    @Test
    void everyEntryIsARecordAndTheCopyVerifies() throws Exception {
        InMemoryLogRecordExporter exported = InMemoryLogRecordExporter.create();
        try (OpenTelemetrySdk sdk = OpenTelemetrySdk.builder().setLoggerProvider(SdkLoggerProvider.builder()
                .addLogRecordProcessor(SimpleLogRecordProcessor.create(exported)).build()).build()) {
            Path file = directory.resolve("access.jsonl");
            try (AccessLog log = AccessLog.open(file, null, null)) {
                log.addSink(SeclumeAccessLogExporter.of(sdk));
                AccessLog.install(log);
                AccessLog.event("secret.read", Map.of("provider", "file", "outcome", "failed"));
                AccessLog.event("data-key.ring", Map.of("primary", "2"));
            } finally {
                AccessLog.install(null);
            }
            List<LogRecordData> records = exported.getFinishedLogRecordItems();
            // log.opened was written before the sink was added; the two after it are exported.
            assertEquals(2, records.size());
            LogRecordData first = records.get(0);
            assertEquals(Files.readAllLines(file).get(1), first.getBodyValue().asString());
            assertEquals(2L, first.getAttributes().get(SeclumeAccessLogExporter.SEQ));
            assertEquals("secret.read", first.getAttributes().get(SeclumeAccessLogExporter.EVENT));
            assertEquals(Severity.WARN, first.getSeverity());
            assertEquals("file", first.getAttributes().get(
                    io.opentelemetry.api.common.AttributeKey.stringKey("seclume.audit.provider")));
            assertEquals(records.get(0).getAttributes().get(SeclumeAccessLogExporter.HASH),
                    records.get(1).getAttributes().get(SeclumeAccessLogExporter.PREV));

            StringBuilder copy = new StringBuilder(Files.readAllLines(file).get(0)).append('\n');
            for (LogRecordData record : records) {
                copy.append(record.getBodyValue().asString()).append('\n');
            }
            Path exportedCopy = Files.writeString(directory.resolve("copy.jsonl"), copy);
            assertTrue(AccessLogVerifier.verify(exportedCopy, null).holds());
        }
    }
}
