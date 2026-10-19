package space.seclume.redis;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

import space.seclume.internal.SeclumeSslEngine;
import space.seclume.secret.SecretProviders;

/** A password written into Lettuce's AUTH is a SecretUse event: the kind and the server, nothing more. */
class RedisEventsTest {

    @TempDir
    Path dir;

    @Test
    void theWrittenPasswordIsRecorded() throws Exception {
        Path password = dir.resolve("pw");
        Files.writeString(password, "recorded-not-shown");
        String placeholder = RespPasswordRewriter.newPlaceholder();
        RespPasswordRewriter rewriter = new RespPasswordRewriter(placeholder,
                SecretProviders.of(Map.of("provider", "file", "path", password.toString())),
                "cache:6379");
        ByteBuffer plain = ByteBuffer.wrap(("*2\r\n$4\r\nAUTH\r\n$" + placeholder.length()
                + "\r\n" + placeholder + "\r\n").getBytes(StandardCharsets.US_ASCII));
        Path file = dir.resolve("redis.jfr");
        try (Recording recording = new Recording()) {
            recording.enable("space.seclume.SecretUse");
            recording.start();
            while (plain.hasRemaining()) {
                SeclumeSslEngine.Outgoing.Step step = rewriter.next(plain);
                if (step.replacement() != null) {
                    step.replacement().close();
                    plain.position(plain.position() + step.replaced());
                } else {
                    plain.position(plain.position() + step.unchanged());
                }
            }
            recording.stop();
            recording.dump(file);
        }
        List<RecordedEvent> uses = RecordingFile.readAllEvents(file).stream()
                .filter(e -> e.getEventType().getName().equals("space.seclume.SecretUse"))
                .toList();
        assertEquals(1, uses.size());
        assertEquals("redis", uses.get(0).getString("kind"));
        assertEquals("cache:6379", uses.get(0).getString("target"));
        assertEquals("AUTH", uses.get(0).getString("mechanism"));
    }
}
