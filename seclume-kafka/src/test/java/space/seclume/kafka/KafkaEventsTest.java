package space.seclume.kafka;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import javax.security.sasl.SaslException;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.internal.SeclumeSslEngine;
import space.seclume.secret.SecretProviders;

/**
 * seclume's Flight Recorder events from Kafka logins: a secret written into a
 * SaslAuthenticate request is a SecretUse event with the broker, and a SCRAM
 * login an Authentication event with its mechanism and outcome.
 */
class KafkaEventsTest {

    @TempDir
    static Path dir;

    @BeforeAll
    static void theEngineFactoryIsInUse() {
        new SeclumeSslEngineFactory().configure(Map.of());
    }

    private static space.seclume.secret.SecretProvider file(String name, String secret)
            throws Exception {
        Path path = dir.resolve(name);
        Files.writeString(path, secret);
        return SecretProviders.of(Map.of("provider", "file", "path", path.toString()));
    }

    /** SaslAuthenticate v0: size, API key 36, version, correlation id, no client id, bytes. */
    private static ByteBuffer frame(byte[] auth) {
        ByteBuffer frame = ByteBuffer.allocate(4 + 2 + 2 + 4 + 2 + 4 + auth.length);
        frame.putInt(frame.capacity() - 4).putShort(SaslAuthenticateRewriter.SASL_AUTHENTICATE)
                .putShort((short) 0).putInt(7).putShort((short) -1).putInt(auth.length).put(auth);
        return frame.flip();
    }

    private static List<RecordedEvent> recorded(Path file, String type) throws Exception {
        return RecordingFile.readAllEvents(file).stream()
                .filter(e -> e.getEventType().getName().equals(type)).toList();
    }

    @Test
    void aSecretWrittenIntoTheLoginIsRecorded() throws Exception {
        PlainClient client = new PlainClient("orders", file("plain", "kafka-recorded-pw"));
        ByteBuffer request = frame(client.evaluateChallenge(new byte[0]));
        Path file = dir.resolve("sasl.jfr");
        try (Recording recording = new Recording()) {
            recording.enable("space.seclume.SecretUse");
            recording.start();
            SeclumeSslEngine.Outgoing.Step step = new SaslAuthenticateRewriter("broker-1:9093")
                    .next(request);
            assertFalse(step.replacement() == null, "nothing was written in");
            step.replacement().close();
            recording.stop();
            recording.dump(file);
        }
        client.dispose();
        List<RecordedEvent> uses = recorded(file, "space.seclume.SecretUse");
        assertEquals(1, uses.size());
        assertEquals("kafka", uses.get(0).getString("kind"));
        assertEquals("broker-1:9093", uses.get(0).getString("target"));
    }

    @Test
    void aScramLoginThatFailsIsRecordedAsFailed() throws Exception {
        ScramClient client = new ScramClient("SCRAM-SHA-256", HashAlgorithm.SHA_256, "orders",
                file("scram", "kafka-scram-pw"), "broker-2");
        Path file = dir.resolve("scram.jfr");
        try (Recording recording = new Recording()) {
            recording.enable("space.seclume.Authentication");
            recording.start();
            client.evaluateChallenge(new byte[0]);
            // A server-first message that is not one.
            assertThrows(SaslException.class, () -> client.evaluateChallenge(
                    "not a server-first message".getBytes(StandardCharsets.US_ASCII)));
            recording.stop();
            recording.dump(file);
        }
        List<RecordedEvent> logins = recorded(file, "space.seclume.Authentication");
        assertEquals(1, logins.size());
        assertEquals("kafka", logins.get(0).getString("kind"));
        assertEquals("broker-2", logins.get(0).getString("server"));
        assertEquals("SCRAM-SHA-256", logins.get(0).getString("method"));
        assertFalse(logins.get(0).getBoolean("succeeded"));
    }
}
