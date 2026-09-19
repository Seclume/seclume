package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

import org.junit.jupiter.api.Test;

import space.seclume.crypto.HashAlgorithm;

/**
 * Both {@code Finished} messages of RFC 8448's trace 3, verified end to end:
 * {@link KeySchedule} built from only the two external inputs (the (EC)DHE
 * shared secret and the recorded message bytes), the transcript hashes taken
 * at the two different points the specification actually asks for them (the
 * server's stops one message earlier than the client's), and
 * {@link Finished#verify} on the recorded {@code verify_data} of each side.
 *
 * <p>Every earlier test that touches this material checks one piece in
 * isolation - {@code KeyScheduleTest} the key schedule with transcript hashes
 * handed to it, {@code CertificateVerificationTest} the signature with a
 * transcript hash handed to it. This is the first test where the transcript
 * hashes themselves come from replaying the actual message bytes in order,
 * which is exactly the thing a real handshake has to get right and a
 * per-vector test cannot exercise.
 */
class FinishedTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void bothFinishedMessagesOfTrace3Verify() throws IOException {
        Map<String, byte[]> messages = new HashMap<>();
        load((who, type, hex) -> messages.putIfAbsent(who + " " + type, HEX.parseHex(hex)));

        Map<String, String[]> extractRows = new HashMap<>();
        Map<String, String[]> expandRows = new HashMap<>();
        loadKeys("extract", (name, fields) -> extractRows.putIfAbsent(name, fields));
        loadKeys("expand", (name, fields) -> expandRows.putIfAbsent(name, fields));

        try (Arena arena = Arena.ofConfined(); KeySchedule schedule = KeySchedule.withoutPsk(HashAlgorithm.SHA_256)) {
            byte[] sharedSecret = HEX.parseHex(extractRows.get("handshake")[1]);
            byte[] helloToHello = HEX.parseHex(expandRows.get("c hs traffic")[1]);
            schedule.deriveHandshakeSecret(of(arena, sharedSecret));
            schedule.deriveHandshakeTrafficSecrets(of(arena, helloToHello));

            try (TranscriptHash transcript = new TranscriptHash(HashAlgorithm.SHA_256)) {
                feed(transcript, arena, messages.get("client ClientHello"));
                feed(transcript, arena, messages.get("server ServerHello"));
                feed(transcript, arena, messages.get("server EncryptedExtensions"));
                feed(transcript, arena, messages.get("server Certificate"));
                feed(transcript, arena, messages.get("server CertificateVerify"));

                MemorySegment throughCertificateVerify = arena.allocate(32);
                transcript.current(throughCertificateVerify, 0);

                byte[] serverFinished = messages.get("server Finished");
                MemorySegment serverFinishedMsg = of(arena, serverFinished);
                long verifyDataAt = Handshake.HEADER;
                int verifyDataLength = Handshake.length(serverFinishedMsg, 0);

                assertTrue(Finished.verify(schedule, schedule.serverHandshakeTrafficSecret(),
                        throughCertificateVerify, serverFinishedMsg, verifyDataAt, verifyDataLength),
                        "the recorded server Finished must verify against the replayed transcript");

                MemorySegment tampered = arena.allocate(32);
                MemorySegment.copy(throughCertificateVerify, 0, tampered, 0, 32);
                tampered.set(ValueLayout.JAVA_BYTE, 0, (byte) (tampered.get(ValueLayout.JAVA_BYTE, 0) ^ 1));
                assertFalse(Finished.verify(schedule, schedule.serverHandshakeTrafficSecret(),
                        tampered, serverFinishedMsg, verifyDataAt, verifyDataLength),
                        "a one-bit wrong transcript hash must fail the server Finished");
                assertFalse(Finished.verify(schedule, schedule.clientHandshakeTrafficSecret(),
                        throughCertificateVerify, serverFinishedMsg, verifyDataAt, verifyDataLength),
                        "the client's own Finished key must not verify the server's Finished");

                // Now the client's Finished, over ClientHello..server Finished.
                feed(transcript, arena, serverFinished);
                MemorySegment throughServerFinished = arena.allocate(32);
                transcript.current(throughServerFinished, 0);

                MemorySegment computed = arena.allocate(32);
                Finished.compute(schedule, schedule.clientHandshakeTrafficSecret(),
                        throughServerFinished, computed);

                byte[] clientFinished = messages.get("client Finished");
                MemorySegment clientFinishedMsg = of(arena, clientFinished);
                int clientVerifyDataLength = Handshake.length(clientFinishedMsg, 0);

                assertTrue(Finished.verify(schedule, schedule.clientHandshakeTrafficSecret(),
                        throughServerFinished, clientFinishedMsg, Handshake.HEADER, clientVerifyDataLength),
                        "the recorded client Finished must verify");
                assertArraysEqual(computed, clientFinishedMsg.asSlice(Handshake.HEADER, clientVerifyDataLength),
                        "what this side computes to send must equal the recorded client Finished");
            }
        }
    }

    private static void assertArraysEqual(MemorySegment a, MemorySegment b, String message) {
        assertTrue(a.mismatch(b) == -1, message);
    }

    private static void feed(TranscriptHash transcript, Arena arena, byte[] message) {
        MemorySegment segment = of(arena, message);
        transcript.update(segment, 0, (int) segment.byteSize());
    }

    private static MemorySegment of(Arena arena, byte[] data) {
        MemorySegment segment = arena.allocate(data.length);
        MemorySegment.copy(data, 0, segment, ValueLayout.JAVA_BYTE, 0, data.length);
        return segment;
    }

    @FunctionalInterface
    private interface MessageConsumer {
        void accept(String who, String type, String hex);
    }

    private static void load(MessageConsumer consumer) throws IOException {
        try (InputStream in = FinishedTest.class.getResourceAsStream("/rfc8448-vectors.txt")) {
            assertTrue(in != null, "rfc8448-vectors.txt is not on the test classpath");
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] parts = line.split("\t", -1);
                if (!parts[0].equals("message") || !parts[1].equals("3")) {
                    continue;
                }
                consumer.accept(parts[2], parts[3], parts[4]);
            }
        }
    }

    @FunctionalInterface
    private interface RowConsumer {
        void accept(String name, String[] fields);
    }

    private static void loadKeys(String kind, RowConsumer consumer) throws IOException {
        try (InputStream in = FinishedTest.class.getResourceAsStream("/rfc8448-vectors.txt")) {
            assertTrue(in != null, "rfc8448-vectors.txt is not on the test classpath");
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] parts = line.split("\t", -1);
                if (!parts[0].equals(kind) || !parts[1].equals("3")) {
                    continue;
                }
                consumer.accept(parts[2], java.util.Arrays.copyOfRange(parts, 3, parts.length));
            }
        }
    }
}
