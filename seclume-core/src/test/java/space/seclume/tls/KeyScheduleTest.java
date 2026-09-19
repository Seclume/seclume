package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * {@link KeySchedule} replayed end to end against RFC 8448's trace 3 - not one
 * HKDF call checked against its own vector (that is {@code Rfc8448VectorsTest}),
 * but the whole seven-step chain fed only the two genuinely external inputs
 * (the (EC)DHE shared secret and the transcript hashes) and checked against
 * every named secret the trace prints along the way. A step taken in the wrong
 * order, or one that feeds the wrong secret into the next, produces a wrong
 * "handshake secret" or "master secret" that a per-call test cannot see,
 * because that test only ever checks one call at a time with inputs taken
 * from the trace itself rather than from the previous step.
 */
class KeyScheduleTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void chainsAllSevenStepsOfTrace3() throws IOException {
        Map<String, String[]> extractRows = new HashMap<>();
        Map<String, String[]> expandRows = new HashMap<>();
        List<String[]> finishedRows = new ArrayList<>();
        load("extract", (name, fields) -> extractRows.putIfAbsent(name, fields));
        load("expand", (name, fields) -> {
            expandRows.putIfAbsent(name, fields); // first occurrence: what this trace actually uses next
            if (name.equals("finished")) {
                finishedRows.add(fields);
            }
        });
        assertTrue(extractRows.containsKey("handshake") && extractRows.containsKey("master"),
                "trace 3 vectors are missing - run tools/rfc8448_vectors.py");

        byte[] sharedSecret = HEX.parseHex(extractRows.get("handshake")[1]); // the (EC)DHE IKM
        byte[] helloToHello = HEX.parseHex(expandRows.get("c hs traffic")[1]);
        byte[] helloToServerFinished = HEX.parseHex(expandRows.get("c ap traffic")[1]);
        byte[] helloToClientFinished = HEX.parseHex(expandRows.get("res master")[1]);

        try (Arena arena = Arena.ofConfined();
                KeySchedule schedule = KeySchedule.withoutPsk(space.seclume.crypto.HashAlgorithm.SHA_256)) {
            schedule.deriveHandshakeSecret(of(arena, sharedSecret));
            schedule.deriveHandshakeTrafficSecrets(of(arena, helloToHello));
            schedule.deriveMasterSecret();
            schedule.deriveApplicationTrafficSecrets(of(arena, helloToServerFinished));
            schedule.deriveResumptionMasterSecret(of(arena, helloToClientFinished));

            int len = schedule.length();
            assertSecret(expandRows, "s hs traffic", len, schedule.serverHandshakeTrafficSecret());
            assertSecret(expandRows, "c hs traffic", len, schedule.clientHandshakeTrafficSecret());
            assertArrayEquals(HEX.parseHex(extractRows.get("master")[2]), bytes(schedule.masterSecret(), len));
            assertSecret(expandRows, "s ap traffic", len, schedule.serverApplicationTrafficSecret());
            assertSecret(expandRows, "c ap traffic", len, schedule.clientApplicationTrafficSecret());
            assertSecret(expandRows, "exp master", len, schedule.exporterMasterSecret());
            assertSecret(expandRows, "res master", len, schedule.resumptionMasterSecret());

            // Finished keys and verify_data, both sides - matched to the trace's two
            // unlabelled "finished" rows by which handshake traffic secret is their PRK.
            assertFinishedKey(schedule, finishedRows, schedule.serverHandshakeTrafficSecret(), arena, len);
            assertFinishedKey(schedule, finishedRows, schedule.clientHandshakeTrafficSecret(), arena, len);
        }
    }

    private void assertSecret(Map<String, String[]> expandRows, String label, int len, MemorySegment actual) {
        byte[] expected = HEX.parseHex(expandRows.get(label)[3]);
        assertArrayEquals(expected, bytes(actual, len), "label \"" + label + "\"");
    }

    private void assertFinishedKey(KeySchedule schedule, List<String[]> finishedRows,
            MemorySegment handshakeTrafficSecret, Arena arena, int len) {
        byte[] secretBytes = bytes(handshakeTrafficSecret, len);
        byte[] expected = null;
        for (String[] row : finishedRows) {
            if (Arrays.equals(HEX.parseHex(row[0]), secretBytes)) {
                expected = HEX.parseHex(row[3]);
                break;
            }
        }
        assertTrue(expected != null, "no \"finished\" vector has this traffic secret as its PRK");

        MemorySegment finishedKey = arena.allocate(len);
        schedule.finishedKey(handshakeTrafficSecret, finishedKey);
        assertArrayEquals(expected, bytes(finishedKey, len));
    }

    private static MemorySegment of(Arena arena, byte[] data) {
        MemorySegment segment = arena.allocate(Math.max(1, data.length));
        MemorySegment.copy(data, 0, segment, ValueLayout.JAVA_BYTE, 0, data.length);
        return segment.asSlice(0, data.length);
    }

    private static byte[] bytes(MemorySegment segment, int length) {
        return segment.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE);
    }

    @FunctionalInterface
    private interface RowConsumer {
        void accept(String name, String[] fields);
    }

    /** Only trace 3's rows - the other four traces use different (EC)DHE / PSK combinations. */
    private static void load(String kind, RowConsumer consumer) throws IOException {
        try (InputStream in = KeyScheduleTest.class.getResourceAsStream("/rfc8448-vectors.txt")) {
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
                consumer.accept(parts[2], Arrays.copyOfRange(parts, 3, parts.length));
            }
        }
    }
}
