package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Random;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The deterministic part of {@link TlsRecordFuzzTest}, in every build: a
 * fixed sample of inputs for each harness, and the controls that show each
 * harness reaches what it is meant to - a clean run delivers the data, a
 * clean frozen connection is rebuilt, and one at the end of its sequence
 * numbers is refused rather than wrapped.
 */
@Timeout(120)
class TlsRecordFuzzSampleTest {

    @Test
    void recordsAfterTheHandshake() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        EncryptedFlight.Material material = EncryptedFlight.material();

        // Control: two data records arrive whole, nothing else in between.
        byte[] clean = {0, 3, 'o', 'n', 'e', 0, 3, 't', 'w', 'o'};
        byte[] got = PostHandshakeRecords.run(clean, material);
        assertArrayEquals(PostHandshakeRecords.script(clean).data(), got,
                "the control case did not deliver its data - the harness reaches nothing");

        Random random = new Random(8446);
        for (int i = 0; i < 400; i++) {
            byte[] input = new byte[random.nextInt(96)];
            random.nextBytes(input);
            PostHandshakeRecords.run(input, material);
        }
    }

    /**
     * The rule the frozen-connection harness found broken on 30.09.2026: at the
     * last sequence number a key neither seals nor opens - before, it sealed
     * and the next record went out under sequence 0 again.
     */
    @Test
    void aKeyAtItsLastSequenceNumberIsUsedUp() {
        try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined();
             RecordProtection key = RecordProtection.fromSecret(
                     space.seclume.crypto.HashAlgorithm.SHA_256, arena.allocate(32), 16)) {
            java.lang.foreign.MemorySegment plain = arena.allocate(1);
            java.lang.foreign.MemorySegment sealed =
                    arena.allocate(RecordProtection.sealedLength(1));
            key.sequence(-2L);
            key.seal((byte) 23, plain, 0, 1, sealed, 0);        // the one before the last
            assertTrue(key.usedUp());
            org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                    () -> key.seal((byte) 23, plain, 0, 1, sealed, 0));
            org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                    () -> key.open(sealed, 0, RecordProtection.sealedLength(1),
                            arena.allocate(64), 0));
            org.junit.jupiter.api.Assertions.assertEquals(-1L, key.sequence(),
                    "a refused record moved the sequence number on");
        }
    }

    @Test
    void aFrozenConnection() {
        // Controls: a clean one is rebuilt, and one at the end of its numbers
        // is refused - flags 0x04 put both sequences at the end.
        assertTrue(FrozenConnections.run(new byte[] {0}), "a clean frozen connection was refused");
        org.junit.jupiter.api.Assertions.assertFalse(
                FrozenConnections.run(new byte[] {0x04, 0, 0, 0, 0, 0, 0, 0, 0}),
                "a frozen connection at the end of its sequence numbers was rebuilt");

        Random random = new Random(5246);
        for (int i = 0; i < 5000; i++) {
            byte[] input = new byte[random.nextInt(160)];
            random.nextBytes(input);
            FrozenConnections.run(input);
        }
    }
}
