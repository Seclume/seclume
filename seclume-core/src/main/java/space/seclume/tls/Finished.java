package space.seclume.tls;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import space.seclume.crypto.ConstantTime;

/**
 * The TLS 1.3 {@code Finished} message (RFC 8446, section 4.4.4): a plain
 * {@code verify_data}, no framing of its own beyond the four-byte handshake
 * header - the whole body <em>is</em> the value {@link KeySchedule#finishedKey}
 * and {@link KeySchedule#verifyData} already know how to compute.
 *
 * <p>This class is the wiring between those two {@link KeySchedule} calls and
 * a message on the wire: which side's traffic secret keys the Finished key,
 * which transcript hash it is computed over (through the peer's last message
 * before Finished, never including Finished itself), and the constant-time
 * comparison a verification actually needs. Getting any one of those three
 * wrong produces a Finished that looks like a random 32 bytes rather than an
 * error - the same trap as the key schedule itself, which is why this exists
 * as its own small, named step rather than being inlined at each call site.
 */
public final class Finished {

    private Finished() {
    }

    /**
     * Verifies a received {@code Finished}'s {@code verify_data} against what
     * this side computes itself.
     *
     * @param handshakeTrafficSecret the <b>sender's</b> handshake traffic
     *                               secret - the server's, to verify a
     *                               server Finished
     * @param transcriptHash         the hash of every handshake message up to
     *                               but not including this Finished
     */
    public static boolean verify(KeySchedule schedule, MemorySegment handshakeTrafficSecret,
            MemorySegment transcriptHash, MemorySegment actual, long actualOffset, int actualLength) {
        int len = schedule.length();
        if (actualLength != len) {
            return false;
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocate(len);
            MemorySegment expected = arena.allocate(len);
            try {
                schedule.finishedKey(handshakeTrafficSecret, key);
                schedule.verifyData(key, transcriptHash, expected);
                return ConstantTime.equals(expected, 0, actual, actualOffset, len);
            } finally {
                key.fill((byte) 0);
                expected.fill((byte) 0);
            }
        }
    }

    /**
     * Computes this side's own {@code verify_data}, to send as a Finished
     * message.
     *
     * @param handshakeTrafficSecret <b>this</b> side's handshake traffic
     *                               secret - the client's, to build the
     *                               client's own Finished
     */
    public static void compute(KeySchedule schedule, MemorySegment handshakeTrafficSecret,
            MemorySegment transcriptHash, MemorySegment out) {
        int len = schedule.length();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocate(len);
            try {
                schedule.finishedKey(handshakeTrafficSecret, key);
                schedule.verifyData(key, transcriptHash, out);
            } finally {
                key.fill((byte) 0);
            }
        }
    }
}
