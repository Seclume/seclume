package space.seclume.tls;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.util.zip.CRC32;

/**
 * One fuzz case against {@link TlsMigration#decode}: the written-down state
 * of a connection, as it arrives from another node.
 *
 * <p>A buffer of random bytes would stop at the magic or the checksum every
 * time and prove nothing about what lies behind them, so the input is made
 * into a frozen connection with each field chosen by it - magic, version,
 * length and checksum right unless the first byte says otherwise, then the
 * cipher suite, key length, two sequence numbers and two secrets as the input
 * has them.
 *
 * <p>What must hold, for every input:
 *
 * <ul>
 *   <li>a refusal is an {@link IllegalArgumentException} and nothing else;
 *   <li>a connection that is rebuilt can seal a record, and its sequence
 *       number then moves on by one - <b>it never wraps round to a number
 *       already used</b>, which would repeat a nonce under the same key
 *       (RFC 8446 section 5.3: rekey or close, never wrap).
 * </ul>
 */
final class FrozenConnections {

    private FrozenConnections() {
    }

    /** The frozen connection an input stands for. */
    static byte[] blob(byte[] input) {
        ByteBuffer in = ByteBuffer.wrap(input);
        int flags = next(in);
        boolean sha384 = (flags & 1) != 0;
        int digest = sha384 ? 48 : 32;
        int length = 16 + 24 + 2 * digest;
        ByteBuffer out = ByteBuffer.allocate(length);
        out.putInt((flags & 0x80) != 0 ? nextInt(in) : TlsMigration.MAGIC);
        out.putInt((flags & 0x40) != 0 ? nextInt(in) : TlsMigration.VERSION);
        out.putInt((flags & 0x20) != 0 ? nextInt(in) : length);
        out.putInt(0);                                          // the checksum, below
        out.putInt((flags & 0x10) != 0 ? nextInt(in) : sha384 ? 2 : 1);
        out.putInt((flags & 0x08) != 0 ? nextInt(in) : (flags & 2) != 0 ? 32 : 16);
        out.putLong(sequence(in, flags >>> 2 & 1));
        out.putLong(sequence(in, flags >>> 2 & 1));
        while (out.hasRemaining()) {
            out.put((byte) next(in));
        }
        byte[] blob = out.array();
        CRC32 crc = new CRC32();
        crc.update(blob);                                       // with the field still zero
        int checksum = (flags & 0x04) != 0 && (flags & 0x02) != 0 ? nextInt(in)
                : (int) crc.getValue();
        ByteBuffer.wrap(blob).putInt(12, checksum);
        return blob;
    }

    /** A sequence number - most often one near the end, where wrapping would begin. */
    private static long sequence(ByteBuffer in, int nearTheEnd) {
        long value = nextLong(in);
        return nearTheEnd != 0 ? -1L - (value & 3) : value;
    }

    private static int next(ByteBuffer in) {
        return in.hasRemaining() ? in.get() & 0xff : 0;
    }

    private static int nextInt(ByteBuffer in) {
        return (next(in) << 24) | (next(in) << 16) | (next(in) << 8) | next(in);
    }

    private static long nextLong(ByteBuffer in) {
        return ((long) nextInt(in) << 32) | (nextInt(in) & 0xffffffffL);
    }

    /**
     * Runs one input; returns normally when the case ended the way it has to,
     * throws {@link AssertionError} when it did not.
     *
     * @return whether a connection was rebuilt
     */
    static boolean run(byte[] input) {
        byte[] blob = blob(input);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment in = arena.allocate(blob.length);
            MemorySegment.copy(blob, 0, in, ValueLayout.JAVA_BYTE, 0, blob.length);
            TlsMigration.Thawed thawed;
            try {
                thawed = TlsMigration.decode(in, 0, blob.length);
            } catch (IllegalArgumentException refused) {
                return false;
            } catch (RuntimeException | Error wrong) {
                throw new AssertionError("a frozen connection was refused with " + wrong
                        + " rather than an IllegalArgumentException", wrong);
            }
            try {
                RecordProtection writing = thawed.writing();
                long before = writing.sequence();
                MemorySegment plain = arena.allocate(1);
                MemorySegment sealed = arena.allocate(RecordProtection.sealedLength(1));
                try {
                    writing.seal((byte) 23, plain, 0, 1, sealed, 0);
                } catch (IllegalStateException usedUp) {
                    if (before != -1L) {
                        throw new AssertionError("sealing refused at sequence " + before
                                + ", which is not the last one", usedUp);
                    }
                    return true;
                }
                if (before == -1L) {
                    throw new AssertionError("a record was sealed with the last sequence "
                            + "number, and the next one is 0 again - a nonce repeated");
                }
                if (writing.sequence() != before + 1) {
                    throw new AssertionError("the sequence number went from " + before
                            + " to " + writing.sequence());
                }
                return true;
            } finally {
                thawed.reading().close();
                thawed.writing().close();
            }
        }
    }
}
