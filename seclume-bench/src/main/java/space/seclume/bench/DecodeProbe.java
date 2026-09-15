package space.seclume.bench;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Arrays;

/**
 * Reading bytes out of native memory against reading them out of a byte array.
 *
 * <p>{@code RowsProbe} says this driver is four percent slower than pgjdbc on a
 * hundred thousand rows while allocating half as much or nothing at all. The
 * candidate explanation is this and only this: we parse every value out of a
 * {@link MemorySegment}, they parse it out of a {@code byte[]} the JIT has
 * optimised since 1999. A scan is millions of those accesses.
 *
 * <p>So this measures exactly that difference and nothing else - the same
 * bytes, the same parse, no socket, no protocol, no JDBC. If the gap is here,
 * it is worth knowing how much of the four percent it explains. If it is not
 * here, the four percent are somewhere else and the search starts again.
 *
 * <p>The third arm is the one that decides what to do about it: a
 * {@code MemorySegment} over a <b>heap</b> array rather than native memory.
 * That separates two things the first two arms confound - the cost of the
 * segment abstraction from the cost of the memory being off-heap.
 */
public final class DecodeProbe {

    private DecodeProbe() {
    }

    /** As many values as a hundred thousand rows of three columns carry. */
    private static final int VALUES = 300_000;
    private static final int BYTES_PER_VALUE = 8;

    public static void main(String[] args) throws Exception {
        int repeats = args.length > 0 ? Integer.parseInt(args[0]) : 200;

        byte[] heap = new byte[VALUES * BYTES_PER_VALUE];
        for (int i = 0; i < VALUES; i++) {
            // Seven digits and a separator - the shape of a number in the wire
            // protocol, which sends them as text.
            String text = String.format("%07d", i % 10_000_000);
            for (int b = 0; b < 7; b++) {
                heap[i * BYTES_PER_VALUE + b] = (byte) text.charAt(b);
            }
            heap[i * BYTES_PER_VALUE + 7] = ',';
        }

        try (Arena arena = Arena.ofShared()) {
            MemorySegment native_ = arena.allocate(heap.length);
            MemorySegment.copy(heap, 0, native_, ValueLayout.JAVA_BYTE, 0, heap.length);
            MemorySegment onHeap = MemorySegment.ofArray(heap);

            long[][] times = new long[4][repeats];
            long sink = 0;
            for (int i = 0; i < repeats + 50; i++) {
                long a = System.nanoTime();
                sink += fromArray(heap);
                long b = System.nanoTime();
                sink += fromSegment(native_);
                long c = System.nanoTime();
                sink += fromSegment(onHeap);
                long d = System.nanoTime();
                sink += fromSegmentWide(native_);
                long e = System.nanoTime();
                if (i >= 50) {                       // the first fifty are warm-up
                    times[0][i - 50] = b - a;
                    times[1][i - 50] = c - b;
                    times[2][i - 50] = d - c;
                    times[3][i - 50] = e - d;
                }
            }
            report("byte[]                ", times[0]);
            report("MemorySegment, native ", times[1]);
            report("MemorySegment, on heap", times[2]);
            report("native, eight at once ", times[3]);
            System.out.println("(checksum " + sink + " - so nothing above is optimised away)");
        }
    }

    private static long fromArray(byte[] data) {
        long total = 0;
        for (int at = 0; at < data.length; at += BYTES_PER_VALUE) {
            long value = 0;
            for (int b = 0; b < 7; b++) {
                value = value * 10 + (data[at + b] - '0');
            }
            total += value;
        }
        return total;
    }

    private static long fromSegment(MemorySegment data) {
        long total = 0;
        long length = data.byteSize();
        for (long at = 0; at < length; at += BYTES_PER_VALUE) {
            long value = 0;
            for (int b = 0; b < 7; b++) {
                value = value * 10 + (data.get(ValueLayout.JAVA_BYTE, at + b) - '0');
            }
            total += value;
        }
        return total;
    }

    /**
     * The same parse, reading eight bytes in one access instead of eight.
     *
     * <p>The cost measured above is per <b>access</b>, not per byte, so the
     * answer is to make fewer of them. A value in this protocol is text, and
     * text short enough to fit in a long is most of what a row carries -
     * integers, dates, decimals of ordinary size. One {@code JAVA_LONG} read
     * and seven shifts do what seven checked byte reads did.
     */
    private static long fromSegmentWide(MemorySegment data) {
        long total = 0;
        long length = data.byteSize();
        for (long at = 0; at < length; at += BYTES_PER_VALUE) {
            long eight = data.get(WIDE, at);
            long value = 0;
            for (int b = 0; b < 7; b++) {
                // Little endian: the first byte of the value is the lowest.
                value = value * 10 + (((eight >>> (b * 8)) & 0xff) - '0');
            }
            total += value;
        }
        return total;
    }

    private static final ValueLayout.OfLong WIDE = ValueLayout.JAVA_LONG_UNALIGNED
            .withOrder(java.nio.ByteOrder.LITTLE_ENDIAN);

    private static void report(String name, long[] times) {
        long[] sorted = times.clone();
        Arrays.sort(sorted);
        System.out.printf("  %s  p50 %8.2f ms  best %8.2f ms%n",
                name, sorted[sorted.length / 2] / 1e6, sorted[0] / 1e6);
    }
}
