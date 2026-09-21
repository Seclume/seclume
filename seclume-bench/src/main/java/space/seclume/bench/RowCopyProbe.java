package space.seclume.bench;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Arrays;

/**
 * What it costs to take a row over by copying it.
 *
 * <p>PostgreSQL's result block does not copy: it writes down two numbers per
 * cell and swaps the whole receive buffer with the session at the end of the
 * statement. MySQL's does copy - one span per row, which is already better
 * than one per cell, but still a copy of every byte that arrives.
 *
 * <p>Before rebuilding the second to look like the first, the question is what
 * the copy is worth. A hundred thousand rows of the width a result usually
 * has, copied span by span, against the same rows merely walked.
 */
public final class RowCopyProbe {

    private RowCopyProbe() {
    }

    private static final int ROWS = 100_000;

    public static void main(String[] args) throws Exception {
        int width = args.length > 0 ? Integer.parseInt(args[0]) : 48;
        int repeats = args.length > 1 ? Integer.parseInt(args[1]) : 200;
        int columns = args.length > 2 ? Integer.parseInt(args[2]) : 3;

        try (Arena arena = Arena.ofShared()) {
            MemorySegment source = arena.allocate((long) ROWS * width);
            MemorySegment target = arena.allocate((long) ROWS * width);
            for (long i = 0; i < source.byteSize(); i++) {
                source.set(ValueLayout.JAVA_BYTE, i, (byte) ('0' + (i % 10)));
            }

            long[][] times = new long[3][repeats];
            long sink = 0;
            for (int i = 0; i < repeats + 30; i++) {
                long a = System.nanoTime();
                copyRowByRow(source, target, width);
                long b = System.nanoTime();
                copyCellByCell(source, target, width, columns);
                long c = System.nanoTime();
                sink += noteOffsets(width);
                long d = System.nanoTime();
                if (i >= 30) {
                    times[0][i - 30] = b - a;
                    times[1][i - 30] = c - b;
                    times[2][i - 30] = d - c;
                }
            }
            report("one copy per row          ", times[0]);
            report("one copy per cell         ", times[1]);
            report("write down two numbers    ", times[2]);
            System.out.println("(checksum " + sink + ", " + ROWS + " rows of "
                    + width + " bytes in " + columns + " columns)");
        }
    }

    private static void copyRowByRow(MemorySegment source, MemorySegment target, int width) {
        for (int row = 0; row < ROWS; row++) {
            long at = (long) row * width;
            MemorySegment.copy(source, at, target, at, width);
        }
    }

    /** What the TDS block does: a copy for every cell, not for every row. */
    private static void copyCellByCell(MemorySegment source, MemorySegment target,
                                       int width, int columns) {
        int cell = width / columns;
        for (int row = 0; row < ROWS; row++) {
            long at = (long) row * width;
            for (int column = 0; column < columns; column++) {
                MemorySegment.copy(source, at + (long) column * cell,
                        target, at + (long) column * cell, cell);
            }
        }
    }

    /** What the PostgreSQL block does instead: bookkeeping, no bytes moved. */
    private static long noteOffsets(int width) {
        int[] cells = new int[ROWS * 2]; // seclume-allow: measurement bookkeeping, no secret in this module
        long total = 0;
        for (int row = 0; row < ROWS; row++) {
            cells[row * 2] = row * width;
            cells[row * 2 + 1] = width;
            total += cells[row * 2 + 1];
        }
        return total;
    }

    private static void report(String what, long[] times) {
        long[] sorted = times.clone();
        Arrays.sort(sorted);
        System.out.printf("  %s  p50 %8.3f ms  best %8.3f ms%n",
                what, sorted[sorted.length / 2] / 1e6, sorted[0] / 1e6);
    }
}
