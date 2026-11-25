package space.seclume.internal.jdbc;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.List;

/**
 * A server's error that quotes a value bound with {@code setSensitive}, masked
 * before any of it becomes a String.
 *
 * <p>{@code SensitiveParameters} promises a value that never becomes a String.
 * The error path broke it: PostgreSQL's {@code DETAIL: Key (signing_key)=(...)
 * already exists} or {@code Failing row contains (...)}, MySQL's
 * {@code Duplicate entry '...'}, decoded as they came - the secret a String on
 * the heap and in every log that prints the exception. The receive buffer is
 * searched for each sensitive value's bytes first, and every occurrence is
 * overwritten with {@code *}.
 */
public final class SensitiveEcho {

    /** Shorter values are not looked for: two or three bytes are found anywhere. */
    static final int SHORTEST = 4;

    private SensitiveEcho() {
    }

    /**
     * Overwrites, in {@code buffer} from {@code from} to {@code to}, every
     * occurrence of each of {@code values} with {@code *}; returns how many.
     */
    public static int mask(MemorySegment buffer, long from, long to, List<NativeValue> values) {
        int masked = 0;
        for (NativeValue value : values) {
            MemorySegment needle;
            long length;
            try {
                needle = value.memory();
                length = value.length();
            } catch (IllegalStateException released) {
                continue;                     // the caller's memory is gone; nothing to find
            }
            if (length < SHORTEST || length > to - from) {
                continue;
            }
            byte first;
            try {
                first = needle.get(ValueLayout.JAVA_BYTE, 0);
            } catch (IllegalStateException released) {
                continue;
            }
            for (long at = from; at + length <= to; at++) {
                if (buffer.get(ValueLayout.JAVA_BYTE, at) != first) {
                    continue;
                }
                if (MemorySegment.mismatch(buffer, at, at + length, needle, 0, length) == -1) {
                    buffer.asSlice(at, length).fill((byte) '*');
                    masked++;
                    at += length - 1;
                }
            }
        }
        return masked;
    }
}
