package space.seclume.internal;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

/**
 * Reading straight into an off-heap segment.
 *
 * <p>The decisive point is in {@link #readFully}: NIO only reads directly into
 * native memory via {@code pread(2)} or {@code ReadFile} when the target buffer
 * is a <b>direct</b> {@link ByteBuffer}. Hand the channel a heap buffer and the
 * JDK internally grabs a temporary direct buffer, copies into it, and from
 * there into the {@code byte[]} - and it is that {@code byte[]} which then
 * shows up in the heap dump. {@code asByteBuffer()} on a native segment yields
 * the direct buffer that prevents this.
 */
public final class OffHeapIo {

    private OffHeapIo() {
    }

    /**
     * Reads until the segment is full or the channel ends.
     *
     * @return the number of bytes read
     * @throws IllegalArgumentException if the target is not native - with a heap
     *         segment the core property would be silently defeated
     */
    public static int readFully(ReadableByteChannel channel, MemorySegment target)
            throws IOException {
        requireNative(target);
        ByteBuffer buffer = target.asByteBuffer();
        int total = 0;
        while (buffer.hasRemaining()) {
            int read = channel.read(buffer);
            if (read < 0) {
                break;
            }
            total += read;
        }
        return total;
    }

    /**
     * Whether the channel would have more data - in which case the segment was
     * too small. Reads a single byte into a direct one-byte buffer.
     */
    public static boolean hasMore(ReadableByteChannel channel) throws IOException {
        ByteBuffer probe = ByteBuffer.allocateDirect(1);
        boolean more = channel.read(probe) > 0;
        // The probe byte is part of the secret - do not leave it lying around.
        probe.clear();
        probe.put((byte) 0);
        return more;
    }

    /** Strips a trailing {@code \n} or {@code \r\n}. */
    public static int trimLineBreak(MemorySegment segment, int length) {
        int end = length;
        while (end > 0) {
            byte last = segment.get(ValueLayout.JAVA_BYTE, end - 1);
            if (last == '\n' || last == '\r') {
                segment.set(ValueLayout.JAVA_BYTE, end - 1, (byte) 0);
                end--;
            } else {
                break;
            }
        }
        return end;
    }

    public static void requireNative(MemorySegment segment) {
        if (!segment.isNative()) {
            throw new IllegalArgumentException(
                    "seclume writes secrets only into native memory; "
                    + "this segment is heap backed and would end up in a heap dump");
        }
    }
}
