package space.seclume;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/**
 * Test helpers: build segments from strings and hex, and read them back.
 *
 * <p>The heap is explicitly allowed here - this is about test vectors and dummy
 * inputs, not about secrets. In production code exactly this is forbidden, and
 * the ArchUnit-style test watches over it.
 */
public final class Segments {

    private Segments() {
    }

    public static MemorySegment ascii(Arena arena, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.US_ASCII);
        MemorySegment segment = arena.allocate(bytes.length);
        MemorySegment.copy(MemorySegment.ofArray(bytes), 0, segment, 0, bytes.length);
        return segment;
    }

    public static MemorySegment utf8(Arena arena, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        MemorySegment segment = arena.allocate(bytes.length);
        MemorySegment.copy(MemorySegment.ofArray(bytes), 0, segment, 0, bytes.length);
        return segment;
    }

    public static MemorySegment hex(Arena arena, String hex) {
        return bytes(arena, HexFormat.of().parseHex(hex));
    }

    public static MemorySegment bytes(Arena arena, byte[] data) {
        MemorySegment segment = arena.allocate(data.length);
        MemorySegment.copy(MemorySegment.ofArray(data), 0, segment, 0, data.length);
        return segment;
    }

    public static MemorySegment repeated(Arena arena, int value, int count) {
        MemorySegment segment = arena.allocate(count);
        segment.fill((byte) value);
        return segment;
    }

    public static byte[] toBytes(MemorySegment segment) {
        byte[] out = new byte[(int) segment.byteSize()];
        MemorySegment.copy(segment, ValueLayout.JAVA_BYTE, 0, out, 0, out.length);
        return out;
    }

    public static String toHex(MemorySegment segment) {
        return HexFormat.of().formatHex(toBytes(segment));
    }
}
