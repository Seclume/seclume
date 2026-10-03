package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class WireBufferBoundsTest {

    @ParameterizedTest
    @ValueSource(ints = {-1, Integer.MIN_VALUE, Integer.MAX_VALUE})
    void invalidPaddingDoesNotChangeTheBuffer(int count) {
        try (WireBuffer buffer = new WireBuffer(64)) {
            buffer.putByte((byte) 42);
            MemorySegment original = buffer.segment();
            assertThrows(WireBuffer.Truncated.class, () -> buffer.putZeroes(count));
            assertSame(original, buffer.segment());
            assertEquals(1, buffer.position());
            assertEquals(42, buffer.getByte(0));
        }
    }

    @ParameterizedTest
    @ValueSource(longs = {-1, Long.MIN_VALUE, 0x1_0000_0000L, Long.MAX_VALUE})
    void invalidCopyLengthIsRejectedBeforeNarrowing(long length) {
        try (WireBuffer buffer = new WireBuffer(64)) {
            buffer.putByte((byte) 42);
            MemorySegment original = buffer.segment();
            assertThrows(WireBuffer.Truncated.class,
                    () -> buffer.putBytes(MemorySegment.NULL, 0, length));
            assertSame(original, buffer.segment());
            assertEquals(1, buffer.position());
            assertEquals(42, buffer.getByte(0));
        }
    }

    @ParameterizedTest
    @ValueSource(longs = {-1, 1, Long.MAX_VALUE})
    void invalidSourceRangeDoesNotGrowOrWipeTheDestination(long offset) {
        try (WireBuffer source = new WireBuffer(64); WireBuffer buffer = new WireBuffer(64)) {
            buffer.putByte((byte) 42);
            MemorySegment original = buffer.segment();
            // A valid copy would grow the destination; an invalid one must not.
            assertThrows(WireBuffer.Truncated.class,
                    () -> buffer.putBytes(source.segment(), offset, 64));
            assertSame(original, buffer.segment());
            assertEquals(42, original.get(ValueLayout.JAVA_BYTE, 0));
            assertEquals(1, buffer.position());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, Integer.MIN_VALUE})
    void negativeCapacityIsRejected(int capacity) {
        try (WireBuffer buffer = new WireBuffer(64)) {
            assertThrows(WireBuffer.Truncated.class, () -> buffer.ensureCapacity(capacity));
            assertEquals(64, buffer.capacity());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, Integer.MIN_VALUE, 65, Integer.MAX_VALUE})
    void invalidPositionIsRejected(int position) {
        try (WireBuffer buffer = new WireBuffer(64)) {
            buffer.putByte((byte) 42);
            assertThrows(WireBuffer.Truncated.class, () -> buffer.position(position));
            assertEquals(1, buffer.position());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 9})
    void invalidIntegerWidthDoesNotChangeTheBuffer(int width) {
        try (WireBuffer buffer = new WireBuffer(64)) {
            buffer.putZeroes(16);
            buffer.limit(16);
            buffer.position(1);
            assertThrows(WireBuffer.Truncated.class, () -> buffer.putUnsignedLe(-1L, width));
            assertThrows(WireBuffer.Truncated.class, () -> buffer.putUnsignedLeAt(0, -1L, width));
            assertThrows(WireBuffer.Truncated.class, () -> buffer.getUnsignedLe(width));
            assertEquals(1, buffer.position());
            for (int i = 0; i < 16; i++) {
                assertEquals(0, buffer.getByte(i));
            }
        }
    }

    @Test
    void headerPatchChecksTheWholeRangeBeforeWriting() {
        try (WireBuffer buffer = new WireBuffer(64)) {
            buffer.putZeroes(64);
            assertThrows(WireBuffer.Truncated.class, () -> buffer.putUnsignedLeAt(63, -1L, 3));
            assertEquals(0, buffer.getByte(63));
            assertEquals(64, buffer.position());
            assertThrows(WireBuffer.Truncated.class,
                    () -> buffer.putUnsignedLeAt(Integer.MAX_VALUE, -1L, 3));
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3, 4, 5, 6, 7, 8})
    void supportedIntegerWidthsStillRoundTripAcrossGrowth(int width) {
        try (WireBuffer buffer = new WireBuffer(64)) {
            buffer.putZeroes(63);
            long value = 0x8070605040302010L;
            buffer.putUnsignedLe(value, width);
            buffer.limit(buffer.position());
            buffer.position(63);
            long expected = width == 8 ? value : value & ((1L << (8 * width)) - 1);
            assertEquals(expected, buffer.getUnsignedLe(width));
            buffer.putUnsignedLeAt(63, -1L, width);
            buffer.position(63);
            assertEquals(width == 8 ? -1L : (1L << (8 * width)) - 1,
                    buffer.getUnsignedLe(width));
        }
    }

    @Test
    void growthPreservesValidContentAndWipesOldMemory() {
        try (WireBuffer buffer = new WireBuffer(64); WireBuffer source = new WireBuffer(64)) {
            buffer.putByte((byte) 42);
            MemorySegment old = buffer.segment();
            source.putZeroes(64);
            source.putByteAt(63, (byte) 7);
            buffer.putBytes(source.segment());
            assertEquals(65, buffer.position());
            assertEquals(42, buffer.getByte(0));
            assertEquals(7, buffer.getByte(64));
            assertEquals(0, old.get(ValueLayout.JAVA_BYTE, 0));
            assertEquals(128, buffer.capacity());
        }
    }

    @Test
    void unterminatedTextDoesNotAdvanceBeyondTheMessage() {
        try (WireBuffer buffer = new WireBuffer(64)) {
            buffer.putText("column");
            buffer.limit(buffer.position());
            buffer.position(0);
            assertThrows(WireBuffer.Truncated.class, buffer::readCString);
            assertEquals(0, buffer.position());
            buffer.position(buffer.limit());
            assertThrows(WireBuffer.Truncated.class, buffer::readCString);
            assertEquals(buffer.limit(), buffer.position());
        }
    }

    @Test
    void terminatedTextAtCapacityStillReads() {
        try (WireBuffer buffer = new WireBuffer(64)) {
            buffer.putZeroes(57).putCString("column");
            buffer.limit(64);
            buffer.position(57);
            assertEquals("column", buffer.readCString());
            assertEquals(0, buffer.remaining());
        }
    }

    @Test
    void writingAtCapacityCanGrowWithoutAReadLimit() {
        try (WireBuffer buffer = new WireBuffer(64)) {
            buffer.position(64);
            buffer.putByte((byte) 42).putShort((short) 7).putInt(9)
                    .putShortLe((short) 11).putIntLe(13).putLongLe(17);
            buffer.limit(buffer.position());
            buffer.position(64);
            assertEquals(42, buffer.getByte());
            assertEquals(7, buffer.getShort());
            assertEquals(9, buffer.getInt());
            assertEquals(11, buffer.getShortLe());
            assertEquals(13, buffer.getIntLe());
            assertEquals(17, buffer.getLongLe());
            assertEquals(0, buffer.remaining());
        }
    }
}
