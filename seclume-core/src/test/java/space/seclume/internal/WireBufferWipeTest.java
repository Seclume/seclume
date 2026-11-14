package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import org.junit.jupiter.api.Test;

/**
 * What the wire buffer wipes, and exactly that much; and that every write at
 * the end of the memory grows it rather than failing.
 *
 * <p>The password of a login passes through this buffer. {@code clear()}
 * promises to reset it "without leaving the content behind" - in both of
 * its states: written (position set, no limit) and read (limit set). PIT
 * found the choice between the two unchecked, and the byte-by-byte wipe of a
 * short run one byte off without a test noticing (run 43416680859,
 * {@code WireBuffer}: 46 survivors). Each wipe here is checked byte by byte,
 * and the byte just past it is checked to still be there - a wipe one too
 * long destroys the next field, one too short leaves a byte of the secret.
 */
class WireBufferWipeTest {

    private static final byte SECRET = (byte) 0x5A;

    private static byte at(WireBuffer buffer, long index) {
        return buffer.segment().get(ValueLayout.JAVA_BYTE, index);
    }

    private static void fill(WireBuffer buffer, int count) {
        for (int i = 0; i < count; i++) {
            buffer.putByte(SECRET);
        }
    }

    private static void assertZero(WireBuffer buffer, long from, long to) {
        for (long i = from; i < to; i++) {
            assertEquals(0, at(buffer, i), "byte " + i + " was not wiped");
        }
    }

    /** Written, not read: what lies before the position is the content. */
    @Test
    void clearAfterWritingWipesEverythingWritten() {
        for (int length : new int[] {1, 31, 32, 33, 100}) {
            try (WireBuffer buffer = new WireBuffer(128)) {
                fill(buffer, length);
                assertEquals(0, buffer.limit());
                buffer.clear();
                assertZero(buffer, 0, length);
                assertEquals(0, buffer.position());
                assertEquals(0, buffer.limit());
            }
        }
    }

    /** Read, with a limit: the whole message is the content, also past where reading stopped. */
    @Test
    void clearAfterReadingWipesTheWholeMessage() {
        for (int length : new int[] {4, 32, 40}) {
            try (WireBuffer buffer = new WireBuffer(128)) {
                fill(buffer, length);
                buffer.limit(length);
                buffer.position(2);                     // read only the start of it
                buffer.clear();
                assertZero(buffer, 0, length);
                assertEquals(0, buffer.position());
                assertEquals(0, buffer.limit());
            }
        }
    }

    @Test
    void clearWipesNoMoreThanTheContent() {
        try (WireBuffer buffer = new WireBuffer(128)) {
            fill(buffer, 20);
            buffer.position(10);                        // the content ends here
            buffer.clear();
            assertZero(buffer, 0, 10);
            assertEquals(SECRET, at(buffer, 10), "the byte after the content is not the buffer's to wipe");
        }
    }

    @Test
    void zeroesOverwriteWhatWasThereAndNothingBeyond() {
        for (int count : new int[] {1, 5, 32, 33, 50}) {
            try (WireBuffer buffer = new WireBuffer(128)) {
                fill(buffer, 100);
                buffer.position(3);
                assertSame(buffer, buffer.putZeroes(count));
                assertEquals(3 + count, buffer.position());
                assertEquals(SECRET, at(buffer, 2), "before the run, count " + count);
                assertZero(buffer, 3, 3 + count);
                assertEquals(SECRET, at(buffer, 3 + count), "after the run, count " + count);
            }
        }
    }

    @Test
    void growingWipesTheMemoryItLeaves() {
        try (WireBuffer buffer = new WireBuffer(64)) {
            fill(buffer, 64);
            MemorySegment old = buffer.segment();
            buffer.putByte(SECRET);                    // the 65th byte does not fit
            assertEquals(64, old.byteSize());
            for (long i = 0; i < old.byteSize(); i++) {
                assertEquals(0, old.get(ValueLayout.JAVA_BYTE, i), "old byte " + i);
            }
            for (int i = 0; i < 65; i++) {
                assertEquals(SECRET, at(buffer, i), "carried over: " + i);
            }
        }
    }

    /** At the very end of the memory every kind of write makes room first. */
    @Test
    void everyWriteAtTheEndOfTheMemoryGrowsTheBuffer() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment source = arena.allocate(8);
            source.fill((byte) 7);
            record Write(String name, java.util.function.Consumer<WireBuffer> write, int length) {
            }
            for (Write write : new Write[] {
                    new Write("putShort", b -> b.putShort((short) 0x0102), 2),
                    new Write("putInt", b -> b.putInt(0x01020304), 4),
                    new Write("putShortLe", b -> b.putShortLe((short) 0x0102), 2),
                    new Write("putIntLe", b -> b.putIntLe(0x01020304), 4),
                    new Write("putLongLe", b -> b.putLongLe(0x0102030405060708L), 8),
                    new Write("putBytes", b -> b.putBytes(source), 8),
                    new Write("putText", b -> b.putText("abcdefgh"), 8),
                    new Write("putText (UTF-8)", b -> b.putText("éééé"), 8),
                    new Write("putCString", b -> b.putCString("abc"), 4),
                    new Write("putZeroes", b -> b.putZeroes(8), 8)}) {
                try (WireBuffer buffer = new WireBuffer(64)) {
                    buffer.position(63);
                    write.write().accept(buffer);
                    assertEquals(63 + write.length(), buffer.position(), write.name());
                    assertEquals(128, buffer.capacity(), write.name() + " grew the buffer");
                }
            }
            // Four characters fit, their eight UTF-8 bytes do not: the second check makes the room.
            try (WireBuffer buffer = new WireBuffer(64)) {
                buffer.position(60);
                buffer.putText("\u00e9\u00e9\u00e9\u00e9");
                assertEquals(68, buffer.position());
                assertEquals((byte) 0xA9, at(buffer, 67));
            }
        }
    }

    @Test
    void numbersLandInTheirByteOrder() {
        try (WireBuffer buffer = new WireBuffer(64)) {
            buffer.putShort((short) 0x0102).putInt(0x03040506).putShortLe((short) 0x0708)
                    .putIntLe(0x090A0B0C).putLongLe(0x0D0E0F1011121314L);
            byte[] expected = {1, 2, 3, 4, 5, 6, 8, 7, 0x0C, 0x0B, 0x0A, 9,
                    0x14, 0x13, 0x12, 0x11, 0x10, 0x0F, 0x0E, 0x0D};
            for (int i = 0; i < expected.length; i++) {
                assertEquals(expected[i], at(buffer, i), "byte " + i);
            }
        }
    }

    /** Every write hands back the buffer it wrote to, for the next one in a chain. */
    @Test
    void everyWriteReturnsTheBufferItself() {
        try (Arena arena = Arena.ofConfined(); WireBuffer buffer = new WireBuffer(64)) {
            MemorySegment source = arena.allocate(4);
            assertSame(buffer, buffer.putBytes(source));
            assertSame(buffer, buffer.putBytes(source, 1, 2));
            assertSame(buffer, buffer.putText("ascii"));
            assertSame(buffer, buffer.putText("ü"));
            assertSame(buffer, buffer.putCString("c"));
            assertSame(buffer, buffer.putLongLe(1));
            assertSame(buffer, buffer.putByteAt(0, (byte) 1));
            assertSame(buffer, buffer.putUnsignedLeAt(0, 1, 2));
            assertSame(buffer, buffer.putInt(0, 1));
            assertSame(buffer, buffer.putIntLe(0, 1));
        }
    }

    @Test
    void theLastCharacterBelowUtf8sMultiByteRangeIsOneByteAndTheFirstInItIsTwo() {
        try (WireBuffer buffer = new WireBuffer(64)) {
            buffer.putText("\u007f");
            assertEquals(1, buffer.position());
            assertEquals(0x7f, at(buffer, 0));
            buffer.putText("\u0080");
            assertEquals(3, buffer.position(), "U+0080 is two bytes in UTF-8");
            assertEquals((byte) 0xC2, at(buffer, 1));
            assertEquals((byte) 0x80, at(buffer, 2));
        }
    }

    @Test
    void rangesThatEndExactlyAtTheEdgeAreAccepted() {
        try (Arena arena = Arena.ofConfined(); WireBuffer buffer = new WireBuffer(64)) {
            MemorySegment source = arena.allocate(5);
            for (int i = 0; i < 5; i++) {
                source.set(ValueLayout.JAVA_BYTE, i, (byte) (i + 1));
            }
            buffer.putBytes(source, 2, 3);              // the last three bytes of the source
            assertEquals(3, buffer.position());
            assertEquals(3, at(buffer, 0));
            assertEquals(5, at(buffer, 2));
            buffer.putBytes(source, 0, 5);              // all of it
            assertEquals(8, buffer.position());
            assertThrows(WireBuffer.Truncated.class, () -> buffer.putBytes(source, 3, 3));

            buffer.putUnsignedLeAt(buffer.capacity() - 4, 0x01020304L, 4);   // the last four bytes
            assertEquals(4, at(buffer, buffer.capacity() - 4));
            assertEquals(1, at(buffer, buffer.capacity() - 1));
            assertThrows(WireBuffer.Truncated.class,
                    () -> buffer.putUnsignedLeAt(buffer.capacity() - 3, 1, 4));

            buffer.limit(buffer.capacity());              // a message exactly as long as the memory
            assertEquals(buffer.capacity(), buffer.limit());
            buffer.position(10);
            assertEquals(buffer.capacity() - 10, buffer.remaining());
            assertThrows(WireBuffer.Truncated.class, () -> buffer.limit(buffer.capacity() + 1));
        }
    }
}
