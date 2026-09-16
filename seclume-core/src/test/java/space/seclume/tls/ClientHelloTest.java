package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Boundary checks; the independent encoding verdict is in LocalClientHelloTest. */
class ClientHelloTest {
    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"localhost", "db.example.test", "xn--bcher-kva.example"})
    void encodesCompleteLengthDelimitedMessages(String name) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(1024);
            out.fill((byte) 0x5a);
            MemorySegment random = arena.allocate(32).fill((byte) 0x12);
            MemorySegment session = arena.allocate(32).fill((byte) 0x34);
            MemorySegment share = arena.allocate(32).fill((byte) 0x56);
            int size = ClientHello.write(out, 7, random, session, share, name);
            assertEquals(0x5a, out.get(ValueLayout.JAVA_BYTE, 6));
            assertEquals(0x5a, out.get(ValueLayout.JAVA_BYTE, 7 + size));
            ByteBuffer in = out.asSlice(7, size).asByteBuffer();
            assertEquals(1, in.get());
            int declared = (Byte.toUnsignedInt(in.get()) << 16) | Short.toUnsignedInt(in.getShort());
            assertEquals(in.remaining(), declared);
            assertEquals(0x0303, in.getShort());
            assertEquals(-1, random.mismatch(MemorySegment.ofBuffer(in.slice(in.position(), 32))));
            in.position(in.position() + 32);
            assertEquals(32, in.get());
            assertEquals(-1, session.mismatch(MemorySegment.ofBuffer(in.slice(in.position(), 32))));
            in.position(in.position() + 32);
            int suites = Short.toUnsignedInt(in.getShort());
            assertEquals(4, suites);
            assertEquals(0x1302, in.getShort());
            assertEquals(0x1301, in.getShort());
            assertEquals(1, in.get());
            assertEquals(0, in.get());
            assertEquals(in.remaining() - 2, Short.toUnsignedInt(in.getShort()));
            Set<Integer> seen = new HashSet<>();
            while (in.hasRemaining()) {
                int type = Short.toUnsignedInt(in.getShort());
                int length = Short.toUnsignedInt(in.getShort());
                assertTrue(seen.add(type), "duplicate extension");
                ByteBuffer extension = in.slice(in.position(), length);
                if (type == 0) {
                    byte[] ascii = name.getBytes(StandardCharsets.US_ASCII);
                    assertEquals(ascii.length + 3, extension.getShort());
                    assertEquals(0, extension.get());
                    assertEquals(ascii.length, extension.getShort());
                    assertEquals(-1, MemorySegment.ofArray(ascii).mismatch(MemorySegment.ofBuffer(extension)));
                } else if (type == 51) {
                    assertEquals(36, extension.getShort());
                    assertEquals(29, extension.getShort());
                    assertEquals(32, extension.getShort());
                    assertEquals(-1, share.mismatch(MemorySegment.ofBuffer(extension)));
                }
                in.position(in.position() + length);
            }
            assertEquals(name == null ? Set.of(10, 13, 43, 50, 51) : Set.of(0, 10, 13, 43, 50, 51), seen);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 31, 32})
    void supportsTheLegalSessionIdLengths(int length) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(512);
            int count = ClientHello.write(out, 0, arena.allocate(32), arena.allocate(length),
                    arena.allocate(32), null);
            assertEquals(length, Handshake.sessionIdLength(out, 4));
            assertEquals(count, Handshake.totalLength(out, 0));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "127.0.0.1", "::1", "db..test", "db.test.", "-db.test", "db-.test", "bücher.test", "db_test", "db/test"})
    void rejectsInvalidSniBeforeWriting(String name) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(512).fill((byte) 0x5a);
            MemorySegment input = arena.allocate(32);
            assertThrows(IllegalArgumentException.class,
                    () -> ClientHello.write(out, 0, input, input, input, name));
            assertEquals(0x5a, out.get(ValueLayout.JAVA_BYTE, 0));
        }
    }

    @Test
    void p256UsesAnUncompressedPointAndMatchingGroup() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(512);
            MemorySegment input = arena.allocate(32);
            MemorySegment share = arena.allocate(65).fill((byte) 0x56);
            share.set(ValueLayout.JAVA_BYTE, 0, (byte) 4);
            int count = ClientHello.write(out, 0, input, input, ClientHello.SECP256R1, share, null);
            assertEquals(count, Handshake.totalLength(out, 0));
            int[] size = new int[1];
            long start = Handshake.clientHelloExtensions(out, 4, size);
            Set<Integer> checked = new HashSet<>();
            Handshake.extensions(out, start, size[0], (type, at, length) -> {
                if (type == 10) {
                    assertEquals(4, length);
                    assertEquals(2, Handshake.u16(out, at));
                    assertEquals(23, Handshake.u16(out, at + 2));
                    checked.add(type);
                } else if (type == 51) {
                    assertEquals(71, length);
                    assertEquals(69, Handshake.u16(out, at));
                    assertEquals(23, Handshake.u16(out, at + 2));
                    assertEquals(65, Handshake.u16(out, at + 4));
                    assertEquals(-1, share.mismatch(out.asSlice(at + 6, 65)));
                    checked.add(type);
                }
            });
            assertEquals(Set.of(10, 51), checked);
            share.set(ValueLayout.JAVA_BYTE, 0, (byte) 2);
            assertThrows(IllegalArgumentException.class,
                    () -> ClientHello.write(out, 0, input, input, ClientHello.SECP256R1, share, null));
            assertThrows(IllegalArgumentException.class,
                    () -> ClientHello.write(out, 0, input, input, 0x1234, input, null));
            assertThrows(IllegalArgumentException.class,
                    () -> ClientHello.write(out, 0, input, input, ClientHello.SECP256R1, input, null));
        }
    }

    @Test
    void enforcesDnsLengthBounds() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(1024);
            MemorySegment input = arena.allocate(32);
            String longest = "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(61);
            int count = ClientHello.write(out, 0, input, input, input, longest);
            assertEquals(count, Handshake.totalLength(out, 0));
            assertThrows(IllegalArgumentException.class,
                    () -> ClientHello.write(out, 0, input, input, input, longest + "d"));
            assertThrows(IllegalArgumentException.class,
                    () -> ClientHello.write(out, 0, input, input, input, "a".repeat(64) + ".test"));
        }
    }

    @Test
    void rejectsWrongSizesAndShortOutputBeforeWriting() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(512).fill((byte) 0x5a);
            MemorySegment input = arena.allocate(32);
            MemorySegment shortInput = arena.allocate(31);
            assertThrows(IllegalArgumentException.class,
                    () -> ClientHello.write(out, 0, shortInput, input, input, null));
            assertThrows(IllegalArgumentException.class,
                    () -> ClientHello.write(out, 0, input, input, shortInput, null));
            assertThrows(IllegalArgumentException.class,
                    () -> ClientHello.write(out, 0, input, arena.allocate(33), input, null));
            int length = ClientHello.write(out, 0, input, input, input, null);
            out.fill((byte) 0x5a);
            assertThrows(IndexOutOfBoundsException.class,
                    () -> ClientHello.write(out.asSlice(0, length - 1), 0, input, input, input, null));
            for (long i = 0; i < out.byteSize(); i++) {
                assertEquals(0x5a, out.get(ValueLayout.JAVA_BYTE, i));
            }
        }
    }
}
