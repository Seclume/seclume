package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Every shape a server's second flight can arrive in: several messages packed
 * into one record, one message split across several records, and the two
 * mixed - a complete message followed by the start of the next, whose rest
 * arrives later. {@link Handshake#messages} alone cannot tell "no more
 * messages here" from "the next one is still in flight"; this is the piece in
 * front of it that can.
 */
class HandshakeReassemblerTest {

    private record Seen(int type, byte[] body) {
    }

    /** One handshake message, header and all: type, three-byte length, body. */
    private static MemorySegment message(Arena arena, int type, byte[] body) {
        MemorySegment out = arena.allocate(Handshake.HEADER + body.length);
        out.set(ValueLayout.JAVA_BYTE, 0, (byte) type);
        out.set(ValueLayout.JAVA_BYTE, 1, (byte) (body.length >>> 16));
        out.set(ValueLayout.JAVA_BYTE, 2, (byte) (body.length >>> 8));
        out.set(ValueLayout.JAVA_BYTE, 3, (byte) body.length);
        MemorySegment.copy(body, 0, out, ValueLayout.JAVA_BYTE, Handshake.HEADER, body.length);
        return out;
    }

    private static byte[] body(int length, int seed) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) (seed + i);
        }
        return out;
    }

    private static List<Seen> drain(HandshakeReassembler r) {
        List<Seen> seen = new ArrayList<>();
        r.drain((type, at, len) -> seen.add(new Seen(type,
                r.segment().asSlice(at, len).toArray(ValueLayout.JAVA_BYTE))));
        return seen;
    }

    @Test
    void oneCompleteMessageInOneAppend() {
        try (Arena arena = Arena.ofConfined(); HandshakeReassembler r = new HandshakeReassembler(4096)) {
            byte[] body = body(10, 1);
            MemorySegment msg = message(arena, Handshake.ENCRYPTED_EXTENSIONS, body);
            r.append(msg, 0, (int) msg.byteSize());

            List<Seen> seen = drain(r);
            assertEquals(1, seen.size());
            assertEquals(Handshake.ENCRYPTED_EXTENSIONS, seen.get(0).type());
            assertArrayEquals(body, seen.get(0).body());
            assertEquals(0, r.buffered(), "the complete message was consumed");
        }
    }

    @Test
    void twoMessagesInOneAppendBothCome() {
        try (Arena arena = Arena.ofConfined(); HandshakeReassembler r = new HandshakeReassembler(4096)) {
            byte[] a = body(3, 10);
            byte[] b = body(5, 20);
            MemorySegment m1 = message(arena, Handshake.CERTIFICATE, a);
            MemorySegment m2 = message(arena, Handshake.CERTIFICATE_VERIFY, b);
            r.append(m1, 0, (int) m1.byteSize());
            r.append(m2, 0, (int) m2.byteSize());

            List<Seen> seen = drain(r);
            assertEquals(2, seen.size());
            assertEquals(Handshake.CERTIFICATE, seen.get(0).type());
            assertArrayEquals(a, seen.get(0).body());
            assertEquals(Handshake.CERTIFICATE_VERIFY, seen.get(1).type());
            assertArrayEquals(b, seen.get(1).body());
        }
    }

    @Test
    void aMessageSplitAcrossManySmallAppendsStillComesOutWhole() {
        try (Arena arena = Arena.ofConfined(); HandshakeReassembler r = new HandshakeReassembler(4096)) {
            byte[] body = body(97, 5);
            MemorySegment msg = message(arena, Handshake.FINISHED, body);
            int total = (int) msg.byteSize();

            for (int at = 0; at < total; at += 3) {
                int chunk = Math.min(3, total - at);
                r.append(msg, at, chunk);
                if (at + chunk < total) {
                    assertTrue(drain(r).isEmpty(), "nothing complete before the last byte arrives");
                }
            }
            List<Seen> seen = drain(r);
            assertEquals(1, seen.size());
            assertEquals(Handshake.FINISHED, seen.get(0).type());
            assertArrayEquals(body, seen.get(0).body());
        }
    }

    @Test
    void aCompleteMessageFollowedByThePartialStartOfTheNext() {
        try (Arena arena = Arena.ofConfined(); HandshakeReassembler r = new HandshakeReassembler(4096)) {
            byte[] a = body(4, 1);
            byte[] b = body(6, 100);
            MemorySegment m1 = message(arena, Handshake.SERVER_HELLO, a);
            MemorySegment m2 = message(arena, Handshake.NEW_SESSION_TICKET, b);
            int m2Total = (int) m2.byteSize();
            int firstPart = 2; // less than the header - the header itself is split

            MemorySegment combined = arena.allocate(m1.byteSize() + firstPart);
            MemorySegment.copy(m1, 0, combined, 0, m1.byteSize());
            MemorySegment.copy(m2, 0, combined, m1.byteSize(), firstPart);
            r.append(combined, 0, (int) combined.byteSize());

            List<Seen> firstDrain = drain(r);
            assertEquals(1, firstDrain.size(), "only the complete first message comes out");
            assertEquals(Handshake.SERVER_HELLO, firstDrain.get(0).type());
            assertArrayEquals(a, firstDrain.get(0).body());
            assertEquals(firstPart, r.buffered(), "the partial header stays buffered");

            r.append(m2, firstPart, m2Total - firstPart);
            List<Seen> secondDrain = drain(r);
            assertEquals(1, secondDrain.size());
            assertEquals(Handshake.NEW_SESSION_TICKET, secondDrain.get(0).type());
            assertArrayEquals(b, secondDrain.get(0).body());
            assertEquals(0, r.buffered());
        }
    }

    @Test
    void drainingTwiceWithNothingNewIsHarmless() {
        try (HandshakeReassembler r = new HandshakeReassembler(4096)) {
            assertTrue(drain(r).isEmpty());
            assertTrue(drain(r).isEmpty());
            assertEquals(0, r.buffered());
        }
    }

    @Test
    void aMessageBiggerThanTheCapIsRefusedNotBufferedWithoutLimit() {
        try (Arena arena = Arena.ofConfined(); HandshakeReassembler r = new HandshakeReassembler(64)) {
            MemorySegment msg = message(arena, Handshake.CERTIFICATE, body(200, 0));
            assertThrows(IllegalStateException.class,
                    () -> r.append(msg, 0, (int) msg.byteSize()));
        }
    }

    @Test
    void manySmallAppendsThatEventuallyExceedTheCapAreRefused() {
        try (Arena arena = Arena.ofConfined(); HandshakeReassembler r = new HandshakeReassembler(32)) {
            MemorySegment chunk = arena.allocate(10);
            r.append(chunk, 0, 10);
            r.append(chunk, 0, 10);
            r.append(chunk, 0, 10);
            assertThrows(IllegalStateException.class, () -> r.append(chunk, 0, 10));
        }
    }
}
