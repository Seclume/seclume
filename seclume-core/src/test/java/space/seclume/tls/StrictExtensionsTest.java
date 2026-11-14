package space.seclume.tls;

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
 * An extension block read strictly, without a server: each way a length can
 * lie earns its own decode_error and says which. The messages differ on
 * purpose - a test that only checks the alert cannot tell one check from the
 * other, and PIT showed (as faults the socket tests timed out on a slow
 * runner and let survive on a fast one) that nothing else did.
 *
 * <p>The block starts at offset 5 of a segment that ends where it does.
 */
class StrictExtensionsTest {

    private static final int AT = 5;

    private record Seen(int type, long at, int length) {
    }

    private static MemorySegment placed(Arena arena, int... bytes) {
        MemorySegment s = arena.allocate(AT + bytes.length);
        s.fill((byte) 0xEE);
        for (int i = 0; i < bytes.length; i++) {
            s.set(ValueLayout.JAVA_BYTE, AT + i, (byte) bytes[i]);
        }
        return s;
    }

    private static TlsProtocolException listRefused(int... bytes) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment s = placed(arena, bytes);
            return assertThrows(TlsProtocolException.class,
                    () -> StrictExtensions.list(s, AT, bytes.length, "the message", (t, a, l) -> { }));
        }
    }

    @Test
    void everyExtensionIsVisitedWhereItIs() throws TlsProtocolException {
        List<Seen> seen = new ArrayList<>();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment s = placed(arena, 0, 10, 0, 0x2b, 0, 2, 3, 4, 0, 0x10, 0, 0);
            StrictExtensions.list(s, AT, 12, "the message", (t, a, l) -> seen.add(new Seen(t, a, l)));
        }
        assertEquals(List.of(new Seen(0x2b, AT + 2 + 4, 2), new Seen(0x10, AT + 2 + 4 + 2 + 4, 0)), seen);
    }

    @Test
    void aBlockLengthThatIsNotTheRestSaysBoth() {
        TlsProtocolException e = listRefused(0, 3, 0, 1, 0, 0);
        assertEquals(TlsAlertException.DECODE_ERROR, e.alert());
        assertTrue(e.getMessage().contains("says its extensions are 3 bytes and has 4"), e.getMessage());
    }

    @Test
    void threeBytesLeftAreATruncatedExtension() {
        TlsProtocolException e = listRefused(0, 7, 0, 1, 0, 0, 0, 2, 0);
        assertEquals(TlsAlertException.DECODE_ERROR, e.alert());
        assertTrue(e.getMessage().contains("has a truncated extension"), e.getMessage());
    }

    @Test
    void anExtensionOneByteLongerThanItsBlockSaysSo() {
        // Type 1, said to be three bytes long, two there.
        TlsProtocolException e = listRefused(0, 6, 0, 1, 0, 3, 9, 9);
        assertEquals(TlsAlertException.DECODE_ERROR, e.alert());
        assertTrue(e.getMessage().contains("has an extension longer than its block"), e.getMessage());
    }

    @Test
    void anExtensionThatFillsItsBlockExactlyIsRead() throws TlsProtocolException {
        List<Seen> seen = new ArrayList<>();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment s = placed(arena, 0, 6, 0, 1, 0, 2, 9, 9);
            StrictExtensions.list(s, AT, 8, "the message", (t, a, l) -> seen.add(new Seen(t, a, l)));
        }
        assertEquals(List.of(new Seen(1, AT + 6, 2)), seen);
    }

    @Test
    void aRepeatedTypeIsAnIllegalParameter() {
        TlsProtocolException e = listRefused(0, 8, 0, 1, 0, 0, 0, 1, 0, 0);
        assertEquals(TlsAlertException.ILLEGAL_PARAMETER, e.alert());
    }

    @Test
    void anEmptyBlockIsTwoBytesOfZeroAndNothingToVisit() throws TlsProtocolException {
        List<Seen> seen = new ArrayList<>();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment s = placed(arena, 0, 0);
            StrictExtensions.list(s, AT, 2, "the message", (t, a, l) -> seen.add(new Seen(t, a, l)));
        }
        assertEquals(List.of(), seen);
    }

    @Test
    void lessThanALengthIsADecodeError() {
        TlsProtocolException e = listRefused(0);
        assertEquals(TlsAlertException.DECODE_ERROR, e.alert());
        assertTrue(e.getMessage().contains("ends before its extensions"), e.getMessage());
    }
}
