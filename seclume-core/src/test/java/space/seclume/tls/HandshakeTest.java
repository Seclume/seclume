package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The parts of the handshake framing that the RFC 8448 vectors cannot reach.
 *
 * <p>This class exists because a negative control failed to fail.
 * {@code Rfc8448VectorsTest} checks forty messages encoded by another
 * implementation, which is the stronger kind of test - but changing
 * {@link Handshake#length} to read two bytes instead of three left all 232 of
 * those tests green. The reason is not subtle once seen: the longest message in
 * any of the five traces is 657 bytes, so the top byte of every length is zero
 * and a parser that ignores it gives the right answer every time.
 *
 * <p>That is the whole value of running the control. The vectors are still the
 * better evidence for everything they cover; what is here is the handful of
 * cases they provably cannot cover - a length that needs its third byte, a
 * walk that must stop rather than run off the end, an extension whose length
 * lies. Each of these is checked against the encoding as specified, which is
 * weaker evidence, and is used only where nothing stronger exists.
 */
class HandshakeTest {

    /**
     * The message length is twenty-four bits, and the top eight matter.
     *
     * <p>A Certificate message with a large chain passes 65535 bytes easily,
     * and a parser that reads two bytes then reports a message 65536 bytes
     * shorter than it is. Everything after it in the record is misread as a new
     * message, and the failure surfaces as a protocol error nowhere near the
     * cause.
     */
    @ParameterizedTest
    @ValueSource(ints = {0, 1, 255, 256, 65535, 65536, 70000, 0x00ffffff})
    void theLengthIsThreeBytes(int length) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment data = arena.allocate(Handshake.HEADER);
            data.set(ValueLayout.JAVA_BYTE, 0, (byte) Handshake.CERTIFICATE);
            data.set(ValueLayout.JAVA_BYTE, 1, (byte) (length >>> 16));
            data.set(ValueLayout.JAVA_BYTE, 2, (byte) (length >>> 8));
            data.set(ValueLayout.JAVA_BYTE, 3, (byte) length);
            assertEquals(length, Handshake.length(data, 0));
            assertEquals(Handshake.HEADER + length, Handshake.totalLength(data, 0));
        }
    }

    /** Several messages in one range, which is how a flight arrives. */
    @Test
    void aFlightOfMessagesIsWalked() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment data = arena.allocate(4 + 2 + 4 + 0 + 4 + 5);
            writeMessage(data, 0, Handshake.ENCRYPTED_EXTENSIONS, 2);
            writeMessage(data, 6, Handshake.CERTIFICATE_VERIFY, 0);
            writeMessage(data, 10, Handshake.FINISHED, 5);

            List<String> seen = new ArrayList<>();
            Handshake.messages(data, 0, (int) data.byteSize(),
                    (type, at, length) -> seen.add(type + "/" + length));
            assertEquals(List.of("8/2", "15/0", "20/5"), seen);
        }
    }

    /**
     * A message cut off by the end of the range is not delivered.
     *
     * <p>Records are 16 kB at most, so a Certificate is regularly split across
     * several of them. Handing the first half to a reader as though it were
     * whole is how a parser invents a certificate.
     */
    @Test
    void aTruncatedMessageIsNotHandedOver() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment data = arena.allocate(10);
            writeMessage(data, 0, Handshake.CERTIFICATE, 100);   // claims 100, has 6
            Handshake.messages(data, 0, 10,
                    (type, at, length) -> fail("a truncated message was delivered"));
        }
    }

    /** And a range too short even for a header ends the walk quietly. */
    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3})
    void aRangeShorterThanAHeaderYieldsNothing(int length) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment data = arena.allocate(4);
            Handshake.messages(data, 0, length,
                    (type, at, l) -> fail("a message appeared in " + length + " bytes"));
        }
    }

    /** Extensions of length zero are legal and must still be reported. */
    @Test
    void anEmptyExtensionIsStillAnExtension() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment data = arena.allocate(4 + 4 + 2);
            writeExtension(data, 0, Handshake.EXTENSION_SUPPORTED_VERSIONS, 2);
            writeExtension(data, 6, Handshake.EXTENSION_PRE_SHARED_KEY, 0);

            List<String> seen = new ArrayList<>();
            Handshake.extensions(data, 0, (int) data.byteSize(),
                    (type, at, length) -> seen.add(type + "/" + length));
            assertEquals(List.of("43/2", "41/0"), seen);
        }
    }

    /**
     * An extension that claims more than is there stops the walk.
     *
     * <p>Under a timeout because the failure being guarded against is a walk
     * that never advances, and a test for an endless loop that hangs the build
     * has not improved anything.
     */
    @Test
    void anExtensionThatOverrunsStopsTheWalk() {
        Assertions.assertTimeoutPreemptively(Duration.ofSeconds(2), () -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment data = arena.allocate(8);
                writeExtension(data, 0, Handshake.EXTENSION_KEY_SHARE, 200);
                int[] calls = {0};
                Handshake.extensions(data, 0, 8, (type, at, length) -> calls[0]++);
                assertEquals(0, calls[0], "an overrunning extension was handed over");
            }
        });
    }

    // ---- the small machinery ---------------------------------------------

    private static void writeMessage(MemorySegment data, long at, int type, int length) {
        data.set(ValueLayout.JAVA_BYTE, at, (byte) type);
        data.set(ValueLayout.JAVA_BYTE, at + 1, (byte) (length >>> 16));
        data.set(ValueLayout.JAVA_BYTE, at + 2, (byte) (length >>> 8));
        data.set(ValueLayout.JAVA_BYTE, at + 3, (byte) length);
    }

    private static void writeExtension(MemorySegment data, long at, int type, int length) {
        data.set(ValueLayout.JAVA_BYTE, at, (byte) (type >>> 8));
        data.set(ValueLayout.JAVA_BYTE, at + 1, (byte) type);
        data.set(ValueLayout.JAVA_BYTE, at + 2, (byte) (length >>> 8));
        data.set(ValueLayout.JAVA_BYTE, at + 3, (byte) length);
    }
}
