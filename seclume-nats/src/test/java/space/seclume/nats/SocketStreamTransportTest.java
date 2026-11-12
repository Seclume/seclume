package space.seclume.nats;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Without TLS the CONNECT line, the password in it, goes from native memory
 * to the socket's stream - which takes an array. Found in the review of
 * 12.11.2026: the array made for that was left as it was, the password in it
 * on the heap until something else was written over it. It is wiped once the
 * stream has it.
 */
class SocketStreamTransportTest {

    /** Keeps every array it was given, as a stream may not - to look at them afterwards. */
    private static final class Remembering extends OutputStream {
        final List<byte[]> given = new ArrayList<>();
        final ByteArrayOutputStream wire = new ByteArrayOutputStream();

        @Override
        public void write(int b) {
            wire.write(b);
        }

        @Override
        public void write(byte[] bytes, int off, int len) {
            given.add(bytes);
            wire.write(bytes, off, len);
        }
    }

    @Test
    void theArrayMadeForNativeBytesIsWipedOnceTheyAreWritten() throws Exception {
        byte[] line = "CONNECT {\"user\":\"orders\",\"pass\":\"a-password-of-the-test\"}\r\n"
                .getBytes(StandardCharsets.US_ASCII);
        Remembering out = new Remembering();
        try (Arena arena = Arena.ofConfined(); Socket socket = new Socket()) {
            MemorySegment offHeap = arena.allocate(line.length);
            MemorySegment.copy(line, 0, offHeap, ValueLayout.JAVA_BYTE, 0, line.length);
            SocketStreamTransport transport = new SocketStreamTransport(socket,
                    new ByteArrayInputStream(new byte[0]), out);
            assertEquals(line.length, transport.write(offHeap.asByteBuffer()));
        }
        assertArrayEquals(line, out.wire.toByteArray(), "what went to the socket");
        for (byte[] given : out.given) {
            assertArrayEquals(new byte[given.length], given, "an array with the line in it was left");
        }
    }

    @Test
    void anArrayOfTheCallersIsWrittenAsItIsAndLeftToTheCaller() throws Exception {
        byte[] ciphertext = {1, 2, 3, 4};
        Remembering out = new Remembering();
        try (Socket socket = new Socket()) {
            new SocketStreamTransport(socket, new ByteArrayInputStream(new byte[0]), out)
                    .write(java.nio.ByteBuffer.wrap(ciphertext));
        }
        assertArrayEquals(new byte[] {1, 2, 3, 4}, ciphertext);
        assertArrayEquals(ciphertext, out.wire.toByteArray());
    }
}
