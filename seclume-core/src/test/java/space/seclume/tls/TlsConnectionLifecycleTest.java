package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.internal.Transport;

/**
 * An established connection from its first write to its close, over a
 * transport that keeps what is written and a peer that holds the same keys:
 * what a write returns, the close_notify a close sends and a discard does
 * not, and the keys freed by either.
 *
 * <p>The handshake tests close every connection they open, and none looked
 * at what the close did. PIT let those faults survive on a fast runner.
 */
@Timeout(30)
class TlsConnectionLifecycleTest {

    /** Keeps what the connection writes; has nothing to read. */
    private static final class Wire implements Transport {
        private final ByteArrayOutputStream written = new ByteArrayOutputStream();
        private boolean open = true;

        @Override
        public int read(ByteBuffer into) {
            return -1;
        }

        @Override
        public int write(ByteBuffer from) {
            int n = from.remaining();
            byte[] b = new byte[n];
            from.get(b);
            written.writeBytes(b);
            return n;
        }

        @Override
        public boolean isOpen() {
            return open;
        }

        @Override
        public void close() {
            open = false;
        }
    }

    private record Opened(int type, byte[] content) {
    }

    private static RecordProtection keys(int seed) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = arena.allocate(32);
            for (int i = 0; i < 32; i++) {
                secret.set(ValueLayout.JAVA_BYTE, i, (byte) (i * seed + 1));
            }
            return RecordProtection.fromSecret(HashAlgorithm.SHA_256, secret, 16);
        }
    }

    private static boolean closed(RecordProtection p) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(RecordProtection.HEADER + 1 + 16 + 1);
            p.seal(RecordProtection.APPLICATION_DATA, out, 0, 1, out, 0);
            return false;
        } catch (IllegalStateException freed) {
            return true;
        }
    }

    /** Every record on the wire, opened with the peer's copy of the write keys. */
    private static List<Opened> records(byte[] wire, RecordProtection peer) {
        List<Opened> found = new ArrayList<>();
        try (Arena arena = Arena.ofConfined()) {
            int at = 0;
            while (at + RecordProtection.HEADER <= wire.length) {
                int length = ((wire[at + 3] & 0xff) << 8) | (wire[at + 4] & 0xff);
                MemorySegment record = arena.allocate(RecordProtection.HEADER + length);
                MemorySegment.copy(wire, at, record, ValueLayout.JAVA_BYTE, 0, RecordProtection.HEADER + length);
                MemorySegment out = arena.allocate(length);
                RecordProtection.Opened opened = peer.open(record, 0, RecordProtection.HEADER + length, out, 0);
                assertNotNull(opened, "a record the peer cannot open");
                found.add(new Opened(opened.contentType(),
                        out.asSlice(0, opened.length()).toArray(ValueLayout.JAVA_BYTE)));
                at += RecordProtection.HEADER + length;
            }
            assertEquals(wire.length, at, "whole records");
        }
        return found;
    }

    private static final class Ends implements AutoCloseable {
        final Wire wire = new Wire();
        final RecordProtection reading = keys(3);
        final RecordProtection writing = keys(5);
        final RecordProtection peer = keys(5);
        final TlsConnection connection;

        Ends() {
            RecordStream records = new RecordStream(wire);
            records.readWith(reading);
            records.writeWith(writing);
            records.established();
            connection = new TlsConnection(wire, records);
        }

        @Override
        public void close() {
            connection.close();
            peer.close();
        }
    }

    @Test
    void aWriteReturnsAllItTookInRecordsOfAtMost16KiB() throws IOException {
        try (Ends ends = new Ends()) {
            byte[] data = new byte[20_000];
            for (int i = 0; i < data.length; i++) {
                data[i] = (byte) (i * 13);
            }
            assertEquals(data.length, ends.connection.write(ByteBuffer.wrap(data)));

            List<Opened> sent = records(ends.wire.written.toByteArray(), ends.peer);
            assertEquals(2, sent.size());
            assertEquals(16384, sent.get(0).content().length);
            ByteArrayOutputStream joined = new ByteArrayOutputStream();
            for (Opened o : sent) {
                assertEquals(RecordProtection.APPLICATION_DATA, o.type());
                joined.writeBytes(o.content());
            }
            assertArrayEquals(data, joined.toByteArray());
        }
    }

    @Test
    void closeSaysGoodbyeClosesTheSocketAndFreesTheKeys() {
        try (Ends ends = new Ends()) {
            assertTrue(ends.connection.isOpen());
            ends.connection.close();

            assertFalse(ends.connection.isOpen());
            assertFalse(ends.wire.isOpen(), "the socket was left open");
            List<Opened> sent = records(ends.wire.written.toByteArray(), ends.peer);
            assertEquals(1, sent.size(), "one close_notify");
            assertEquals(21, sent.get(0).type());
            assertArrayEquals(new byte[] {TlsAlertException.WARNING, TlsAlertException.CLOSE_NOTIFY},
                    sent.get(0).content());
            assertTrue(closed(ends.reading), "the read keys outlived the connection");
            assertTrue(closed(ends.writing), "the write keys outlived the connection");
            assertThrows(IOException.class, () -> ends.connection.write(ByteBuffer.wrap(new byte[1])));
        }
    }

    @Test
    void aCloseLetsGoOfItsLocks() throws Exception {
        // Another thread that writes after the close is told it is closed -
        // at once, not after waiting on a lock the closing thread kept.
        try (Ends ends = new Ends()) {
            ends.connection.close();
            java.util.concurrent.ExecutorService other = java.util.concurrent.Executors.newSingleThreadExecutor();
            try {
                java.util.concurrent.Future<Object> late = other.submit(() -> {
                    try {
                        return ends.connection.write(ByteBuffer.wrap(new byte[1]));
                    } catch (IOException expected) {
                        return expected;
                    }
                });
                Object result = late.get(10, java.util.concurrent.TimeUnit.SECONDS);
                assertTrue(result instanceof IOException, String.valueOf(result));
            } finally {
                other.shutdownNow();
            }
        }
    }

    @Test
    void discardFreesTheKeysAndLeavesTheSocketAlone() {
        try (Ends ends = new Ends()) {
            ends.connection.discard();

            assertFalse(ends.connection.isOpen());
            assertTrue(ends.wire.isOpen(), "the socket is the successor's");
            assertEquals(0, ends.wire.written.size(), "no goodbye to a peer that is gone");
            assertTrue(closed(ends.reading));
            assertTrue(closed(ends.writing));
        }
    }

    @Test
    void aSocketClosedUnderneathIsNotOpen() {
        try (Ends ends = new Ends()) {
            ends.wire.close();
            assertFalse(ends.connection.isOpen());
        }
    }
}
