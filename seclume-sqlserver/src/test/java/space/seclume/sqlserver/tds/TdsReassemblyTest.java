package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.internal.Transport;

class TdsReassemblyTest {

    @ParameterizedTest
    @ValueSource(ints = {1, 7, 8, 9, 31, 4096, 32768, Integer.MAX_VALUE})
    void reassemblesAcrossReadAndPacketBoundaries(int readSize) throws Exception {
        byte[] expected = payload(100_003);
        try (Feed feed = new Feed(frame(expected, 997), readSize);
                TdsChannel channel = TdsChannel.over(feed)) {
            assertEquals(Tds.TYPE_TABULAR_RESULT, channel.receive());
            assertArrayEquals(expected, channel.message().slice(0, channel.messageLength())
                    .toArray(ValueLayout.JAVA_BYTE));
        }
    }

    @Test
    void acceptsTheLargestRepresentablePacket() throws Exception {
        byte[] expected = payload(65535 - Tds.HEADER_SIZE);
        try (Feed feed = new Feed(frame(expected, expected.length), 1000);
                TdsChannel channel = TdsChannel.over(feed)) {
            channel.receive();
            assertArrayEquals(expected, channel.message().slice(0, channel.messageLength())
                    .toArray(ValueLayout.JAVA_BYTE));
        }
    }

    @Test
    void readAheadDoesNotScaleWithRetainedMessageCapacity() throws Exception {
        byte[] expected = payload(16_384);
        try (Feed feed = new Feed(frame(expected, 1), Integer.MAX_VALUE);
                TdsChannel channel = TdsChannel.over(feed)) {
            channel.message().ensureCapacity(1024 * 1024);
            channel.receive();
            assertArrayEquals(expected, channel.message().slice(0, channel.messageLength())
                    .toArray(ValueLayout.JAVA_BYTE));
            assertTrue(feed.largestRead <= 65536,
                    "read-ahead grew with the result buffer: " + feed.largestRead);
        }
    }

    @Test
    void preservesTheNextMessageWhenBothArriveTogether() throws Exception {
        byte[] first = payload(71);
        byte[] second = payload(113);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        bytes.writeBytes(frame(first, 11));
        bytes.writeBytes(frame(second, 13));
        try (Feed feed = new Feed(bytes.toByteArray(), Integer.MAX_VALUE);
                TdsChannel channel = TdsChannel.over(feed)) {
            channel.receive();
            assertArrayEquals(first, channel.message().slice(0, channel.messageLength())
                    .toArray(ValueLayout.JAVA_BYTE));
            channel.receive();
            assertArrayEquals(second, channel.message().slice(0, channel.messageLength())
                    .toArray(ValueLayout.JAVA_BYTE));
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 17, 32768, Integer.MAX_VALUE})
    void streamingRetainsPartialTokensAcrossPauses(int readSize) throws Exception {
        byte[] expected = payload(12_003);
        ByteArrayOutputStream received = new ByteArrayOutputStream();
        try (Feed feed = new Feed(frame(expected, 101), readSize);
                TdsChannel channel = TdsChannel.over(feed)) {
            channel.startStreaming();
            boolean done;
            int pauses = 0;
            do {
                done = channel.pump((in, end) -> {
                    int used = end - end % 3;
                    received.writeBytes(in.slice(0, used).toArray(ValueLayout.JAVA_BYTE));
                    return used;
                }, () -> true);
                if (!done) {
                    pauses++;
                }
            } while (!done);
            assertTrue(pauses > 1);
            assertArrayEquals(expected, received.toByteArray());
            assertEquals(0, channel.messageLength());
        }
    }

    @Test
    void streamingReadAheadAlsoStaysBounded() throws Exception {
        byte[] expected = payload(16_384);
        ByteArrayOutputStream received = new ByteArrayOutputStream();
        try (Feed feed = new Feed(frame(expected, 1), Integer.MAX_VALUE);
                TdsChannel channel = TdsChannel.over(feed)) {
            channel.message().ensureCapacity(1024 * 1024);
            channel.receiveStreaming((in, end) -> {
                received.writeBytes(in.slice(0, end).toArray(ValueLayout.JAVA_BYTE));
                return end;
            });
            assertArrayEquals(expected, received.toByteArray());
            assertTrue(feed.largestRead <= 65536,
                    "read-ahead grew with the result buffer: " + feed.largestRead);
        }
    }

    @Test
    void streamingCanGrowAnUnfinishedTokenAcrossManyPackets() throws Exception {
        byte[] expected = payload(200_003);
        ByteArrayOutputStream received = new ByteArrayOutputStream();
        try (Feed feed = new Feed(frame(expected, 7919), Integer.MAX_VALUE);
                TdsChannel channel = TdsChannel.over(feed)) {
            channel.receiveStreaming((in, end) -> {
                if (end < expected.length) {
                    return 0;
                }
                received.writeBytes(in.slice(0, end).toArray(ValueLayout.JAVA_BYTE));
                return end;
            });
            assertArrayEquals(expected, received.toByteArray());
        }
    }

    @Test
    void consumedPacketBytesAreWipedBeforePausing() throws Exception {
        byte[] expected = payload(22);
        try (Feed feed = new Feed(frame(expected, 11), Integer.MAX_VALUE);
                TdsChannel channel = TdsChannel.over(feed)) {
            channel.startStreaming();
            assertFalse(channel.pump((in, end) -> end, () -> true));
            for (int i = 0; i < Tds.HEADER_SIZE + 11; i++) {
                assertEquals(0, feed.lastReadView.get(i), "consumed packet byte " + i);
            }
            assertTrue(channel.pump((in, end) -> {
                assertArrayEquals(Arrays.copyOfRange(expected, 11, 22),
                        in.slice(0, end).toArray(ValueLayout.JAVA_BYTE));
                return end;
            }, () -> true));
            for (int i = 0; i < feed.lastReadView.limit(); i++) {
                assertEquals(0, feed.lastReadView.get(i), "packet storage byte " + i);
            }
        }
    }

    @Test
    void closeReleasesThePacketStorage() throws Exception {
        ByteBuffer packetView;
        try (Feed feed = new Feed(frame(payload(11), 11), Integer.MAX_VALUE);
                TdsChannel channel = TdsChannel.over(feed)) {
            channel.receive();
            packetView = feed.lastReadView;
        }
        assertThrows(IllegalStateException.class, () -> packetView.get(0));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 3})
    void rejectsConsumerOffsetsOutsideTheMessage(int used) {
        try (Feed feed = new Feed(frame(payload(2), 1), Integer.MAX_VALUE);
                TdsChannel channel = TdsChannel.over(feed)) {
            assertThrows(IOException.class, () -> channel.receiveStreaming((in, end) -> used));
        }
    }

    @Test
    void rejectsTruncatedPacketsAndShortHeaders() {
        byte[] packet = frame(payload(11), 11);
        for (int end : new int[] {0, 1, 7, 8, packet.length - 1}) {
            try (Feed feed = new Feed(Arrays.copyOf(packet, end), 3);
                    TdsChannel channel = TdsChannel.over(feed)) {
                assertThrows(IOException.class, channel::receive);
            }
        }
        packet[3] = 7;
        try (Feed feed = new Feed(packet, Integer.MAX_VALUE);
                TdsChannel channel = TdsChannel.over(feed)) {
            assertThrows(IOException.class, channel::receive);
        }
    }

    @Test
    void incompleteFinalTokenIsRefused() {
        try (Feed feed = new Feed(frame(payload(2), 1), Integer.MAX_VALUE);
                TdsChannel channel = TdsChannel.over(feed)) {
            assertThrows(IOException.class, () -> channel.receiveStreaming((in, end) -> 0));
        }
    }

    @Test
    void emptyPacketsAndEmptyMessagesAreAllowed() throws Exception {
        byte[] empty = frame(new byte[0], 1);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] continuation = empty.clone();
        continuation[1] = 0;
        bytes.writeBytes(continuation);
        bytes.writeBytes(empty);
        try (Feed feed = new Feed(bytes.toByteArray(), Integer.MAX_VALUE);
                TdsChannel channel = TdsChannel.over(feed)) {
            channel.startStreaming();
            assertFalse(channel.pump((in, end) -> end, () -> true));
            assertTrue(channel.pump((in, end) -> end, () -> true));
            assertEquals(0, channel.messageLength());
        }
    }

    // An opt-in comparison, not a timing threshold in CI. Reuse a large result
    // buffer to model a connection that previously read a large answer.
    @Test
    @EnabledIfSystemProperty(named = "seclume.tds.probe", matches = "true")
    void measureCoalescedTinyPackets() throws Exception {
        for (boolean streaming : new boolean[] {false, true}) {
            for (int count : new int[] {8192, 16384, 32768}) {
                byte[] bytes = frame(payload(count), 1);
                long[] nanos = new long[5];
                for (int round = -2; round < nanos.length; round++) {
                    try (Feed feed = new Feed(bytes, Integer.MAX_VALUE);
                            TdsChannel channel = TdsChannel.over(feed)) {
                        channel.message().ensureCapacity(1024 * 1024);
                        long start = System.nanoTime();
                        if (streaming) {
                            channel.receiveStreaming((in, end) -> end);
                        } else {
                            channel.receive();
                            assertEquals(count, channel.messageLength());
                        }
                        long elapsed = System.nanoTime() - start;
                        if (round >= 0) {
                            nanos[round] = elapsed;
                        }
                    }
                }
                Arrays.sort(nanos);
                System.out.printf("TDS probe streaming=%s packets=%d median_ms=%.3f%n",
                        streaming, count, nanos[nanos.length / 2] / 1_000_000.0);
            }
        }
    }

    private static byte[] payload(int length) {
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            result[i] = (byte) (i * 31 + 7);
        }
        return result;
    }

    private static byte[] frame(byte[] payload, int payloadPerPacket) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int offset = 0;
        do {
            int count = Math.min(payloadPerPacket, payload.length - offset);
            bytes.write(Tds.TYPE_TABULAR_RESULT);
            bytes.write(offset + count == payload.length ? Tds.STATUS_END_OF_MESSAGE : 0);
            bytes.write((count + Tds.HEADER_SIZE) >>> 8);
            bytes.write(count + Tds.HEADER_SIZE);
            bytes.write(0);
            bytes.write(0);
            bytes.write(1);
            bytes.write(0);
            bytes.write(payload, offset, count);
            offset += count;
        } while (offset < payload.length);
        return bytes.toByteArray();
    }

    private static final class Feed implements Transport {
        private final ByteBuffer source;
        private final int readSize;
        private int largestRead;
        private ByteBuffer lastReadView;
        private boolean open = true;

        Feed(byte[] bytes, int readSize) {
            source = ByteBuffer.wrap(bytes);
            this.readSize = readSize;
        }

        @Override
        public int read(ByteBuffer into) {
            largestRead = Math.max(largestRead, into.remaining());
            if (!source.hasRemaining()) {
                return -1;
            }
            int count = Math.min(Math.min(readSize, into.remaining()), source.remaining());
            into.put(source.slice(source.position(), count));
            source.position(source.position() + count);
            lastReadView = into.duplicate().flip();
            return count;
        }

        @Override
        public int write(ByteBuffer from) {
            throw new AssertionError("unexpected write");
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
}
