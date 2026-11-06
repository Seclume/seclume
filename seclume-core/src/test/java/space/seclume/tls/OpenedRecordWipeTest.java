package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.internal.Transport;

/**
 * What a server sends back is often the secret itself - a password from
 * Vault, a data key from a KMS - and the record layer opens it into a buffer
 * of its own before the caller copies it out. That buffer is wiped once the
 * caller has taken everything, before the next record is opened over it (a
 * shorter record would otherwise leave the tail of a longer one), and when the
 * connection closes.
 */
@Timeout(30)
class OpenedRecordWipeTest {

    private static final byte[] SECRET = "s3cr3t-from-the-vault-0123456789-abcdefghijklmnop"
            .repeat(4).getBytes(StandardCharsets.US_ASCII);

    /** Whatever is written is there to be read, in order. */
    private static final class Pipe implements Transport {

        private final ByteArrayOutputStream written = new ByteArrayOutputStream();
        private ByteBuffer readable = ByteBuffer.allocate(0);
        private boolean open = true;

        @Override
        public int read(ByteBuffer into) {
            if (!readable.hasRemaining()) {
                readable = ByteBuffer.wrap(written.toByteArray());
                written.reset();
                if (!readable.hasRemaining()) {
                    return -1;
                }
            }
            int n = Math.min(into.remaining(), readable.remaining());
            into.put(readable.slice().limit(n));
            readable.position(readable.position() + n);
            return n;
        }

        @Override
        public int write(ByteBuffer from) {
            int n = from.remaining();
            byte[] bytes = new byte[n];
            from.get(bytes);
            written.writeBytes(bytes);
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

    /** A writer and a reader under the same traffic secret, sharing one pipe. */
    private record Ends(Pipe pipe, RecordStream writer, RecordStream reader) implements AutoCloseable {

        static Ends open() {
            Pipe pipe = new Pipe();
            RecordStream writer = new RecordStream(pipe);
            RecordStream reader = new RecordStream(pipe);
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment secret = arena.allocate(32);
                for (int i = 0; i < 32; i++) {
                    secret.set(ValueLayout.JAVA_BYTE, i, (byte) (i * 7 + 1));
                }
                writer.writeWith(RecordProtection.fromSecret(HashAlgorithm.SHA_256, secret, 16));
                reader.readWith(RecordProtection.fromSecret(HashAlgorithm.SHA_256, secret, 16));
            }
            writer.established();
            reader.established();
            return new Ends(pipe, writer, reader);
        }

        void send(byte[] plain) throws IOException {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment data = arena.allocate(Math.max(1, plain.length));
                MemorySegment.copy(plain, 0, data, ValueLayout.JAVA_BYTE, 0, plain.length);
                writer.write(RecordProtection.APPLICATION_DATA, data, 0, plain.length);
            }
        }

        @Override
        public void close() {
            writer.close();
            reader.close();
        }
    }

    private static byte[] bytes(MemorySegment segment, long offset, int length) {
        return segment.asSlice(offset, length).toArray(ValueLayout.JAVA_BYTE);
    }

    private static boolean zero(MemorySegment segment, long offset, int length) {
        for (byte b : bytes(segment, offset, length)) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    @Test
    void aShorterRecordDoesNotLeaveTheTailOfTheLongerOneBefore() throws IOException {
        try (Ends ends = Ends.open()) {
            ends.send(SECRET);
            ends.send("ok".getBytes(StandardCharsets.US_ASCII));
            RecordStream.Incoming first = ends.reader().next();
            assertEquals(RecordProtection.APPLICATION_DATA, first.contentType());
            assertArrayEquals(SECRET, bytes(first.data(), first.offset(), first.length()));

            RecordStream.Incoming second = ends.reader().next();
            assertEquals("ok", new String(bytes(second.data(), second.offset(), second.length()),
                    StandardCharsets.US_ASCII));
            assertTrue(zero(second.data(), second.offset() + 2, SECRET.length - 2),
                    "the first record's secret is still behind the second one");
        }
    }

    @Test
    void wipingTheOpenedRecordZeroesAllOfIt() throws IOException {
        try (Ends ends = Ends.open()) {
            ends.send(SECRET);
            RecordStream.Incoming record = ends.reader().next();
            ends.reader().wipeOpened();
            assertTrue(zero(record.data(), record.offset(), SECRET.length));
            ends.reader().wipeOpened();                 // twice is harmless
            assertTrue(zero(record.data(), 0, (int) record.data().byteSize()));
        }
    }

    @Test
    void theConnectionWipesWhatTheCallerHasTakenAndNotBefore() throws IOException {
        try (Ends ends = Ends.open()) {
            // The first record through the stream directly: only to learn which
            // buffer the connection's records are opened into.
            ends.send(new byte[] {1});
            MemorySegment opened = ends.reader().next().data();

            ends.send(SECRET);
            TlsConnection connection = new TlsConnection(ends.pipe(), ends.reader());
            ByteBuffer part = ByteBuffer.allocate(10);
            assertEquals(10, connection.read(part));
            // Still being read: the rest has to be there.
            assertArrayEquals(Arrays.copyOfRange(SECRET, 10, SECRET.length),
                    bytes(opened, 10, SECRET.length - 10));

            ByteBuffer rest = ByteBuffer.allocate(SECRET.length);
            assertEquals(SECRET.length - 10, connection.read(rest));
            byte[] taken = new byte[SECRET.length];
            System.arraycopy(part.array(), 0, taken, 0, 10);
            System.arraycopy(rest.array(), 0, taken, 10, SECRET.length - 10);
            assertArrayEquals(SECRET, taken);
            assertTrue(zero(opened, 0, SECRET.length),
                    "the connection keeps a copy of what the caller has taken");
        }
    }

    @Test
    void aRecordThatDoesNotAuthenticateLeavesNoPlaintext() throws IOException {
        try (Ends ends = Ends.open()) {
            ends.send(new byte[] {1});
            MemorySegment opened = ends.reader().next().data();
            ends.send(SECRET);
            // The tag's last byte, flipped: the ciphertext itself is genuine and
            // decrypts to the secret, which must not stay behind the refusal.
            byte[] sealed = ends.pipe().written.toByteArray();
            sealed[sealed.length - 1] ^= 1;
            ends.pipe().written.reset();
            ends.pipe().written.writeBytes(sealed);
            TlsProtocolException refused = assertThrows(TlsProtocolException.class,
                    ends.reader()::next);
            assertEquals(TlsAlertException.BAD_RECORD_MAC, refused.alert());
            assertTrue(zero(opened, 0, SECRET.length));
        }
    }
}
