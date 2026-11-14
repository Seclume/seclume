package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Deque;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.internal.Transport;

/**
 * The record layer against a transport that is a script: the bytes a test
 * puts in are what the stream reads, the bytes it writes are kept. The
 * limits on a record's length, the version bytes of the first record, the
 * alert {@code abort} sends, a read that returns nothing yet, and which keys
 * are closed when - each checked at its boundary.
 *
 * <p>The handshake tests reach all of this through a socket. PIT timed those
 * faults out on a slow runner and let them survive on a fast one; here each
 * fails at once.
 */
@Timeout(30)
class RecordStreamTest {

    /** Reads what the test queued, a zero-length read where it said so, then the end. */
    private static final class Script implements Transport {
        private final Deque<byte[]> reads = new ArrayDeque<>();
        private final ByteArrayOutputStream written = new ByteArrayOutputStream();
        private byte[] current = new byte[0];
        private int at;

        Script then(byte[] bytes) {
            reads.add(bytes);
            return this;
        }

        /** A read that returns 0: nothing yet, which is not the end. */
        Script nothingYet() {
            reads.add(new byte[0]);
            return this;
        }

        @Override
        public int read(ByteBuffer into) {
            if (at == current.length) {
                if (reads.isEmpty()) {
                    return -1;
                }
                current = reads.poll();
                at = 0;
                if (current.length == 0) {
                    return 0;
                }
            }
            int n = Math.min(into.remaining(), current.length - at);
            into.put(current, at, n);
            at += n;
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

        byte[] written() {
            return written.toByteArray();
        }

        @Override
        public boolean isOpen() {
            return true;
        }

        @Override
        public void close() {
        }
    }

    private static byte[] header(int type, int length) {
        return new byte[] {(byte) type, 3, 3, (byte) (length >>> 8), (byte) length};
    }

    private static byte[] record(int type, int length) {
        byte[] r = new byte[RecordProtection.HEADER + length];
        System.arraycopy(header(type, length), 0, r, 0, RecordProtection.HEADER);
        for (int i = RecordProtection.HEADER; i < r.length; i++) {
            r[i] = (byte) (i * 31 + 7);
        }
        return r;
    }

    private static RecordProtection protection() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = arena.allocate(32);
            for (int i = 0; i < 32; i++) {
                secret.set(ValueLayout.JAVA_BYTE, i, (byte) (i * 5 + 3));
            }
            return RecordProtection.fromSecret(HashAlgorithm.SHA_256, secret, 16);
        }
    }

    /** Whether the keys are gone: sealing with them touches their memory, freed by close. */
    private static boolean closed(RecordProtection p) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(RecordProtection.HEADER + 1 + 16 + 1);
            p.seal(RecordProtection.APPLICATION_DATA, out, 0, 1, out, 0);
            return false;
        } catch (IllegalStateException freed) {
            return true;
        }
    }

    private static TlsProtocolException refused(RecordStream stream) {
        return assertThrows(TlsProtocolException.class, stream::next);
    }

    // --- how long a record may say it is ---

    @Test
    void aPlaintextRecordMayHold16KiBAndNotOneByteMore() throws IOException {
        int most = RecordStream.MAX_PLAINTEXT;
        try (RecordStream s = new RecordStream(new Script().then(record(22, most)))) {
            RecordStream.Incoming in = s.next();
            assertEquals(22, in.contentType());
            assertEquals(most, in.length());
        }
        try (RecordStream s = new RecordStream(new Script().then(record(22, most + 1)))) {
            TlsProtocolException e = refused(s);
            assertEquals(TlsAlertException.RECORD_OVERFLOW, e.alert());
            assertTrue(e.getMessage().contains("announced " + (most + 1) + " bytes"), e.getMessage());
        }
    }

    @Test
    void anEncryptedTls13RecordMayBeLongerButNotByMoreThan256() {
        int most = RecordStream.MAX_CIPHERTEXT;
        try (RecordStream s = new RecordStream(new Script().then(record(23, most + 1)))) {
            s.readWith(protection());
            TlsProtocolException e = refused(s);
            assertEquals(TlsAlertException.RECORD_OVERFLOW, e.alert());
            assertTrue(e.getMessage().contains("announced " + (most + 1) + " bytes"), e.getMessage());
        }
    }

    @Test
    void anEncryptedTls12RecordMayBeLongerStill() {
        // Past the TLS 1.3 limit, within TLS 1.2's: the header is accepted and
        // the record read; what refuses it then is that it does not open.
        int length = RecordStream.MAX_CIPHERTEXT + 1;
        try (RecordStream s = new RecordStream(new Script().then(record(23, length)))) {
            s.tls12();
            assertTrue(s.isTls12());
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment keys = arena.allocate(2 * 16 + 2 * 4);
                s.readWith(RecordProtection.forTls12(HashAlgorithm.SHA_256, keys, 0, 16, 32));
            }
            TlsProtocolException e = refused(s);
            assertFalse(e.getMessage().contains("announced"), e.getMessage());
        }
    }

    @Test
    void innerContentOfExactly16KiBAndOneIsOpenedAndMoreIsTooMuch() {
        // RFC 8446 section 5.4: content, type and padding at most 2^14 + 1.
        int tag = 16;
        try (RecordStream s = new RecordStream(new Script().then(record(23, tag + RecordStream.MAX_PLAINTEXT + 1)))) {
            s.readWith(protection());
            assertEquals(TlsAlertException.BAD_RECORD_MAC, refused(s).alert(),
                    "within the limit: opened, and these bytes do not authenticate");
        }
        try (RecordStream s = new RecordStream(new Script().then(record(23, tag + RecordStream.MAX_PLAINTEXT + 2)))) {
            s.readWith(protection());
            assertEquals(TlsAlertException.RECORD_OVERFLOW, refused(s).alert());
        }
    }

    // --- what an encrypted record may hold ---

    private static RecordStream[] pair() {
        Script wire = new Script();
        RecordStream writer = new RecordStream(new Transport() {
            @Override
            public int read(ByteBuffer into) {
                return -1;
            }

            @Override
            public int write(ByteBuffer from) {
                int n = from.remaining();
                byte[] b = new byte[n];
                from.get(b);
                wire.then(b);
                return n;
            }

            @Override
            public boolean isOpen() {
                return true;
            }

            @Override
            public void close() {
            }
        });
        RecordStream reader = new RecordStream(wire);
        writer.writeWith(protection());
        reader.readWith(protection());
        return new RecordStream[] {writer, reader};
    }

    @Test
    void anEmptyApplicationDataRecordIsAllowedAndAnEmptyHandshakeRecordIsNot() throws IOException {
        RecordStream[] ends = pair();
        try (RecordStream writer = ends[0]; RecordStream reader = ends[1]) {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment none = arena.allocate(1);
                writer.write(RecordProtection.APPLICATION_DATA, none, 0, 0);
                writer.write((byte) 22, none, 0, 0);
            }
            RecordStream.Incoming empty = reader.next();
            assertEquals(RecordProtection.APPLICATION_DATA, empty.contentType());
            assertEquals(0, empty.length());
            TlsProtocolException e = refused(reader);
            assertEquals(TlsAlertException.UNEXPECTED_MESSAGE, e.alert());
            assertTrue(e.getMessage().contains("an empty record of type 22"), e.getMessage());
        }
    }

    @Test
    void tls12AllowsOneChangeCipherSpecAndNotTwo() throws IOException {
        byte[] ccs = {20, 3, 3, 0, 1, 1};
        try (RecordStream s = new RecordStream(new Script().then(ccs).then(ccs))) {
            s.tls12();
            RecordStream.Incoming first = s.next();
            assertEquals(20, first.contentType());
            TlsProtocolException e = refused(s);
            assertEquals(TlsAlertException.UNEXPECTED_MESSAGE, e.alert());
        }
    }

    // --- reading and writing whole records ---

    @Test
    void aReadThatReturnsNothingYetIsNotTheEnd() throws IOException {
        byte[] r = record(22, 4);
        byte[] head = new byte[3];
        byte[] rest = new byte[r.length - 3];
        System.arraycopy(r, 0, head, 0, 3);
        System.arraycopy(r, 3, rest, 0, rest.length);
        try (RecordStream s = new RecordStream(new Script().then(head).nothingYet().then(rest))) {
            assertEquals(4, s.next().length());
        }
    }

    @Test
    void theEndInTheMiddleOfARecordSaysHowMuchCame() {
        byte[] r = record(22, 5);
        byte[] cut = new byte[RecordProtection.HEADER + 2];
        System.arraycopy(r, 0, cut, 0, cut.length);
        try (RecordStream s = new RecordStream(new Script().then(cut))) {
            EOFException e = assertThrows(EOFException.class, s::next);
            assertTrue(e.getMessage().contains("5 bytes were expected, 2 arrived"), e.getMessage());
        }
    }

    @Test
    void theFirstRecordSaysTls10AndEveryLaterOneTls12() throws IOException {
        Script wire = new Script();
        try (RecordStream s = new RecordStream(wire); Arena arena = Arena.ofConfined()) {
            MemorySegment data = arena.allocate(300);
            data.fill((byte) 0x42);
            s.write((byte) 22, data, 0, 300);
            s.write((byte) 22, data, 0, 1);
            byte[] out = wire.written();
            assertArrayEquals(new byte[] {22, 3, 1, 1, 44}, java.util.Arrays.copyOfRange(out, 0, 5));
            assertArrayEquals(new byte[] {22, 3, 3, 0, 1}, java.util.Arrays.copyOfRange(out, 305, 310));
        }
    }

    @Test
    void abortSendsAFatalAlertWithTheReason() {
        Script wire = new Script();
        try (RecordStream s = new RecordStream(wire)) {
            s.abort(TlsAlertException.DECODE_ERROR);
            assertArrayEquals(new byte[] {21, 3, 1, 0, 2, 2, 50}, wire.written());
        }
    }

    // --- keys, closed when they are done with ---

    @Test
    void newKeysCloseTheOldOnes() {
        try (RecordStream s = new RecordStream(new Script())) {
            RecordProtection oldRead = protection();
            RecordProtection oldWrite = protection();
            s.readWith(oldRead);
            s.writeWith(oldWrite);
            assertFalse(closed(oldRead));
            RecordProtection newRead = protection();
            RecordProtection newWrite = protection();
            s.readWith(newRead);
            s.writeWith(newWrite);
            assertTrue(closed(oldRead), "the old read keys were left open");
            assertTrue(closed(oldWrite), "the old write keys were left open");
            assertFalse(closed(newRead));
        }
    }

    @Test
    void closeClosesBothKeysAndFreesTheBuffers() throws IOException {
        RecordProtection read = protection();
        RecordProtection write = protection();
        RecordStream s = new RecordStream(new Script().then(record(22, 3)));
        RecordStream.Incoming in = s.next();
        s.readWith(read);
        s.writeWith(write);
        s.close();
        assertTrue(closed(read), "the read keys outlived the stream");
        assertTrue(closed(write), "the write keys outlived the stream");
        assertNull(s.readProtection());
        assertThrows(IllegalStateException.class, () -> in.data().get(ValueLayout.JAVA_BYTE, in.offset()),
                "the record buffers outlived the stream");
    }
}
