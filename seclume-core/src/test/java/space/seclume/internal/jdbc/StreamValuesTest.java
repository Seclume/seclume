package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.sql.SQLException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

class StreamValuesTest {

    private static byte[] ramp(int size) {
        byte[] bytes = new byte[size]; // seclume-allow: test payload
        for (int i = 0; i < size; i++) {
            bytes[i] = (byte) (i * 31 + 7);
        }
        return bytes;
    }

    @Test
    void aStreamWithoutLengthIsReadToItsEnd() throws Exception {
        byte[] data = ramp(100_000);
        assertArrayEquals(data, StreamValues.bytes(new ByteArrayInputStream(data),
                StreamValues.UNKNOWN));
        String text = "äöü ".repeat(10_000);
        assertEquals(text, StreamValues.text(new StringReader(text), StreamValues.UNKNOWN));
    }

    @Test
    void aGivenLengthIsHeldTo() throws Exception {
        byte[] data = ramp(50_000);
        assertArrayEquals(java.util.Arrays.copyOf(data, 20_000),
                StreamValues.bytes(new ByteArrayInputStream(data), 20_000),
                "past the length the stream is not read");
        assertEquals("abc", StreamValues.text(new StringReader("abcdef"), 3));
        assertEquals("", StreamValues.text(new StringReader("abc"), 0));
    }

    @Test
    void aStreamThatEndsEarlyIsAnErrorNotAShorterValue() {
        SQLException bytes = assertThrows(SQLException.class, () ->
                StreamValues.bytes(new ByteArrayInputStream(ramp(10)), 11));
        assertTrue(bytes.getMessage().contains("10 of the 11 bytes"), bytes.getMessage());
        SQLException text = assertThrows(SQLException.class, () ->
                StreamValues.text(new StringReader("ab"), 5));
        assertEquals("22000", text.getSQLState());
    }

    @Test
    void nullStaysNullAndTheStreamIsClosed() throws Exception {
        assertNull(StreamValues.bytes(null, 5));
        assertNull(StreamValues.text(null, StreamValues.UNKNOWN));
        AtomicBoolean closed = new AtomicBoolean();
        InputStream stream = new ByteArrayInputStream(ramp(3)) {
            @Override
            public void close() throws IOException {
                closed.set(true);
            }
        };
        StreamValues.bytes(stream, 3);
        assertTrue(closed.get());
    }

    @Test
    void asciiKeepsEveryByteAsOneCharacter() throws Exception {
        byte[] latin = {'a', (byte) 0xe4, 'b'};
        assertEquals("aäb", StreamValues.ascii(new ByteArrayInputStream(latin), 3));
    }

    @Test
    void aLengthNoValueCanHoldIsRefusedBeforeReading() {
        assertThrows(SQLException.class, () ->
                StreamValues.bytes(new ByteArrayInputStream(new byte[1]), 1L << 33));
    }
}
