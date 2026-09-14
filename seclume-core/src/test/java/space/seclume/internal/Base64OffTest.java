package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import space.seclume.Segments;

/** RFC 4648 examples and a cross-check against {@link Base64} over all remainder lengths. */
class Base64OffTest {

    @ParameterizedTest
    @CsvSource({
        "'',''",
        "f,Zg==",
        "fo,Zm8=",
        "foo,Zm9v",
        "foob,Zm9vYg==",
        "fooba,Zm9vYmE=",
        "foobar,Zm9vYmFy",
    })
    void rfc4648Examples(String plain, String encoded) {
        String text = plain == null ? "" : plain;
        String expected = encoded == null ? "" : encoded;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment source = Segments.ascii(arena, text);
            MemorySegment target = arena.allocate(Base64Off.encodedLength(text.length()) + 1);
            int written = Base64Off.encode(source, 0, text.length(), target, 0);
            assertEquals(expected, new String(
                    Segments.toBytes(target.asSlice(0, written)), StandardCharsets.US_ASCII));

            MemorySegment back = arena.allocate(Base64Off.decodedUpperBound(written) + 1);
            int decoded = Base64Off.decode(target, 0, written, back, 0);
            assertEquals(text, new String(
                    Segments.toBytes(back.asSlice(0, decoded)), StandardCharsets.US_ASCII));
        }
    }

    @Test
    void matchesTheJdkForRandomData() {
        Random random = new Random(20260905L);
        try (Arena arena = Arena.ofConfined()) {
            for (int length = 0; length < 200; length++) {
                byte[] data = new byte[length];
                random.nextBytes(data);
                String expected = Base64.getEncoder().encodeToString(data);

                MemorySegment source = Segments.bytes(arena, data);
                MemorySegment target = arena.allocate(Base64Off.encodedLength(length) + 1);
                int written = Base64Off.encode(source, 0, length, target, 0);
                assertEquals(expected, new String(
                        Segments.toBytes(target.asSlice(0, written)), StandardCharsets.US_ASCII),
                        "encoding " + length + " bytes");

                MemorySegment back = arena.allocate(Base64Off.decodedUpperBound(written) + 1);
                int decoded = Base64Off.decode(target, 0, written, back, 0);
                assertArrayEquals(data, Segments.toBytes(back.asSlice(0, decoded)),
                        "decoding " + length + " bytes");
            }
        }
    }

    /** PEM comes with line breaks; they must not disturb the decoder. */
    @Test
    void skipsLineBreaks() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment source = Segments.ascii(arena, "Zm9v\nYmFy\r\n");
            MemorySegment target = arena.allocate(16);
            int decoded = Base64Off.decode(source, 0, (int) source.byteSize(), target, 0);
            assertEquals("foobar", new String(
                    Segments.toBytes(target.asSlice(0, decoded)), StandardCharsets.US_ASCII));
        }
    }

    @Test
    void rejectsGarbage() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment source = Segments.ascii(arena, "Zm9v!!");
            MemorySegment target = arena.allocate(16);
            assertThrows(IllegalArgumentException.class,
                    () -> Base64Off.decode(source, 0, (int) source.byteSize(), target, 0));
        }
    }
}
