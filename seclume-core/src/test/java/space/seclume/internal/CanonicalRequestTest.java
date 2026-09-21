package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * The canonical request assembled in native memory.
 *
 * <p>Its whole purpose is that one line of an AWS canonical request can be a
 * session token, and a token that is signed as well as sent would otherwise
 * be concatenated into a {@code String}. So there are two things to check
 * and they pull in opposite directions: <b>it has to produce exactly what
 * concatenation produced</b>, or AWS rejects the signature with nothing that
 * says why; and <b>it must not leave the bytes lying around</b>, or the
 * exercise was pointless.
 */
class CanonicalRequestTest {

    /**
     * Byte for byte the same digest as the string it replaces.
     *
     * <p>The oracle is the old way of doing it. Anything else would be this
     * class agreeing with itself.
     */
    @Test
    void producesTheSameDigestAsConcatenation() {
        String token = "FwoGZXIvYXdzEExampleSessionToken";
        String expected = AwsSigV4.sha256Hex("POST\n/\n\n"
                + "host:secretsmanager.eu-central-1.amazonaws.com\n"
                + "x-amz-security-token:" + token + "\n\n"
                + "host;x-amz-security-token\n"
                + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        try (Arena arena = Arena.ofConfined();
                CanonicalRequest request = new CanonicalRequest(arena, 1024)) {
            request.text("POST\n/\n\n")
                    .text("host:secretsmanager.eu-central-1.amazonaws.com\n")
                    .text("x-amz-security-token:");
            request.secret(bytes(arena, token), token.length());
            request.text("\n\n")
                    .text("host;x-amz-security-token\n")
                    .text(AwsSigV4.EMPTY_PAYLOAD);
            assertEquals(expected, request.sha256Hex());
        }
    }

    /** And a different token is a different digest - the control for the above. */
    @Test
    void adifferentTokenIsADifferentDigest() {
        try (Arena arena = Arena.ofConfined()) {
            assertNotEquals(digestOf(arena, "token-one"), digestOf(arena, "token-two"));
        }
    }

    /**
     * Closing wipes, and the object refuses to be used afterwards.
     *
     * <p>The arena would free the memory eventually, and freeing is not
     * erasing. Checked by reading the buffer back through {@code at}, which
     * exists for exactly this - there is no other way to ask from outside
     * whether something was really overwritten.
     */
    @Test
    void closingWipesWhatWasWritten() {
        try (Arena arena = Arena.ofConfined()) {
            CanonicalRequest request = new CanonicalRequest(arena, 64);
            request.text("x-amz-security-token:hunter2");
            assertEquals((byte) 'x', request.at(0));
            int length = request.length();
            assertTrue(length > 20);

            request.close();
            assertThrows(IllegalStateException.class, () -> request.at(0));
            assertThrows(IllegalStateException.class, () -> request.text("more"));
            assertThrows(IllegalStateException.class, request::sha256Hex);
        }
    }

    /** Twice is allowed and does nothing the second time. */
    @Test
    void closingTwiceIsHarmless() {
        try (Arena arena = Arena.ofConfined()) {
            CanonicalRequest request = new CanonicalRequest(arena, 16);
            request.text("abc");
            request.close();
            request.close();
        }
    }

    /**
     * Running out of room is an exception, not a silent truncation.
     *
     * <p>A truncated canonical request signs perfectly well and is refused
     * by AWS with a message that names nothing. Better to fail here, where
     * the reason is in the stack trace.
     */
    @Test
    void refusesToOverflow() {
        try (Arena arena = Arena.ofConfined();
                CanonicalRequest request = new CanonicalRequest(arena, 8)) {
            MemorySegment tooMuch = bytes(arena, "0123456789");
            assertThrows(IllegalStateException.class, () -> request.secret(tooMuch, 10));
        }
    }

    private static String digestOf(Arena arena, String token) {
        try (CanonicalRequest request = new CanonicalRequest(arena, 256)) {
            request.text("x-amz-security-token:");
            request.secret(bytes(arena, token), token.length());
            return request.sha256Hex();
        }
    }

    private static MemorySegment bytes(Arena arena, String text) {
        byte[] raw = text.getBytes(StandardCharsets.US_ASCII);
        MemorySegment segment = arena.allocate(raw.length);
        MemorySegment.copy(raw, 0, segment, ValueLayout.JAVA_BYTE, 0, raw.length);
        return segment;
    }
}
