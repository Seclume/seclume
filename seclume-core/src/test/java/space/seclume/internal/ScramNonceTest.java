package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.function.UnaryOperator;

import org.junit.jupiter.api.Test;

import space.seclume.crypto.HashAlgorithm;

/**
 * The server's nonce has to extend the client's (RFC 5802, section 5.1). The
 * check was "at least as long, and starts with ours": a server that sent our
 * nonce back unchanged - nothing of its own in it - passed. Found by the
 * mutation test (|| to &&, < to <= survived); these are the tests it asked for.
 */
class ScramNonceTest {

    private static final String SALT = "YSBzYWx0IG9mIHNpeHRlZW4=";

    private static MemorySegment ascii(Arena arena, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.US_ASCII);
        MemorySegment segment = arena.allocate(bytes.length);
        MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return segment;
    }

    /** The server's first message, its nonce made from ours by {@code nonce}. */
    private static void serverAnswers(UnaryOperator<String> nonce) {
        try (Arena arena = Arena.ofConfined(); Scram scram = new Scram(HashAlgorithm.SHA_256)) {
            MemorySegment out = arena.allocate(256);
            int length = scram.clientFirst(out, "app");
            String first = new String(out.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.US_ASCII);
            String ours = first.substring(first.indexOf(",r=") + 3);
            String serverFirst = "r=" + nonce.apply(ours) + ",s=" + SALT + ",i=4096";
            scram.serverFirst(ascii(arena, serverFirst), 0, serverFirst.length());
        }
    }

    @Test
    void aServerNonceThatExtendsOursIsTaken() {
        assertDoesNotThrow(() -> serverAnswers(ours -> ours + "srv"));
    }

    @Test
    void aServerNonceThatOnlyEqualsOursIsRefused() {
        assertThrows(IllegalStateException.class, () -> serverAnswers(ours -> ours));
    }

    @Test
    void aServerNonceThatDoesNotStartWithOursIsRefused() {
        assertThrows(IllegalStateException.class,
                () -> serverAnswers(ours -> "x" + ours.substring(1) + "srv"));
        assertThrows(IllegalStateException.class,
                () -> serverAnswers(ours -> new StringBuilder(ours).reverse() + "srv"));
    }

    @Test
    void aShorterServerNonceIsRefused() {
        assertThrows(IllegalStateException.class,
                () -> serverAnswers(ours -> ours.substring(0, ours.length() - 1)));
    }
}
