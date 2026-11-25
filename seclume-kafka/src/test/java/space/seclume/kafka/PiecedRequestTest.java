package space.seclume.kafka;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;

import org.junit.jupiter.api.Test;

import space.seclume.internal.SeclumeSslEngine.Outgoing.Step;

/**
 * A request whose size and API key reached the rewriter in two writes was an
 * IOException, and the connection was gone. They are held until all six bytes
 * are there and passed on as they were; only a SaslAuthenticate cut there is
 * still refused, since its placeholder is replaced in one piece.
 */
class PiecedRequestTest {

    private static Step step(SaslAuthenticateRewriter rewriter, byte... bytes) throws IOException {
        return rewriter.next(ByteBuffer.wrap(bytes));
    }

    @Test
    void aHeadInTwoPiecesIsPassedOnAsItWas() throws IOException {
        SaslAuthenticateRewriter rewriter = new SaslAuthenticateRewriter();
        Step first = step(rewriter, (byte) 0, (byte) 0, (byte) 0, (byte) 10);   // size 10
        assertEquals(4, first.replaced());
        assertEquals(0, first.replacement().length(), "sent before the API key was known");
        first.replacement().close();

        Step second = step(rewriter, (byte) 0, (byte) 3, (byte) 0, (byte) 1,       // key 3
                (byte) 0, (byte) 0, (byte) 0, (byte) 7, (byte) 0, (byte) 0, (byte) 9, (byte) 9);
        assertEquals(2, second.replaced());
        byte[] held = second.replacement().segment().asSlice(0, second.replacement().length())
                .toArray(ValueLayout.JAVA_BYTE);
        second.replacement().close();
        assertArrayEquals(new byte[] {0, 0, 0, 10, 0, 3}, held);

        Step rest = rewriter.next(ByteBuffer.wrap(new byte[] {0, 1, 0, 0, 0, 7, 0, 0}));
        assertEquals(8, rest.unchanged(), "the rest of the request goes through as it is");
    }

    @Test
    void aSaslAuthenticateCutBeforeItsKeyIsStillRefused() throws IOException {
        SaslAuthenticateRewriter rewriter = new SaslAuthenticateRewriter();
        step(rewriter, (byte) 0, (byte) 0, (byte) 0, (byte) 40).replacement().close();
        assertThrows(IOException.class, () -> step(rewriter, (byte) 0, (byte) 36));
    }
}
