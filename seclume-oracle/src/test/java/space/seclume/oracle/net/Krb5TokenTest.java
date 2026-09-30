package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * The GSS-API frame around a Kerberos message, taken off for Oracle and put
 * back on for the library - short and long lengths, and the frames that are
 * not what they claim refused.
 */
class Krb5TokenTest {

    @Test
    void framedAndUnframedAgain() throws IOException {
        for (int size : new int[] {1, 100, 116, 117, 200, 1500}) {
            byte[] message = new byte[size];
            Arrays.fill(message, (byte) 0x6e);           // an AP-REQ starts with [APPLICATION 14]
            byte[] framed = Krb5Token.frame(MemorySegment.ofArray(message), 0x01);
            int at = Krb5Token.innerOffset(framed, 0x01);
            assertEquals(size, framed.length - at, "size " + size);
            assertArrayEquals(message, Arrays.copyOfRange(framed, at, framed.length));
        }
    }

    @Test
    void theWrongTokenOrMechanismIsRefused() {
        byte[] reply = Krb5Token.frame(MemorySegment.ofArray(new byte[] {1, 2, 3}), 0x02);
        assertThrows(IOException.class, () -> Krb5Token.innerOffset(reply, 0x01));
        byte[] other = reply.clone();
        other[4] = 0x7f;                                   // inside the OID
        assertThrows(IOException.class, () -> Krb5Token.innerOffset(other, 0x02));
        assertThrows(IOException.class, () -> Krb5Token.innerOffset(new byte[] {0x30, 0}, 0x01));
    }
}
