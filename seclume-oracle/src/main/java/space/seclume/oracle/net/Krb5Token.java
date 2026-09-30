package space.seclume.oracle.net;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * The GSS-API framing of a Kerberos token (RFC 2743 3.1, RFC 4121 4.1) -
 * {@code [APPLICATION 0] { OID 1.2.840.113554.1.2.2, token id, message }} -
 * taken off and put back on.
 *
 * <p>MIT's GSSAPI and Windows' SSPI hand out an AP-REQ in this frame and
 * expect the AP-REP in it; Oracle's negotiation carries the bare Kerberos
 * messages. A ticket and an authenticator are protocol data, not the key -
 * the session key stays inside the library.
 */
final class Krb5Token {

    /** DER of the Kerberos V5 mechanism OID, tag and length included. */
    private static final byte[] KRB5_OID = {0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86,
            (byte) 0xf7, 0x12, 0x01, 0x02, 0x02};

    private Krb5Token() {
    }

    /**
     * Where the bare message starts in a framed token, after checking the
     * frame, the OID and the token id ({@code 0x01} for an AP-REQ).
     */
    static int innerOffset(byte[] token, int tokenId) throws IOException {
        if (token.length < 2 || (token[0] & 0xff) != 0x60) {
            throw new IOException("the Kerberos library's token is not GSS-API framed");
        }
        int at = 1;
        int first = token[at++] & 0xff;
        if ((first & 0x80) != 0) {
            at += first & 0x7f;                            // a long-form length
        }
        for (byte b : KRB5_OID) {
            if (at >= token.length || token[at++] != b) {
                throw new IOException("the Kerberos library's token is not for Kerberos V5");
            }
        }
        if (at + 2 > token.length || token[at] != tokenId || token[at + 1] != 0) {
            throw new IOException("the Kerberos library's token is not the expected message");
        }
        return at + 2;
    }

    /** {@code message} framed, with {@code tokenId} ({@code 0x02} for an AP-REP). */
    static byte[] frame(MemorySegment message, int tokenId) {
        int inner = KRB5_OID.length + 2 + (int) message.byteSize();
        byte[] length = derLength(inner);
        byte[] out = new byte[1 + length.length + inner]; // seclume-allow: a Kerberos reply, protocol data and not a key
        int at = 0;
        out[at++] = 0x60;
        System.arraycopy(length, 0, out, at, length.length);
        at += length.length;
        System.arraycopy(KRB5_OID, 0, out, at, KRB5_OID.length);
        at += KRB5_OID.length;
        out[at++] = (byte) tokenId;
        out[at++] = 0;
        MemorySegment.copy(message, ValueLayout.JAVA_BYTE, 0, out, at, (int) message.byteSize());
        return out;
    }

    private static byte[] derLength(int length) {
        if (length < 0x80) {
            return new byte[] {(byte) length};
        }
        if (length < 0x100) {
            return new byte[] {(byte) 0x81, (byte) length};
        }
        return new byte[] {(byte) 0x82, (byte) (length >>> 8), (byte) length};
    }
}
