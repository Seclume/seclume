package space.seclume.tls;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * The TLS 1.3 {@code Certificate} message body (RFC 8446, section 4.4.2):
 * a request context, then a list of {@code CertificateEntry} - each one a
 * DER certificate and its own per-certificate extensions.
 *
 * <p>The first entry is the end-entity (leaf) certificate; the rest, if any,
 * are the chain up to (not including) a trust anchor. Reading them all is
 * this class's job; deciding whether they chain to something trusted, and
 * whether the leaf's name matches the host connected to, is not - see
 * the project notes.
 */
public final class CertificateMessage {

    private CertificateMessage() {
    }

    /**
     * Walks every {@code CertificateEntry} in order, leaf first.
     *
     * <p>Bounded the same way {@link Handshake#extensions} is: an entry whose
     * length runs past the end of the list stops the walk rather than reading
     * into whatever follows.
     */
    public static void certificates(MemorySegment body, long offset, int length, Reader reader) {
        long end = offset + length;
        int contextLength = u8(body, offset);
        long at = offset + 1 + contextLength;
        if (at + 3 > end) {
            return;
        }
        int listLength = u24(body, at);
        at += 3;
        long listEnd = at + listLength;
        if (listEnd > end) {
            listEnd = end;                    // truncated; walk what is actually there
        }
        while (listEnd - at >= 3) {
            int certLength = u24(body, at);
            at += 3;
            if (at + certLength + 2 > listEnd) {
                return;
            }
            long certAt = at;
            at += certLength;
            int extensionsLength = u16(body, at);
            at += 2;
            if (at + extensionsLength > listEnd) {
                return;
            }
            long extAt = at;
            at += extensionsLength;
            reader.certificate(certAt, certLength, extAt, extensionsLength);
        }
    }

    /**
     * Writes the client's own {@code Certificate} message, header and all.
     *
     * <p>Sent whenever the server asked, <b>including when there is nothing
     * to send</b>: RFC 8446 requires a Certificate message in answer to a
     * CertificateRequest, and an empty certificate list is how a client says
     * "I have none". Staying silent instead would hang the handshake, and
     * failing instead would take the decision away from the server, which may
     * well be configured to accept an anonymous client.
     *
     * <p>The request context is echoed back exactly as it arrived. It is empty
     * for a certificate requested during the handshake and non-empty only for
     * post-handshake authentication, which this client does not do - but
     * echoing whatever came is both cheaper and more correct than assuming.
     *
     * @param chain DER certificates, leaf first; may be empty
     * @return how many bytes of {@code out} were written
     */
    public static int write(MemorySegment out, byte[] context, java.util.List<byte[]> chain) {
        long at = Handshake.HEADER;
        out.set(ValueLayout.JAVA_BYTE, at++, (byte) context.length);
        MemorySegment.copy(context, 0, out, ValueLayout.JAVA_BYTE, at, context.length);
        at += context.length;

        int listLength = 0;
        for (byte[] certificate : chain) {
            listLength += 3 + certificate.length + 2;   // length, body, no extensions
        }
        putU24(out, at, listLength);
        at += 3;
        for (byte[] certificate : chain) {
            putU24(out, at, certificate.length);
            at += 3;
            MemorySegment.copy(certificate, 0, out, ValueLayout.JAVA_BYTE, at, certificate.length);
            at += certificate.length;
            out.set(ValueLayout.JAVA_BYTE, at++, (byte) 0);   // extensions: none
            out.set(ValueLayout.JAVA_BYTE, at++, (byte) 0);
        }

        int body = (int) (at - Handshake.HEADER);
        out.set(ValueLayout.JAVA_BYTE, 0, (byte) Handshake.CERTIFICATE);
        putU24(out, 1, body);
        return Handshake.HEADER + body;
    }

    /** How large a buffer {@link #write} needs for this chain. */
    public static int sizeFor(byte[] context, java.util.List<byte[]> chain) {
        int size = Handshake.HEADER + 1 + context.length + 3;
        for (byte[] certificate : chain) {
            size += 3 + certificate.length + 2;
        }
        return size;
    }

    /** The request context of a {@code CertificateRequest}, as sent. */
    public static byte[] requestContext(MemorySegment body, long offset) {
        int length = u8(body, offset);
        byte[] context = new byte[length];
        MemorySegment.copy(body, ValueLayout.JAVA_BYTE, offset + 1, context, 0, length);
        return context;
    }

    private static void putU24(MemorySegment out, long at, int value) {
        out.set(ValueLayout.JAVA_BYTE, at, (byte) (value >>> 16));
        out.set(ValueLayout.JAVA_BYTE, at + 1, (byte) (value >>> 8));
        out.set(ValueLayout.JAVA_BYTE, at + 2, (byte) value);
    }

    /** What {@link #certificates} calls for each entry. */
    @FunctionalInterface
    public interface Reader {
        void certificate(long certificateAt, int certificateLength,
                long extensionsAt, int extensionsLength);
    }

    private static int u8(MemorySegment data, long at) {
        return data.get(ValueLayout.JAVA_BYTE, at) & 0xff;
    }

    private static int u16(MemorySegment data, long at) {
        return Handshake.u16(data, at);
    }

    private static int u24(MemorySegment data, long at) {
        return ((u8(data, at)) << 16) | ((u8(data, at + 1)) << 8) | u8(data, at + 2);
    }
}
