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
