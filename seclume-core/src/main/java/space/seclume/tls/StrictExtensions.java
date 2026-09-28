package space.seclume.tls;

import java.lang.foreign.MemorySegment;
import java.util.HashSet;
import java.util.Set;

/**
 * An extension block read the way RFC 8446 section 4.2 writes it: the list
 * fills its length exactly, every extension fills its own, and no type
 * appears twice. {@link Handshake#extensions} stops quietly at the first
 * thing that does not fit, which is right for reading one's own messages
 * back and wrong for a peer's: a length that lies is a {@code decode_error},
 * found by TLS-Anvil (27.09.2026) in the ServerHello and EncryptedExtensions.
 */
final class StrictExtensions {

    private StrictExtensions() {
    }

    @FunctionalInterface
    interface Visitor {
        void extension(int type, long at, int length) throws TlsProtocolException;
    }

    /**
     * The {@code Extension extensions<..>} field at {@code offset}: two bytes
     * of length, then the extensions - and together exactly {@code length}
     * bytes, since this field ends the message it is in.
     */
    static void list(MemorySegment data, long offset, int length, String message,
            Visitor visitor) throws TlsProtocolException {
        if (length < 2) {
            throw decodeError(message + " ends before its extensions");
        }
        int listLength = Handshake.u16(data, offset);
        if (listLength != length - 2) {
            throw decodeError(message + " says its extensions are " + listLength
                    + " bytes and has " + (length - 2));
        }
        entries(data, offset + 2, listLength, message, visitor);
    }

    /** The extensions themselves, {@code length} bytes from {@code offset}. */
    static void entries(MemorySegment data, long offset, int length, String message,
            Visitor visitor) throws TlsProtocolException {
        Set<Integer> seen = new HashSet<>();
        long at = 0;
        while (at < length) {
            if (length - at < 4) {
                throw decodeError(message + " has a truncated extension");
            }
            int type = Handshake.u16(data, offset + at);
            int extensionLength = Handshake.u16(data, offset + at + 2);
            if (at + 4 + extensionLength > length) {
                throw decodeError(message + " has an extension longer than its block");
            }
            if (!seen.add(type)) {
                throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                        message + " repeats extension " + type);
            }
            visitor.extension(type, offset + at + 4, extensionLength);
            at += 4 + extensionLength;
        }
    }

    static TlsProtocolException decodeError(String text) {
        return new TlsProtocolException(TlsAlertException.DECODE_ERROR, text);
    }

    /** An extension the client did not ask for: RFC 8446 section 4.2. */
    static TlsProtocolException unsolicited(String message, int type) {
        return new TlsProtocolException(TlsAlertException.UNSUPPORTED_EXTENSION,
                message + " carries extension " + type + ", which this client did not offer");
    }
}
