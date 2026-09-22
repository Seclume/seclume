package space.seclume.internal;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;

/**
 * Encryption between a driver's buffers and its socket - whichever
 * implementation provides it.
 *
 * <p>There are two, and the difference matters to exactly one caller: the
 * person configuring the connection. {@link TlsChannel} is an
 * {@code SSLEngine} and is what a JDBC driver normally is; {@code SeclumeTls}
 * is this project's own TLS 1.3 client, where every traffic secret lives in
 * native memory and the connection can be frozen and carried to another
 * machine. Neither is visible above this interface, which is the point - the
 * four protocols write bytes and read bytes and have no business knowing which
 * stack carries them.
 *
 * <p>Note what {@link #write} promises that {@link Transport#write} does not:
 * everything in the buffer goes out. A partial write of a TLS record has no
 * useful meaning to a caller, since the record is already encrypted and the
 * remainder is not a message of its own - so the looping happens here, once,
 * instead of in each of the three channels.
 */
public interface TlsLayer extends AutoCloseable {

    /** Encrypts and sends everything remaining in {@code plain}. */
    void write(ByteBuffer plain) throws IOException;

    /**
     * Reads decrypted bytes into {@code target}.
     *
     * @return how many bytes were put there; -1 when the peer closed the
     *         connection
     */
    int read(ByteBuffer target) throws IOException;

    /**
     * The server's certificate - for channel binding, not for checking.
     *
     * <p>Available whatever the TLS mode: with {@code require} the certificate
     * is not verified, but it is still the certificate of this connection, and
     * that is all a binding needs.
     */
    X509Certificate peerCertificate() throws IOException;

    /** Protocol and cipher suite, for the preflight report. */
    String description();

    /**
     * Whether this layer's state can be written down and taken up on another
     * machine.
     *
     * <p>The difference between the two implementations, and the one that
     * decides whether a live connection can change host. Moving a session
     * means serialising its state, and the encryption is part of that state:
     * the keys and the record sequence numbers. An {@code SSLEngine} does not
     * hand either out - no method of {@code SSLSession} or {@code SSLEngine}
     * is named for them, by design - so a connection on the JDK's TLS can be
     * frozen and thawed <b>within one process</b>, where the engine is an
     * object that stays put, and cannot leave it. On seclume's own stack the
     * state is ours, in memory we allocated, and it can travel.
     *
     * <p>A method rather than a sentence in a document, so that the code
     * refuses rather than the reader remembers.
     */
    boolean movable();

    /**
     * How many bytes {@link #freeze} needs.
     *
     * <p>Ask before allocating, and allocate a
     * {@link space.seclume.secret.SecretScope} rather than an array: what
     * {@code freeze} writes is key material.
     *
     * @throws UnsupportedOperationException on a layer whose {@link #movable()}
     *         is {@code false}
     */
    default int frozenLength() {
        throw new UnsupportedOperationException(notMovable());
    }

    /**
     * Writes this layer's encryption state out and gives the layer up,
     * <b>without closing the transport underneath and without saying goodbye
     * to the peer</b>.
     *
     * <p>Only at a quiet moment: with a record decrypted whose bytes nobody
     * has read, freezing would drop them, and the implementation refuses
     * rather than risks it.
     *
     * <p><b>What lands in {@code out} is the key to the connection, in both
     * directions.</b> Whoever holds these bytes can read and forge everything
     * on it, so the segment should be a
     * {@link space.seclume.secret.SecretScope} - locked, wiped on close - and
     * the carrier that takes them anywhere has to be confidential as well as
     * authenticated.
     *
     * @return the number of bytes written
     * @throws UnsupportedOperationException on a layer whose {@link #movable()}
     *         is {@code false}
     */
    default int freeze(MemorySegment out, long offset) {
        throw new UnsupportedOperationException(notMovable());
    }

    private static String notMovable() {
        return "this TLS layer is an SSLEngine: it does not hand out its traffic secrets or "
                + "its record sequence numbers, by design, so its state cannot be written "
                + "down. Use seclume's own TLS stack for a connection that has to move";
    }

    /**
     * Puts a different transport underneath, keeping the encryption state as
     * it is.
     *
     * <p>Called when a connection's socket is rebuilt beneath it. The keys and
     * the record sequence numbers do not care which descriptor carried them;
     * this layer does, because it holds a second reference to the old one.
     */
    void replaceTransport(Transport replacement);

    /**
     * Releases this layer without closing the transport underneath.
     *
     * <p>Separate from {@link #close()} because the two implementations
     * differ in exactly this: an {@code SSLEngine} never owned the socket,
     * and the own stack's connection does. The distinction only matters
     * where a second TLS session is brought up on a socket that is still in
     * use - Oracle's TCPS handover - and where getting it wrong closes the
     * socket out from under the successor.
     */
    void discard();

    @Override
    void close();
}
