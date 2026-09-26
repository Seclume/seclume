package space.seclume.internal;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Bytes to the server and back, and nothing else.
 *
 * <p>Every one of the four drivers writes into a buffer and reads out of one;
 * underneath that sits a {@link java.nio.channels.SocketChannel} today, in
 * exactly four places, reached through four methods. This interface is those
 * four methods.
 *
  * <p>It is not an abstraction for its own sake. Something other than a
 * {@code SocketChannel} can carry a session - see the note on session
 * mobility in the README - and the ways to reach a channel's descriptor
 * inside the JDK, reflection into {@code sun.nio.ch} or
 * {@code jdk.internal.access}, are the kind of grip that breaks with the next
 * JDK. So a second implementation has to be possible from outside, and this
 * is the seam it goes into - see {@link TransportProvider}.
 *
 * <p>The seam is worth having before the implementation exists, which is why it
 * lands on its own: it changes no behaviour, every existing test has to stay
 * green on top of it, and a refactoring that can be checked that way is a
 * different risk from one bundled with new syscalls.
 *
 * <p><b>Blocking, deliberately.</b> The callers are written against blocking
 * reads and writes, virtual threads unmount on them, and nothing in the drivers
 * wants a selector. An FFM implementation will need {@code O_NONBLOCK} plus a
 * readiness wait of its own to keep that promise - a blocking {@code read}
 * syscall through FFM pins its carrier thread - but that is its problem to
 * solve behind this interface, not the callers'.
 */
public interface Transport extends AutoCloseable {

    /**
     * Reads into the buffer, blocking until at least one byte arrives.
     *
     * @return the number of bytes read, or -1 at the end of the stream
     */
    int read(ByteBuffer into) throws IOException;

    /**
     * Writes from the buffer.
     *
     * <p>May write less than the buffer holds; the callers loop, exactly as
     * they do on a {@code SocketChannel}.
     *
     * @return the number of bytes written
     */
    int write(ByteBuffer from) throws IOException;

    /**
     * Gives up on a read or write that waits longer than this, and closes the
     * transport - {@code Connection.setNetworkTimeout}. Zero waits for ever,
     * which is what every transport does until told otherwise.
     *
     * <p>Default: not supported, for a transport that has no socket of its own
     * to give up on.
     *
     * @param millis the longest a single read or write may wait, or 0
     * @throws IOException if this transport cannot do it
     */
    default void networkTimeout(int millis) throws IOException {
        throw new IOException("this transport has no network timeout");
    }

    /**
     * Sends one byte ahead of everything still queued - TCP urgent data.
     *
     * <p>The fifth method, and it took a protocol to justify it. Oracle's
     * break is not a packet the server reads in turn: the server is busy
     * running the statement and is not reading the socket at all, so an
     * in-band marker sits in its receive buffer until the statement it was
     * meant to stop has finished. Urgent data is delivered out of order and
     * raises {@code SIGURG} on the far side, which is what makes a server look
     * up from what it is doing. Oracle accepts the in-band marker only when
     * the listener is configured with {@code DISABLE_OOB=ON}.
     *
     * <p>Default: not supported. Most transports cannot do this - a pipe, a
     * TLS layer, anything that is not a socket - and a caller that needs it
     * has to be able to find out without guessing.
     *
     * @param value the byte, of which TCP carries exactly one
     * @throws IOException if this transport has no way to send it
     */
    default void sendUrgent(int value) throws IOException {
        throw new IOException("this transport cannot send urgent data");
    }

    /** Whether this transport can still carry bytes. */
    boolean isOpen();

    /**
     * Closes it; afterwards nothing works any more.
     *
     * <p>Without a checked exception on purpose - on close an error has no
     * consequences anybody could act on, and every caller in this project
     * already swallows it.
     */
    @Override
    void close();
}
