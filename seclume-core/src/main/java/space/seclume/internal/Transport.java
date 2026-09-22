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
