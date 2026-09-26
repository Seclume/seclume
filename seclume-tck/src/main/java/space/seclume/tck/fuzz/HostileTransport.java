package space.seclume.tck.fuzz;

import java.io.IOException;
import java.nio.ByteBuffer;

import space.seclume.internal.Transport;

/**
 * A server that sends whatever it likes, in whatever pieces it likes.
 *
 * <p>The boundary walkers could be fuzzed as functions: bytes in, a number
 * out. The decoders cannot. What they do with a hostile field is only visible
 * through the session that drives them - the order of the reads, the state
 * left behind, whether a failure is one a caller could act on - so the way to
 * reach them is to put this underneath a real session object and let the
 * driver do the asking.
 *
 * <p>{@code resume()} is what makes that cheap. All four drivers can take up a
 * stream somebody else authenticated, which means a test can hand them a
 * transport without faking a login first, and every byte after that goes
 * straight into the decoders.
 *
 * <p><b>Three things this does that a socket also does</b>, and each has
 * caught something somewhere in this project already:
 *
 * <ul>
 *   <li>it hands over <b>fewer bytes than asked for</b>. A reader that assumes
 *       one read fills its buffer works on loopback and fails across a network;
 *   <li>it <b>ends</b>. A stream that stops mid-message is the ordinary
 *       consequence of a server being restarted, and the decoder above has to
 *       say so rather than block or spin;
 *   <li>it <b>accepts everything written to it</b> and remembers nothing. What
 *       the driver sends is not the subject here - only what it does with what
 *       comes back.
 * </ul>
 */
public final class HostileTransport implements Transport {

    private final byte[] script;
    private final int[] chunks;
    private final boolean closeAtTheEnd;

    private int at;
    private int chunk;
    private boolean closed;
    private int writes;

    private HostileTransport(byte[] script, int[] chunks, boolean closeAtTheEnd) {
        this.script = script;
        this.chunks = chunks;
        this.closeAtTheEnd = closeAtTheEnd;
    }

    /** Serves the script in one piece, then ends the stream. */
    public static HostileTransport of(byte[] script) {
        return new HostileTransport(script, new int[] {Integer.MAX_VALUE}, true);
    }

    /**
     * Serves the script in the given sizes, repeating them, then ends.
     *
     * <p>A chunking of {@code {1}} is the cruellest and the most realistic of
     * the cheap ones: every message arrives split at every byte, which is what
     * a reader that keeps no state between reads cannot survive.
     */
    public static HostileTransport of(byte[] script, int... chunks) {
        return new HostileTransport(script, chunks.length == 0
                ? new int[] {Integer.MAX_VALUE} : chunks, true);
    }

    /**
     * The same, but the stream stays open and empty once the script runs out.
     *
     * <p>For the question a closing stream cannot ask: a decoder waiting for
     * bytes that will never come. Reported as an end of stream here rather
     * than as a block, because a test that blocks is a test that hangs - the
     * distinction is whether the driver treats "nothing more" as an error or
     * as a reason to wait, and it has to treat it as an error.
     */
    public static HostileTransport thatGoesQuiet(byte[] script) {
        return new HostileTransport(script, new int[] {Integer.MAX_VALUE}, false);
    }

    @Override
    public int read(ByteBuffer into) throws IOException {
        if (closed) {
            throw new IOException("this transport is closed");
        }
        if (into.remaining() <= 0) {
            // A real socket answers a zero-length read with zero, and a driver
            // that then calls again has written itself a spin loop. Saying so
            // out loud rather than returning zero: a timeout ten seconds later
            // names nothing, and the first version of this class produced
            // exactly that - fifty-one identical "did not return" findings
            // with no clue which layer was turning.
            throw new IOException("the driver asked to read into a buffer with no room left");
        }
        if (at >= script.length) {
            return -1;
        }
        int want = Math.min(chunks[chunk++ % chunks.length], into.remaining());
        if (want <= 0) {
            want = into.remaining();
        }
        int take = Math.min(want, script.length - at);
        into.put(script, at, take);
        at += take;
        return take;
    }

    @Override
    public int write(ByteBuffer from) {
        writes++;
        int wrote = from.remaining();
        from.position(from.limit());
        return wrote;
    }

    @Override
    public boolean isOpen() {
        return !closed && (closeAtTheEnd ? at < script.length || writes >= 0 : true);
    }

    @Override
    public void close() {
        closed = true;
    }

    /** How many bytes of the script the driver actually took. */
    public int consumed() {
        return at;
    }

    /** Whether the driver closed this transport - for a test that asks. */
    public boolean wasClosed() {
        return closed;
    }
}
