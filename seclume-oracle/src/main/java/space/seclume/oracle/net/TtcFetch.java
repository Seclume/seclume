package space.seclume.oracle.net;

import java.io.IOException;

import space.seclume.internal.WireBuffer;

/**
 * The fetch call - the rest of a result.
 *
 * <p>Oracle answers a statement with a first block of rows and then waits. How
 * large that block is the client says in the execute call; everything after it
 * has to be asked for, one block at a time, naming the cursor the server
 * opened.
 *
 * <p>The message is short enough to quote in full: type, function, sequence
 * number, the token, the cursor number, and how many rows are wanted.
 */
public final class TtcFetch {

    /** Fetch the next block. */
    public static final int FUNCTION = 5;

    private TtcFetch() {
    }

    /** Sends the call. */
    public static void send(NsChannel channel, int sequence, int cursorId, int rows)
            throws IOException {
        WireBuffer out = channel.beginData();
        out.putByte((byte) TtcMessage.TYPE_FUNCTION);
        out.putByte((byte) FUNCTION);
        out.putByte((byte) sequence);
        TtcParameters.putNumber(out, 0);               // token number
        TtcParameters.putNumber(out, cursorId);
        TtcParameters.putNumber(out, rows);
        channel.sendData();
    }
}
