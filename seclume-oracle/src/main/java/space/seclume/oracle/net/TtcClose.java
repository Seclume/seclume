package space.seclume.oracle.net;

import space.seclume.internal.WireBuffer;

/**
 * Giving cursors back - the call that says "I am done with these numbers".
 *
 * <p>A cursor belongs to the session, not to the statement object in front of
 * it, so a driver that keeps a parsed statement keeps a cursor at the server.
 * That is the whole point of keeping them. What it also means is that
 * <b>dropping the number is not the same as closing the cursor</b>: the server
 * has no way of learning that nobody will ask for it again, counts it against
 * {@code open_cursors}, and a connection that sees more distinct statement
 * texts than the cache holds ends in {@code ORA-01000}.
 *
 * <p><b>It rides in front of the next call rather than travelling alone.</b>
 * TTC has a message type for exactly this - a <i>piggyback</i>, written into
 * the same packet ahead of the real call - so giving a cursor back costs no
 * round trip at all. It is also what Oracle's own client does, which is how
 * the shape below was read: a run of {@code python-oracledb} with
 * {@code PYO_DEBUG_PACKETS=1} and a statement cache of two, then five cursors
 * closed at once to tell the count apart from the first id.
 *
 * <pre>
 * 11 69 08                 piggyback, function 105, call number
 * 00                       token number
 * 01                       a pointer: the array below is there
 * 01 05                    five of them
 * 01 01  01 03  01 04 ...  the cursor numbers
 * </pre>
 *
 * <p>The answer is the next call's answer. A piggyback produces none of its
 * own - which is why it may be written into a packet that is about to be sent
 * and never into one of its own.
 */
public final class TtcClose {

    /** Close cursors. */
    public static final int FUNCTION = 105;

    private TtcClose() {
    }

    /**
     * Writes the piggyback into a data packet that is already open.
     *
     * @param out     the buffer {@code beginData} returned, positioned before
     *                the call this rides in front of
     * @param sequence the call number for the piggyback itself - it consumes
     *                one like any other call
     * @param cursors  the numbers to give back
     * @param count    how many of {@code cursors} are in use
     */
    public static void putPiggyback(WireBuffer out, int sequence, int[] cursors, int count) {
        out.putByte((byte) TtcMessage.TYPE_PIGGYBACK);
        out.putByte((byte) FUNCTION);
        out.putByte((byte) sequence);
        TtcParameters.putNumber(out, 0);               // token number
        out.putByte((byte) 1);                         // pointer: the array follows
        TtcParameters.putNumber(out, count);
        for (int i = 0; i < count; i++) {
            TtcParameters.putNumber(out, cursors[i]);
        }
    }
}
