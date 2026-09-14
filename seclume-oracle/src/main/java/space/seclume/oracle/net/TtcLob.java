package space.seclume.oracle.net;

import java.io.IOException;
import java.sql.SQLException;

import space.seclume.internal.WireBuffer;

/**
 * LOB operations - TTC function 96.
 *
 * <p>A {@code CLOB} or {@code BLOB} does not travel inside its row. The row
 * carries a <b>locator</b>, 112 bytes that name the value on the server, and
 * the contents are fetched with a call of their own. This class is that call.
 *
 * <p>Every number here was measured, not guessed: a run of
 * {@code python-oracledb} with {@code debug output} against Oracle Free
 * 23ai, with the same read done three times over values of different size so
 * that the field carrying the length had to move. The recording is in
 * {@code docs/protocol/oracle-lob.md}, the findings in
 * {@code docs/protocol/oracle-lob.md}.
 *
 * <p>Two of those findings shape this code:
 *
 * <ul>
 *   <li>The <b>length needs no round trip</b> - it stands in the row next to
 *       the locator. A driver that asks the server for it pays a round trip it
 *       does not owe.
 *   <li>The answer to a large read <b>spans many packets</b>. Only the last
 *       one carries the end flag; the ones before it are raw continuation and
 *       carry no message type at all.
 * </ul>
 */
public final class TtcLob {

    /** LOB operations. */
    public static final int FUNCTION = 96;

    /** Read part or all of a LOB. */
    public static final int OP_READ = 0x0002;

    /**
     * Ask how long a LOB is.
     *
     * <p>The same message as a read, with the code changed and offset and
     * amount at zero - every byte of it accounted for against a recording, not
     * reasoned by analogy. The answer carries the length behind the returned
     * locator.
     *
     * <p>Two more codes are measured and written down in
     * {@code docs/protocol/oracle-lob.md} but not built: write (0x0040) and
     * create temporary (0x0110).
     */
    public static final int OP_GET_LENGTH = 0x0001;

    /** A locator is always this long. */
    public static final int LOCATOR_LENGTH = 112;

    /**
     * The locator plus the two bytes that announce it.
     *
     * <p>The same 114 shows up three times in a recorded call - twice as a
     * number, once as a plain byte - which is what identified it.
     */
    private static final int DESCRIPTOR_LENGTH = LOCATOR_LENGTH + 2;

    /** Read everything from the offset on. */
    public static final long ALL = 0xFFFFFFFFL;

    /** A value that arrives in pieces, each with its own length in front. */
    private static final int CHUNKED = 0xfe;

    private TtcLob() {
    }

    /**
     * Asks for {@code amount} units from {@code offset} on - characters for a
     * {@code CLOB}, bytes for a {@code BLOB}.
     *
     * <p>Oracle counts from 1. Passing 0 as the offset yields nothing, which
     * looks exactly like an empty value and is the kind of mistake that costs
     * an afternoon.
     *
     * @param source where the locator lies
     * @param at     its first byte within {@code source}
     */
    public static void sendRead(NsChannel channel, int sequence, WireBuffer source, int at,
                                long offset, long amount) throws IOException {
        putRead(channel.beginData(), sequence, source, at, offset, amount);
        channel.sendData();
    }

    /**
     * Creates a temporary LOB on the server and returns nothing - the locator
     * comes back in the answer.
     *
     * <p>The message is transcribed from a recording rather than reasoned out.
     * Between the header and the trailing character set sit seventeen bytes
     * that are the same in every recorded create; they are written as they were
     * measured, because a field one does not understand is not a field one may
     * shorten. Only two things vary, and both were seen varying: a flag that is
     * 1 for a CLOB and 0 for a BLOB, and the type - 112 or 113.
     *
     * <p>The locator that comes back is <b>38 bytes</b>, not the 112 of a
     * persistent one, which is why nothing here assumes a length.
     */
    public static void sendCreateTemporary(NsChannel channel, int sequence, boolean character,
                                           int characterSet) throws IOException {
        WireBuffer out = channel.beginData();
        out.putByte((byte) TtcMessage.TYPE_FUNCTION);
        out.putByte((byte) FUNCTION);
        out.putByte((byte) sequence);
        for (int value : CREATE_TEMPORARY_PREFIX) {
            out.putByte((byte) value);
        }
        TtcParameters.putNumber(out, character ? 1 : 0);
        TtcParameters.putNumber(out, character ? 112 : 113);
        out.putZeroes(47);
        TtcParameters.putNumber(out, characterSet);
        channel.sendData();
    }

    /**
     * The bytes between the header and the type of a create call, exactly as
     * they were recorded. Not decoded field by field on purpose: they never
     * changed across the recordings, and inventing names for them would suggest
     * an understanding that is not there.
     */
    private static final int[] CREATE_TEMPORARY_PREFIX = {
        0x00, 0x01, 0x01, 0x28, 0x00, 0x01, 0x0a, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x02, 0x01, 0x10, 0x00, 0x00
    };

    /** Asks for the length - see {@link #OP_GET_LENGTH}. */
    public static void sendLength(NsChannel channel, int sequence, WireBuffer source, int at)
            throws IOException {
        put(channel.beginData(), sequence, OP_GET_LENGTH, source, at, 0, 0);
        channel.sendData();
    }

    /** The message itself - separate so that it can be compared against a recording. */
    public static void putRead(WireBuffer out, int sequence, WireBuffer source, int at,
                               long offset, long amount) {
        put(out, sequence, OP_READ, source, at, offset, amount);
    }

    private static void put(WireBuffer out, int sequence, int operation, WireBuffer source,
                            int at, long offset, long amount) {
        out.putByte((byte) TtcMessage.TYPE_FUNCTION);
        out.putByte((byte) FUNCTION);
        out.putByte((byte) sequence);

        TtcParameters.putNumber(out, 0);                  // token number
        out.putByte((byte) 1);                            // a source locator follows
        TtcParameters.putNumber(out, DESCRIPTOR_LENGTH);
        out.putZeroes(7);                                 // no destination locator
        TtcParameters.putNumber(out, operation);
        out.putZeroes(2);
        TtcParameters.putNumber(out, offset);
        out.putByte((byte) 0);
        out.putByte((byte) 1);                            // an amount follows
        out.putZeroes(7);

        out.putByte((byte) LOCATOR_LENGTH);
        out.putBytes(source.segment(), at, LOCATOR_LENGTH);

        TtcParameters.putNumber(out, amount);
    }

    /**
     * Reads one answer into {@code sink} and hands the rest of the walk to
     * {@link TtcResult}, which owns error and status handling.
     *
     * <p>The answer is a {@code LOB_DATA} message with the contents, a
     * {@code PARAMETER} message that returns the locator and how much was
     * actually read, and then the usual closing status. The last of those is
     * an {@code ORA-01403} often enough - and that is not a failure but the
     * end of the data, the same convention as everywhere else in this
     * protocol.
     *
     * @param sink grows to hold the contents; never a heap array
     * @return the parsed tail, for the error it may carry
     */
    public static Answer read(WireBuffer in, int at, int end, WireBuffer sink)
            throws SQLException {
        int p = at;
        long reported = -1;
        int locatorAt = -1;
        int locatorLength = 0;
        while (p < end) {
            int type = in.getByte(p) & 0xff;
            if (type == TtcMessage.TYPE_LOB_DATA) {
                p = readData(in, p + 1, end, sink);
            } else if (type == TtcMessage.TYPE_PARAMETER) {
                Returned returned = readReturned(in, p + 1);
                reported = returned.value();
                locatorAt = returned.locatorAt();
                locatorLength = returned.locatorLength();
                p = returned.end();
            } else {
                break;
            }
        }
        TtcResult tail = new TtcResult();
        tail.read(in, p, end, null);
        return new Answer(tail, reported, locatorAt, locatorLength);
    }

    /**
     * What came back: the parsed tail, the number the server put behind the
     * locator - how much it really gave us, or, for a length call, the length -
     * and where the returned locator lies, for a create.
     */
    public record Answer(TtcResult tail, long reported, int locatorAt, int locatorLength) {
    }

    private record Returned(long value, int locatorAt, int locatorLength, int end) {
    }

    /** The contents: one length and the bytes, or a chain of chunks. */
    private static int readData(WireBuffer in, int at, int end, WireBuffer sink) {
        int p = at;
        int length = in.getByte(p) & 0xff;
        p++;
        if (length != CHUNKED) {
            if (length > 0) {
                append(sink, in, p, length);
                p += length;
            }
            return p;
        }
        while (p < end) {
            int lengthOfLength = in.getByte(p) & 0xff;
            p++;
            long chunk = 0;
            for (int i = 0; i < lengthOfLength; i++) {
                chunk = (chunk << 8) | (in.getByte(p + i) & 0xff);
            }
            p += lengthOfLength;
            if (chunk == 0) {
                break;                                    // the chain ends on a zero length
            }
            append(sink, in, p, chunk);
            p += (int) chunk;
        }
        return p;
    }

    private static void append(WireBuffer sink, WireBuffer in, int at, long length) {
        sink.ensureCapacity(sink.position() + (int) length);
        sink.putBytes(in.segment(), at, length);
    }

    /**
     * The server sends the locator back, unchanged, and then how much it
     * really gave us. Neither is needed for a read that asked for everything,
     * so both are walked over - but the shape has to be right, or the closing
     * status would be read from the middle of a locator.
     */
    private static Returned readReturned(WireBuffer in, int at) {
        int p = at;
        p++;                                              // a zero byte
        int length = in.getByte(p) & 0xff;
        p++;
        int locatorAt = p;
        p += length;                                      // the locator itself
        int digits = in.getByte(p) & 0xff;
        long value = 0;
        for (int i = 0; i < digits; i++) {
            value = (value << 8) | (in.getByte(p + 1 + i) & 0xff);
        }
        return new Returned(value, locatorAt, length, p + 1 + digits);
    }
}
