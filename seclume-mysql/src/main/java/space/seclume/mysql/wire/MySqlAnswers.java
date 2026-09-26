package space.seclume.mysql.wire;

import space.seclume.internal.AnswerBoundary;

/**
 * MySQL's answer boundary, which is the hardest of the four.
 *
 * <p>PostgreSQL says when it is at rest: every answer ends with a
 * {@code ReadyForQuery} and nothing else looks like one. MySQL says no such
 * thing. An answer ends with a packet whose first byte is {@code 0x00},
 * {@code 0xff} or {@code 0xfe} - and a <b>row</b> may begin with any of those
 * three, because the first byte of a row is the length of its first value.
 *
 * <p>So the boundary cannot be found by looking at bytes. It has to be counted,
 * in the same three phases the driver reads in:
 *
 * <ol>
 *   <li>the first packet of an answer decides everything: {@code 0xff} is an
 *       error and ends it, {@code 0x00} is an OK and ends it, a short
 *       {@code 0xfe} ends it, and anything else is a <b>column count</b>;
 *   <li>then exactly that many column definitions, which are counted and not
 *       read;
 *   <li>then rows, until a packet that terminates them - and only here does
 *       "short {@code 0xfe}" mean the end, because by now a row is possible
 *       and a row of nine bytes or more that starts with {@code 0xfe} is data.
 * </ol>
 *
 * <p><b>And then it may not be over.</b> With {@code CLIENT_MULTI_RESULTS} -
 * which this driver negotiates, because a procedure returns its results that
 * way - the terminating packet carries a status flag saying another result
 * follows. Reading that flag needs the negotiated capabilities, because
 * {@code DEPRECATE_EOF} moves it: an OK packet carries the status after two
 * length-encoded numbers, an old EOF carries it after the warning count. That
 * is why this class is constructed with the capabilities and not with nothing.
 *
 * <p>The 16 MB rule is the last trap. A payload of {@code 0xffffff} bytes means
 * the logical packet continues in the next one, whose first byte is data rather
 * than a type - so the phase machine must not look at it.
 */
public final class MySqlAnswers implements AnswerBoundary {

    private static final int HEADER = 4;
    private static final int CONTINUES = 0xffffff;

    private static final int OK = 0x00;
    private static final int EOF = 0xfe;
    private static final int ERR = 0xff;

    /** {@code SERVER_MORE_RESULTS_EXISTS}. */
    private static final int MORE_RESULTS = 0x0008;
    /** {@code CLIENT_DEPRECATE_EOF}. */
    private static final int DEPRECATE_EOF = 0x0100_0000;

    private enum Phase { FIRST, COLUMNS, ROWS }

    private final boolean deprecateEof;

    private final byte[] header = new byte[HEADER];
    private int headerFilled;
    private int remaining;
    private boolean continuation;
    /** The payload of the packet being read, kept only while it may be a terminator. */
    private byte[] payload = new byte[0];
    private int payloadFilled;

    private Phase phase = Phase.FIRST;
    private long columnsLeft;

    public MySqlAnswers(int capabilities) {
        this.deprecateEof = (capabilities & DEPRECATE_EOF) != 0;
    }

    @Override
    public int endOfAnswer(byte[] data, int offset, int length) {
        int at = offset;
        int end = offset + length;
        while (at < end) {
            if (remaining > 0 || payloadFilled < payload.length) {
                int take = Math.min(remaining, end - at);
                if (payload.length > 0) {
                    int keep = Math.min(take, payload.length - payloadFilled);
                    System.arraycopy(data, at, payload, payloadFilled, keep);
                    payloadFilled += keep;
                }
                at += take;
                remaining -= take;
                if (remaining == 0 && finishesTheAnswer()) {
                    reset();
                    return at - offset;
                }
                continue;
            }
            int take = Math.min(HEADER - headerFilled, end - at);
            System.arraycopy(data, at, header, headerFilled, take);
            headerFilled += take;
            at += take;
            if (headerFilled < HEADER) {
                return -1;
            }
            headerFilled = 0;
            int announced = (header[0] & 0xff) | ((header[1] & 0xff) << 8)
                    | ((header[2] & 0xff) << 16);
            boolean wasContinuation = continuation;
            continuation = announced == CONTINUES;
            remaining = announced;
            // A packet that carries the tail of a 16 MB value starts with data,
            // so its first byte says nothing about phases.
            payload = !wasContinuation && announced > 0 && announced < 512
                    ? new byte[Math.min(announced, 32)]
                    : new byte[0];
            payloadFilled = 0;
            if (announced == 0) {
                continue;
            }
        }
        return -1;
    }

    /**
     * Whether the packet just read ends the answer, and moves the phase on if
     * it does not.
     */
    private boolean finishesTheAnswer() {
        if (continuation || payload.length == 0) {
            // Long packets are data: a row, or a column definition. Either way
            // it is not a terminator, and in the FIRST phase it is the column
            // count, which a packet that long cannot be.
            return advanceOnData();
        }
        int first = payload[0] & 0xff;
        boolean shortPacket = payloadFilled < 9;
        switch (phase) {
            case FIRST -> {
                if (first == ERR) {
                    return true;
                }
                if (first == OK || (first == EOF && shortPacket)) {
                    return !moreResultsFollow(first);
                }
                columnsLeft = lengthEncoded();
                phase = columnsLeft > 0 ? Phase.COLUMNS : Phase.ROWS;
                return false;
            }
            case COLUMNS -> {
                if (--columnsLeft <= 0) {
                    phase = Phase.ROWS;
                }
                return false;
            }
            default -> {
                if (first == ERR) {
                    return true;
                }
                if (first == EOF && shortPacket) {
                    return !moreResultsFollow(first);
                }
                return false;                        // an ordinary row
            }
        }
    }

    /** A data packet cannot end anything; it can only move the phase on. */
    private boolean advanceOnData() {
        if (phase == Phase.COLUMNS && --columnsLeft <= 0) {
            phase = Phase.ROWS;
        } else if (phase == Phase.FIRST) {
            phase = Phase.ROWS;
        }
        return false;
    }

    /**
     * The status flags of a terminating packet, and where they sit.
     *
     * <p>Two layouts for one question. An OK packet puts the status after the
     * affected rows and the last insert id, both length-encoded; an EOF puts it
     * after a two-byte warning count. {@code DEPRECATE_EOF} decides which shape
     * a {@code 0xfe} packet has, and that is negotiated - hence the
     * capabilities in the constructor.
     */
    private boolean moreResultsFollow(int first) {
        int at = 1;
        if (first == OK || deprecateEof) {
            at = skipLengthEncoded(skipLengthEncoded(at));
        } else {
            at += 2;                                 // the warnings
        }
        if (at + 1 >= payloadFilled) {
            return false;                            // nothing left to read a status from
        }
        int status = (payload[at] & 0xff) | ((payload[at + 1] & 0xff) << 8);
        if ((status & MORE_RESULTS) == 0) {
            return false;
        }
        // Another result set follows in the same answer, and it starts over
        // with a column count.
        phase = Phase.FIRST;
        columnsLeft = 0;
        return true;
    }

    /**
     * The column count at the head of a result set.
     *
     * <p><b>The width is announced by the first byte and the bytes it
     * announces may not be there.</b> A packet holding the single byte
     * {@code 0xfc} says "a two-byte number follows" and then ends, and reading
     * the number walked off the end of the buffer - an
     * {@code ArrayIndexOutOfBoundsException} with no message, from a server
     * that sent five bytes. Found by the fuzz corpus on 23.09.2026, and not by
     * the version of it that flipped bytes to {@code 00 ff 80 5a}: no
     * arbitrary byte is ever {@code 0xfc}, so the corpus had to learn what
     * this protocol's bytes mean before it could express the input that breaks
     * it.
     *
     * <p>Refused rather than guessed, which is what the other three walkers do
     * with a length that cannot be right. A count of zero would have been
     * survivable and wrong: it says "no columns" about a packet whose shape
     * nobody understood, and the phase machine would then read column
     * definitions as rows.
     */
    private long lengthEncoded() {
        int first = payload[0] & 0xff;
        if (first < 0xfb) {
            return first;
        }
        int width = switch (first) {
            case 0xfc -> 2;
            case 0xfd -> 3;
            default -> 0;                            // 0xfe as a count: absurd, treat as one
        };
        if (width == 0) {
            return 1;
        }
        if (payloadFilled < 1 + width) {
            throw new IllegalStateException("the server announced a column count of "
                    + width + " bytes in a packet holding " + payloadFilled);
        }
        long count = 0;
        for (int i = 0; i < width; i++) {
            count |= (payload[1 + i] & 0xffL) << (8 * i);
        }
        return count;
    }

    private int skipLengthEncoded(int at) {
        if (at >= payloadFilled) {
            return at + 1;
        }
        int first = payload[at] & 0xff;
        if (first < 0xfb) {
            return at + 1;
        }
        return switch (first) {
            case 0xfc -> at + 3;
            case 0xfd -> at + 4;
            case 0xfe -> at + 9;
            default -> at + 1;
        };
    }

    @Override
    public void reset() {
        headerFilled = 0;
        remaining = 0;
        continuation = false;
        payload = new byte[0];
        payloadFilled = 0;
        phase = Phase.FIRST;
        columnsLeft = 0;
    }
}
