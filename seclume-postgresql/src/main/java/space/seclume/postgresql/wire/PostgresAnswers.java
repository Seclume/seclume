package space.seclume.postgresql.wire;

import space.seclume.internal.AnswerBoundary;

/**
 * PostgreSQL's answer boundary: everything up to and including
 * {@code ReadyForQuery}.
 *
 * <p>After the startup phase every message the server sends has the same
 * shape - one byte of type, four bytes of length, then the body - so finding
 * the boundaries needs no knowledge of what any of them mean. The length
 * counts itself, which is the one detail worth getting right and the one that
 * is easy to get wrong by four.
 *
 * <p>{@code ReadyForQuery} is not merely the last message of an answer; it is
 * the server saying the conversation is at rest, and it carries the
 * transaction status while it says so. That makes it the protocol-layer
 * quiescent point: the one place where nothing is half-read, half-written or
 * half-decided, which is why a stream may change hands there and nowhere
 * else.
 */
public final class PostgresAnswers implements AnswerBoundary {

    /** {@code Z} - and the only tag this class has to recognise. */
    private static final byte READY_FOR_QUERY = 'Z';

    /** One type byte and a four-byte length. */
    private static final int HEADER = 5;

    /** One per stream: the state below is what was half seen on it. */
    public PostgresAnswers() {
    }

    private final byte[] header = new byte[HEADER];
    private int headerFilled;
    private long remaining;
    private byte type;

    @Override
    public int endOfAnswer(byte[] data, int offset, int length) {
        int at = offset;
        int end = offset + length;
        while (at < end) {
            if (remaining > 0) {
                int take = (int) Math.min(remaining, end - at);
                at += take;
                remaining -= take;
                if (remaining == 0 && type == READY_FOR_QUERY) {
                    return at - offset;
                }
                continue;
            }
            int take = Math.min(HEADER - headerFilled, end - at);
            System.arraycopy(data, at, header, headerFilled, take);
            headerFilled += take;
            at += take;
            if (headerFilled < HEADER) {
                return -1;                      // a header split across reads
            }
            headerFilled = 0;
            type = header[0];
            int announced = ((header[1] & 0xff) << 24) | ((header[2] & 0xff) << 16)
                    | ((header[3] & 0xff) << 8) | (header[4] & 0xff);
            if (announced < 4) {
                // A length that does not even cover itself is not a message.
                // Refused rather than trusted: a length off the wire handed to
                // an allocator is the classic way a parser is made to hang.
                throw new IllegalStateException(
                        "the server announced a message of " + announced + " bytes");
            }
            remaining = announced - 4L;
            if (remaining == 0 && type == READY_FOR_QUERY) {
                return at - offset;             // no body; cannot happen, and costs nothing
            }
        }
        return -1;
    }

    @Override
    public void reset() {
        headerFilled = 0;
        remaining = 0;
        type = 0;
    }
}
