package space.seclume.sqlserver.tds;

import space.seclume.internal.AnswerBoundary;

/**
 * TDS's answer boundary, which the protocol states outright.
 *
 * <p>Every TDS packet begins with eight bytes, and the second of them carries a
 * bit meaning "this is the last packet of this message". A response message is
 * exactly one answer, so the boundary is that bit and nothing else: no tokens
 * are read, no statements counted, no state kept beyond the packet being
 * reassembled.
 *
 * <p><b>Three protocols, three different answers to one question</b>, and the
 * comparison is the reason the interface exists. PostgreSQL states it in a
 * message - {@code ReadyForQuery} - which also says whether a transaction is
 * open. MySQL states it nowhere: an answer ends with a packet whose first byte
 * a row may equally well start with, so it has to be counted through phases.
 * TDS states it in the framing, which is the cheapest place it could be.
 *
 * <p>The one thing worth not getting wrong: a <b>DONE</b> token is not the
 * boundary. A batch or a procedure sends one per statement
 * ({@code DONE_IN_PROC}), and reading those as ends would cut an answer into
 * as many pieces as it has statements - the failure would look like a client
 * receiving somebody else's rows.
 */
public final class SqlServerAnswers implements AnswerBoundary {

    private static final int HEADER = 8;
    /** {@code STATUS_END_OF_MESSAGE}. */
    private static final int END_OF_MESSAGE = 0x01;

    private final byte[] header = new byte[HEADER];
    private int headerFilled;
    private int remaining;
    private boolean last;

    /** One per stream: what is kept is the packet half seen on it. */
    public SqlServerAnswers() {
    }

    @Override
    public int endOfAnswer(byte[] data, int offset, int length) {
        int at = offset;
        int end = offset + length;
        while (at < end) {
            if (remaining > 0) {
                int take = Math.min(remaining, end - at);
                at += take;
                remaining -= take;
                if (remaining == 0 && last) {
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
            last = (header[1] & END_OF_MESSAGE) != 0;
            // Big endian, and the length counts the header with it.
            int announced = ((header[2] & 0xff) << 8) | (header[3] & 0xff);
            if (announced < HEADER) {
                throw new IllegalStateException(
                        "the server announced a TDS packet of " + announced + " bytes");
            }
            remaining = announced - HEADER;
            if (remaining == 0 && last) {
                return at - offset;
            }
        }
        return -1;
    }

    @Override
    public void reset() {
        headerFilled = 0;
        remaining = 0;
        last = false;
    }
}
