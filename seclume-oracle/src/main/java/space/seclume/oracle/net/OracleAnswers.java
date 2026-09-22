package space.seclume.oracle.net;

import space.seclume.internal.AnswerBoundary;

/**
 * Oracle's answer boundary: the NS packet that says it is the last one.
 *
 * <p>This looked, for an afternoon, like the hardest of the four. The end of a
 * call in TTC can only be found by walking the messages - they carry no length
 * of their own, a row's size depends on the description that came before it,
 * and this driver's own reader switches on seven types to get through one
 * answer. A relay repeating that walk would be the same reader twice.
 *
 * <p><b>It does not have to.</b> The transport layer underneath states it: bit
 * {@code 0x2000} of a DATA packet's data flags marks the last packet of an
 * answer, which is exactly what {@code OracleSession} itself reads to know
 * whether it may parse where the bytes lie or has to collect first. So the
 * boundary is the same question the driver already asks, asked one layer down
 * and without parsing anything.
 *
 * <p>The lesson is the older one in this project: the answer was in code that
 * had been read twice, in a constant named after what it does. Looking at what
 * the driver already relies on is cheaper than deriving what a protocol ought
 * to offer.
 *
 * <p><b>The length field is two bytes or four</b>, and which one is a
 * negotiated fact - {@link NsPacket#VERSION_MIN_LARGE_SDU} and above use four.
 * Whoever hands a stream over knows the version; a boundary that guessed would
 * read the first packet at the wrong offset and never recover.
 *
 * <p><b>An answer can also end without any of that.</b> When a statement
 * fails, Oracle does not send the error: it sends a break marker and a reset
 * marker and then waits for the client to answer with a reset of its own -
 * only after that does the error arrive. A relay that read on until an
 * end-of-answer flag would wait for a packet the server will never send until
 * it has been answered, and the driver behind the relay would never see the
 * markers it has to answer. Both sides wait, and the symptom is a hung
 * connection rather than a failed statement. So the reset marker ends an
 * answer too: the pair goes to the driver, whose {@code drainMarkers} answers
 * it, and that answer is the next request.
 *
 * <p>A break marker alone does not end anything - it is the first half of that
 * pair, and ending on it would hand the driver half a conversation.
 */
public final class OracleAnswers implements AnswerBoundary {

    /** The flag on the last packet of an answer - see {@code OracleSession}. */
    private static final int END_OF_ANSWER = 0x2000;

    private final boolean largeLength;

    /** The fixed eight bytes every packet starts with. */
    private final byte[] head = new byte[NsPacket.HEADER_SIZE];
    private int headFilled;

    /**
     * What follows the header and decides whether the answer ends here: a
     * DATA packet's two data flag bytes, or a marker's three body bytes, the
     * last of which says which kind of marker it is.
     */
    private final byte[] extra = new byte[3];
    /** How many of those this packet has - {@code -1} while the header is unread. */
    private int extraWant = -1;
    private int extraFilled;

    private int announced;
    private int remaining;
    private boolean lastOfAnswer;

    /**
     * @param protocolVersion what the two sides negotiated - it decides
     *                        whether the length takes two bytes or four
     */
    public OracleAnswers(int protocolVersion) {
        this.largeLength = NsPacket.hasLargeLength(protocolVersion);
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
                if (remaining == 0 && lastOfAnswer) {
                    return at - offset;
                }
                continue;
            }
            if (extraWant < 0) {
                int take = Math.min(NsPacket.HEADER_SIZE - headFilled, end - at);
                System.arraycopy(data, at, head, headFilled, take);
                headFilled += take;
                at += take;
                if (headFilled < NsPacket.HEADER_SIZE) {
                    return -1;
                }
                headFilled = 0;
                announced = largeLength
                        ? ((head[0] & 0xff) << 24) | ((head[1] & 0xff) << 16)
                                | ((head[2] & 0xff) << 8) | (head[3] & 0xff)
                        : ((head[0] & 0xff) << 8) | (head[1] & 0xff);
                if (announced < NsPacket.HEADER_SIZE) {
                    throw new IllegalStateException(
                            "the server announced a packet of " + announced + " bytes");
                }
                int type = head[4] & 0xff;
                // Never more than the packet holds: a packet too short for
                // what its type usually carries is read as payload rather
                // than mistaken for the next packet's header.
                extraWant = Math.min(switch (type) {
                    case NsPacket.TYPE_DATA -> 2;
                    case NsPacket.TYPE_MARKER -> 3;
                    default -> 0;
                }, announced - NsPacket.HEADER_SIZE);
                extraFilled = 0;
                continue;
            }
            if (extraFilled < extraWant) {
                int take = Math.min(extraWant - extraFilled, end - at);
                System.arraycopy(data, at, extra, extraFilled, take);
                extraFilled += take;
                at += take;
                if (extraFilled < extraWant) {
                    return -1;
                }
            }
            int type = head[4] & 0xff;
            lastOfAnswer = switch (type) {
                case NsPacket.TYPE_DATA -> extraWant == 2
                        && ((((extra[0] & 0xff) << 8) | (extra[1] & 0xff)) & END_OF_ANSWER) != 0;
                // The reset half of the pair a failed statement begins with.
                case NsPacket.TYPE_MARKER -> extraWant == 3
                        && (extra[2] & 0xff) == NsPacket.MARKER_TYPE_RESET;
                default -> false;
            };
            remaining = announced - NsPacket.HEADER_SIZE - extraWant;
            extraWant = -1;
            if (remaining == 0 && lastOfAnswer) {
                return at - offset;
            }
        }
        return -1;
    }

    @Override
    public void reset() {
        headFilled = 0;
        extraWant = -1;
        extraFilled = 0;
        remaining = 0;
        lastOfAnswer = false;
    }
}
