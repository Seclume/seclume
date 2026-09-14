package space.seclume.oracle.net;

/**
 * The packet layer of Oracle Net Services (NS).
 *
 * <p>Beneath the actual database protocol (TTC), Oracle has a transport layer
 * of its own. Every packet starts with an <b>eight byte</b> header:
 *
 * <pre>
 *   0..3  length (big-endian)   - on older protocol levels only 0..1,
 *                                 in which case 2..3 are filler
 *   4     packet type
 *   5     flags
 *   6..7  filler
 * </pre>
 *
 * <p>Whether the length takes two or four bytes depends on the negotiated
 * protocol level: from {@link #VERSION_MIN_LARGE_SDU} onwards it is four. That
 * is no subtlety - get it wrong and you read nonsense from the second packet
 * on, without an error message, because the bytes happen to look plausible.
 *
 * <p>With a {@link #TYPE_DATA} the header is followed by two more bytes of data
 * flags; only then does the TTC content begin.
 *
 * <p>Derived from python-oracledb v4.0.2 ({@code impl/thin/packet.pyx},
 * {@code impl/thin/constants.pxi}); see {@code docs/protocol/oracle.md} for
 * licence and provenance.
 */
public final class NsPacket {

    /** Length of the packet header. */
    public static final int HEADER_SIZE = 8;
    /** Length of the extra data flags on a DATA packet. */
    public static final int DATA_FLAGS_SIZE = 2;

    // ---- packet types ----------------------------------------------------

    /** The connect request from the client. */
    public static final int TYPE_CONNECT = 1;
    /** The server accepts and names the negotiated sizes. */
    public static final int TYPE_ACCEPT = 2;
    /** The server refuses - with the reason in the content. */
    public static final int TYPE_REFUSE = 4;
    /** The server points at another address (listener, RAC, Data Guard). */
    public static final int TYPE_REDIRECT = 5;
    /** Payload: TTC sits inside this. */
    public static final int TYPE_DATA = 6;
    /** The server asks for the connect request to be sent again. */
    public static final int TYPE_RESEND = 11;
    /** Out of band: break, reset, interrupt. */
    public static final int TYPE_MARKER = 12;

    /** Marker: stop what you are doing. */
    public static final int MARKER_BREAK = 1;
    /** Marker: back to a defined state - this is the one to answer with. */
    public static final int MARKER_RESET = 2;
    /** Marker: an interruption. */
    public static final int MARKER_INTERRUPT = 3;
    /** Control of the connection itself. */
    public static final int TYPE_CONTROL = 14;

    // ---- data flags ------------------------------------------------------

    /** End of the answer - after this the server is done. */
    public static final int DATA_FLAGS_END_OF_RESPONSE = 0x2000;
    /** End of the request. */
    public static final int DATA_FLAGS_END_OF_REQUEST = 0x0800;
    /** The start of a pipeline. */
    public static final int DATA_FLAGS_BEGIN_PIPELINE = 0x1000;
    /** End of file - the server hung up. */
    public static final int DATA_FLAGS_EOF = 0x0040;

    // ---- marker types ----------------------------------------------------

    /** Cancels the running statement - what sits behind {@code cancel()}. */
    public static final int MARKER_TYPE_BREAK = 1;
    /** Reset after a break. */
    public static final int MARKER_TYPE_RESET = 2;
    /** Interrupt. */
    public static final int MARKER_TYPE_INTERRUPT = 3;

    // ---- protocol levels -------------------------------------------------

    /** The level this client aims for. */
    public static final int VERSION_DESIRED = 319;
    /** Anything below this is not supported. */
    public static final int VERSION_MINIMUM = 300;
    /** From here on the header length is four bytes instead of two. */
    public static final int VERSION_MIN_LARGE_SDU = 315;

    private NsPacket() {
    }

    /** Whether the header length field takes four bytes. */
    public static boolean hasLargeLength(int protocolVersion) {
        return protocolVersion >= VERSION_MIN_LARGE_SDU;
    }

    /** The name of a packet type - for error messages, not for logic. */
    public static String typeName(int type) {
        return switch (type) {
            case TYPE_CONNECT -> "CONNECT";
            case TYPE_ACCEPT -> "ACCEPT";
            case TYPE_REFUSE -> "REFUSE";
            case TYPE_REDIRECT -> "REDIRECT";
            case TYPE_DATA -> "DATA";
            case TYPE_RESEND -> "RESEND";
            case TYPE_MARKER -> "MARKER";
            case TYPE_CONTROL -> "CONTROL";
            default -> "unknown(" + type + ")";
        };
    }
}
