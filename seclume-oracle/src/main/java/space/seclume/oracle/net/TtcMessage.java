package space.seclume.oracle.net;

/**
 * The message types of TTC - the protocol that sits <i>inside</i> the DATA
 * packets of Oracle Net.
 *
 * <p>Oracle thereby has two layers on top of each other: NS handles the
 * connection and the packet sizes, TTC handles everything to do with the
 * database. A TTC exchange always starts with one of these type bytes.
 *
 * <p>Derived from python-oracledb v4.0.2; see {@code PROVENANCE.md}.
 */
public final class TtcMessage {

    /** Protocol negotiation - the first thing after the ACCEPT. */
    public static final int TYPE_PROTOCOL = 1;
    /** Negotiation of how data types are represented. */
    public static final int TYPE_DATA_TYPES = 2;
    /** A function call: log in, parse, execute, fetch. */
    public static final int TYPE_FUNCTION = 3;
    /** An error from the server. */
    public static final int TYPE_ERROR = 4;
    /** The header of a result row. */
    public static final int TYPE_ROW_HEADER = 6;
    /** The data of a result row. */
    public static final int TYPE_ROW_DATA = 7;
    /** Key-value pairs - this is how the login data travels there and back. */
    public static final int TYPE_PARAMETER = 8;
    /** The end of a call, with its return value. */
    public static final int TYPE_STATUS = 9;
    /**
     * The in/out vector of a PL/SQL call - which binds the server is writing
     * back. It arrives in front of their values and has to be stepped over,
     * or the values behind it are never read.
     */
    public static final int TYPE_IO_VECTOR = 11;

    /** The description of a value. */
    public static final int TYPE_OAC = 13;
    /**
     * The contents of a LOB, as the answer to function 96.
     *
     * <p>One length and the bytes, or - for anything larger than a chunk - a
     * chain of chunks that ends on a zero length and runs on across packet
     * boundaries.
     */
    public static final int TYPE_LOB_DATA = 14;
    /**
     * The bit vector on its own.
     *
     * <p>Between rows the server sends this instead of a whole row header when
     * only the "unchanged" information has changed. Whoever does not know this
     * message stops after the first block of rows and thinks the result is
     * over - which is exactly what happened here before it was handled.
     */
    public static final int TYPE_BIT_VECTOR = 21;
    /** A warning, not an error. */
    public static final int TYPE_WARNING = 15;
    /** The description of a result. */
    public static final int TYPE_DESCRIBE_INFO = 16;
    /** End of the answer. */
    public static final int TYPE_END_OF_RESPONSE = 29;
    /** Login in one go - newer servers can do this. */
    public static final int TYPE_FAST_AUTH = 34;

    // ---- function numbers ------------------------------------------------

    /**
     * The first login stage: the client names the user, the server answers
     * with {@code AUTH_SESSKEY} and {@code AUTH_VFR_DATA}.
     */
    public static final int FUNC_AUTH_PHASE_ONE = 118;
    /**
     * The second login stage: the client sends {@code AUTH_PASSWORD}. Only
     * here does something derived from the password leave the process - which
     * is exactly why the way there has to be off-heap.
     */
    public static final int FUNC_AUTH_PHASE_TWO = 115;

    /** Length of the capability arrays both sides exchange. */
    public static final int COMPILE_CAPABILITIES = 53;
    public static final int RUNTIME_CAPABILITIES = 11;

    private TtcMessage() {
    }

    /** The name of a message type - for error messages. */
    public static String typeName(int type) {
        return switch (type) {
            case TYPE_PROTOCOL -> "PROTOCOL";
            case TYPE_DATA_TYPES -> "DATA_TYPES";
            case TYPE_FUNCTION -> "FUNCTION";
            case TYPE_ERROR -> "ERROR";
            case TYPE_ROW_HEADER -> "ROW_HEADER";
            case TYPE_ROW_DATA -> "ROW_DATA";
            case TYPE_PARAMETER -> "PARAMETER";
            case TYPE_STATUS -> "STATUS";
            case TYPE_OAC -> "OAC";
            case TYPE_LOB_DATA -> "LOB_DATA";
            case TYPE_BIT_VECTOR -> "BITVECTOR";
            case TYPE_WARNING -> "WARNING";
            case TYPE_DESCRIBE_INFO -> "DESCRIBE_INFO";
            case TYPE_END_OF_RESPONSE -> "END_OF_RESPONSE";
            case TYPE_FAST_AUTH -> "FAST_AUTH";
            default -> "unknown(" + type + ")";
        };
    }

    /** Ends the transaction and keeps the work. */
    public static final int FUNCTION_COMMIT = 14;

    /** Ends the transaction and throws the work away. */
    public static final int FUNCTION_ROLLBACK = 15;
}
