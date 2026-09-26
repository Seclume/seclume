package space.seclume.sqlserver.tds;

/**
 * The constants of TDS 7.4.
 *
 * <p>A pleasant contrast to Oracle: TDS is openly specified ({@code MS-TDS}).
 * Nothing here is guessed or derived from someone else's implementation - it
 * all comes from a document Microsoft publishes.
 *
 * <p>A TDS packet starts with eight bytes:
 *
 * <pre>
 *   0     type
 *   1     status (bit 0 = last packet of a message)
 *   2..3  length including the header, <b>big-endian</b>
 *   4..5  SPID
 *   6     packet number
 *   7     window (always 0)
 * </pre>
 *
 * <p>That big-endian length is the trap: everything else in TDS is
 * little-endian, only the packet header is not.
 */
public final class Tds {

    /** Length of the packet header. */
    public static final int HEADER_SIZE = 8;
    /** Default packet size; the server may change it in the login answer. */
    public static final int DEFAULT_PACKET_SIZE = 4096;
    /** What the login asks for: the most TDS allows. */
    public static final int REQUESTED_PACKET_SIZE = 32767;

    // ---- packet types ----------------------------------------------------

    /** A statement as text. */
    public static final int TYPE_SQL_BATCH = 0x01;
    /** Login. */
    public static final int TYPE_LOGIN7 = 0x10;
    /** An integrated login's next token, after LOGIN7 (MS-TDS 2.2.1.12). */
    public static final int TYPE_SSPI = 0x11;
    /** Remote procedure call - this is how prepared statements run. */
    public static final int TYPE_RPC = 0x03;
    /** The server's answer: a stream of tokens. */
    public static final int TYPE_TABULAR_RESULT = 0x04;
    /** Cancels the running statement - what sits behind {@code cancel()}. */
    public static final int TYPE_ATTENTION = 0x06;
    /** Bulk load data - the rows of an {@code INSERT BULK}. */
    public static final int TYPE_BULK_LOAD = 0x07;
    /** Transaction control. */
    public static final int TYPE_TRANSACTION_MANAGER = 0x0e;

    /** Imports a coordinator's transaction and answers with its descriptor. */
    public static final int TM_PROPAGATE_XACT = 1;
    /** The first exchange: versions, and whether to encrypt. */
    public static final int TYPE_PRELOGIN = 0x12;

    /** Status bit: last packet of this message. */
    public static final int STATUS_END_OF_MESSAGE = 0x01;

    // ---- PRELOGIN options ------------------------------------------------

    public static final int PRELOGIN_VERSION = 0x00;
    public static final int PRELOGIN_ENCRYPTION = 0x01;
    public static final int PRELOGIN_INSTOPT = 0x02;
    public static final int PRELOGIN_THREADID = 0x03;
    public static final int PRELOGIN_MARS = 0x04;
    public static final int PRELOGIN_TRACEID = 0x05;
    public static final int PRELOGIN_FEDAUTHREQUIRED = 0x06;
    public static final int PRELOGIN_NONCE = 0x08;
    public static final int PRELOGIN_TERMINATOR = 0xff;

    // ---- encryption negotiation ------------------------------------------

    /** The client can encrypt but does not insist. */
    public static final int ENCRYPT_OFF = 0x00;
    /** The client wants encryption. */
    public static final int ENCRYPT_ON = 0x01;
    /** The server does not allow encryption. */
    public static final int ENCRYPT_NOT_SUP = 0x02;
    /** The server insists on it. */
    public static final int ENCRYPT_REQ = 0x03;

    // ---- tokens in the answer stream -------------------------------------

    /** A change to the session state: database, language, packet size. */
    public static final int TOKEN_ENVCHANGE = 0xe3;
    /** An error from the server. */
    public static final int TOKEN_ERROR = 0xaa;
    /** A message that is not an error. */
    public static final int TOKEN_INFO = 0xab;
    /** The server's identification after a successful login. */
    public static final int TOKEN_LOGIN_ACK = 0xad;
    /** Description of a result's columns. */
    public static final int TOKEN_COLMETADATA = 0x81;
    /** A result row. */
    public static final int TOKEN_ROW = 0xd1;
    /** A result row with a bitmask for its NULL values. */
    public static final int TOKEN_NBCROW = 0xd2;
    /** End of a result. */
    public static final int TOKEN_DONE = 0xfd;
    /** End of a procedure. */
    public static final int TOKEN_DONE_PROC = 0xfe;
    /** End of a statement inside a batch. */
    public static final int TOKEN_DONE_IN_PROC = 0xff;
    /** The sort order of a result - of no interest, but it has to be skipped. */
    public static final int TOKEN_ORDER = 0xa9;
    /** Which table a column came from - a cursor result carries these. */
    public static final int TOKEN_TABNAME = 0xa4;
    public static final int TOKEN_COLINFO = 0xa5;
    /** A procedure's output value. */
    public static final int TOKEN_RETURN_VALUE = 0xac;
    /** The nullable integer type, as a RETURNVALUE carries it. */
    public static final int TYPE_INTN = 0x26;
    /** A procedure's return status. */
    public static final int TOKEN_RETURN_STATUS = 0x79;
    /** The server acknowledges the requested feature extensions. */
    public static final int TOKEN_FEATURE_EXT_ACK = 0xae;
    /** The server's token in an integrated login. */
    public static final int TOKEN_SSPI = 0xed;

    /** TDS 7.4 - the level this driver speaks (SQL Server 2012 and newer). */
    public static final int VERSION_7_4 = 0x74000004;

    private Tds() {
    }

    /** A token's name - for error messages, not for logic. */
    public static String tokenName(int token) {
        return switch (token) {
            case TOKEN_ENVCHANGE -> "ENVCHANGE";
            case TOKEN_SSPI -> "SSPI";
            case TOKEN_ERROR -> "ERROR";
            case TOKEN_INFO -> "INFO";
            case TOKEN_LOGIN_ACK -> "LOGINACK";
            case TOKEN_COLMETADATA -> "COLMETADATA";
            case TOKEN_ROW -> "ROW";
            case TOKEN_NBCROW -> "NBCROW";
            case TOKEN_DONE -> "DONE";
            case TOKEN_DONE_PROC -> "DONEPROC";
            case TOKEN_DONE_IN_PROC -> "DONEINPROC";
            case TOKEN_ORDER -> "ORDER";
            case TOKEN_TABNAME -> "TABNAME";
            case TOKEN_COLINFO -> "COLINFO";
            case TOKEN_RETURN_VALUE -> "RETURNVALUE";
            case TOKEN_RETURN_STATUS -> "RETURNSTATUS";
            case TOKEN_FEATURE_EXT_ACK -> "FEATUREEXTACK";
            default -> "unknown(0x" + Integer.toHexString(token) + ")";
        };
    }
}
