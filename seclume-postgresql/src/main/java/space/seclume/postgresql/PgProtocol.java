package space.seclume.postgresql;

/**
 * The markers of frontend protocol 3.0.
 *
 * <p>Single-letter constants with speaking names: that is what the messages are
 * called in the protocol, and anyone reading this code next to the
 * specification finds their way around straight away.
 */
public final class PgProtocol {

    /** 3.0, as major/minor in one 32-bit word. */
    public static final int VERSION_3 = 3 << 16;
    /** The magic "version" of the SSL request: 1234 << 16 | 5679. */
    public static final int SSL_REQUEST = 80877103;
    /** The magic "version" of the cancel request. */
    public static final int CANCEL_REQUEST = 80877102;

    // Frontend
    public static final byte QUERY = 'Q';
    public static final byte PARSE = 'P';
    public static final byte BIND = 'B';
    public static final byte DESCRIBE = 'D';
    public static final byte EXECUTE = 'E';
    public static final byte SYNC = 'S';
    public static final byte CLOSE = 'C';
    public static final byte FLUSH = 'H';
    public static final byte TERMINATE = 'X';
    public static final byte PASSWORD = 'p';   // auch SASLInitialResponse/SASLResponse

    // Backend
    public static final byte AUTHENTICATION = 'R';
    public static final byte PARAMETER_STATUS = 'S';
    public static final byte BACKEND_KEY_DATA = 'K';
    public static final byte READY_FOR_QUERY = 'Z';
    public static final byte ROW_DESCRIPTION = 'T';
    public static final byte DATA_ROW = 'D';
    public static final byte COMMAND_COMPLETE = 'C';
    public static final byte EMPTY_QUERY = 'I';
    public static final byte ERROR_RESPONSE = 'E';
    public static final byte NOTICE_RESPONSE = 'N';
    public static final byte NOTIFICATION_RESPONSE = 'A';
    public static final byte PARSE_COMPLETE = '1';
    public static final byte BIND_COMPLETE = '2';
    public static final byte CLOSE_COMPLETE = '3';
    public static final byte NO_DATA = 'n';
    public static final byte PARAMETER_DESCRIPTION = 't';
    public static final byte PORTAL_SUSPENDED = 's';
    public static final byte COPY_IN_RESPONSE = 'G';
    public static final byte COPY_OUT_RESPONSE = 'H';
    public static final byte COPY_BOTH_RESPONSE = 'W';
    public static final byte COPY_DATA = 'd';
    public static final byte COPY_DONE = 'c';
    public static final byte COPY_FAIL = 'f';

    // codes of the authentication message
    public static final int AUTH_OK = 0;
    public static final int AUTH_KERBEROS_V5 = 2;
    public static final int AUTH_CLEARTEXT = 3;
    public static final int AUTH_MD5 = 5;
    public static final int AUTH_GSS = 7;
    public static final int AUTH_GSS_CONTINUE = 8;
    public static final int AUTH_SSPI = 9;
    public static final int AUTH_SASL = 10;
    public static final int AUTH_SASL_CONTINUE = 11;
    public static final int AUTH_SASL_FINAL = 12;

    /**
     * The name of a message type, for a diagnostic.
     *
     * <p>Both directions in one table, because a tag means one thing going out
     * and another coming back - {@code D} is Describe from the client and
     * DataRow from the server, {@code E} is Execute and ErrorResponse - and a
     * recording that did not say which would be worse than none. The direction
     * is in the record beside it, so the name carries both readings where they
     * differ.
     *
     * <p>A constant per tag and never a byte off the wire turned into text: an
     * unknown tag comes back as its hex, which is what a desynchronised stream
     * produces and exactly what somebody reading the recording needs to see.
     */
    public static String nameOf(byte tag) {
        return switch (tag) {
            case 0 -> "Startup";
            case QUERY -> "Query";
            case PARSE -> "Parse";
            case BIND -> "Bind";
            case 'D' -> "Describe/DataRow";
            case 'E' -> "Execute/ErrorResponse";
            case 'S' -> "Sync/ParameterStatus";
            case 'C' -> "Close/CommandComplete";
            case FLUSH -> "Flush";
            case TERMINATE -> "Terminate";
            case PASSWORD -> "PasswordMessage";
            case AUTHENTICATION -> "Authentication";
            case BACKEND_KEY_DATA -> "BackendKeyData";
            case READY_FOR_QUERY -> "ReadyForQuery";
            case ROW_DESCRIPTION -> "RowDescription";
            case EMPTY_QUERY -> "EmptyQueryResponse";
            case NOTICE_RESPONSE -> "NoticeResponse";
            case NOTIFICATION_RESPONSE -> "NotificationResponse";
            case PARSE_COMPLETE -> "ParseComplete";
            case BIND_COMPLETE -> "BindComplete";
            case CLOSE_COMPLETE -> "CloseComplete";
            case NO_DATA -> "NoData";
            case PARAMETER_DESCRIPTION -> "ParameterDescription";
            case PORTAL_SUSPENDED -> "PortalSuspended";
            default -> "0x" + Integer.toHexString(tag & 0xff);
        };
    }

    private PgProtocol() {
    }
}
