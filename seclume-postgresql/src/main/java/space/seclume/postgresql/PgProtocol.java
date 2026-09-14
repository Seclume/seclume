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

    private PgProtocol() {
    }
}
