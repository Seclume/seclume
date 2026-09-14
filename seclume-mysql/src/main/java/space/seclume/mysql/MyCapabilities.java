package space.seclume.mysql;

/**
 * The capability bits client and server agree on during the handshake.
 *
 * <p>The server says what it can do; the client answers with what of that it
 * intends to use. Both sides go by it - right down into the packet formats:
 * whether an EOF packet or an OK packet follows a result hangs on a single one
 * of these bits.
 *
 * <p>Listed here are the bits this driver really touches. What it cannot do it
 * does not ask for either - a set bit is a promise the server takes at face
 * value.
 */
public final class MyCapabilities {

    /** The server may take the default database from the handshake. */
    public static final int CONNECT_WITH_DB = 0x0000_0008;
    /** Several statements in one {@code COM_QUERY} - deliberately not set. */
    public static final int MULTI_STATEMENTS = 0x0001_0000;
    /** Several results one after the other. */
    public static final int MULTI_RESULTS = 0x0002_0000;
    /** Protocol 4.1 - everything else in this driver presupposes it. */
    public static final int PROTOCOL_41 = 0x0000_0200;
    /** The login runs through a named plugin. */
    public static final int PLUGIN_AUTH = 0x0008_0000;
    /** The 20-byte scramble instead of the old 8-byte scheme. */
    public static final int SECURE_CONNECTION = 0x0000_8000;
    /** The login answer carries a length-encoded length - needed past 255 bytes. */
    public static final int PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x0020_0000;
    /** OK packets arrive instead of EOF packets; saves one packet per result. */
    public static final int DEPRECATE_EOF = 0x0100_0000;
    /** Transaction status in the OK packet. */
    public static final int TRANSACTIONS = 0x0000_2000;
    /** Connection attributes such as the program name. */
    public static final int CONNECT_ATTRS = 0x0010_0000;
    /** {@code LOAD DATA LOCAL INFILE} - deliberately not set, see below. */
    public static final int LOCAL_FILES = 0x0000_0080;
    /** TLS from the next packet on. */
    public static final int SSL = 0x0000_0800;

    /**
     * What this driver asks for.
     *
     * <p>{@link #LOCAL_FILES} is missing on purpose: with that bit the
     * <b>server</b> may ask the client to send an arbitrary local file. A
     * malicious or taken-over server thereby reads {@code /etc/passwd} out of
     * the application container. Whoever needs it has to switch it on
     * explicitly.
     *
     * <p>{@link #MULTI_STATEMENTS} is missing just as much: several statements
     * in one text are the road along which a SQL injection turns into a second
     * command.
     */
    public static final int CLIENT_DEFAULTS =
            PROTOCOL_41 | SECURE_CONNECTION | PLUGIN_AUTH | PLUGIN_AUTH_LENENC_CLIENT_DATA
            | TRANSACTIONS | DEPRECATE_EOF | MULTI_RESULTS | CONNECT_ATTRS;

    private MyCapabilities() {
    }

    /** Whether a bit is set in a set - reads better than the mask. */
    public static boolean has(int capabilities, int bit) {
        return (capabilities & bit) != 0;
    }
}
