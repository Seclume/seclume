package space.seclume.sqlserver.tds;

import java.io.IOException;
import java.sql.SQLException;

import space.seclume.internal.WireBuffer;

/**
 * The answer to LOGIN7 - a stream of tokens.
 *
 * <p>SQL Server does not answer with one message but with a sequence of
 * tokens, each starting with a token byte. Four of them matter for the login:
 *
 * <ul>
 *   <li>{@link Tds#TOKEN_LOGIN_ACK} - logged in, with server name and version.</li>
 *   <li>{@link Tds#TOKEN_ENVCHANGE} - changes to the session state, such as the
 *       database or the packet size. The latter matters: the server may set it
 *       here, and the client has to abide by it.</li>
 *   <li>{@link Tds#TOKEN_ERROR} - the login failed.</li>
 *   <li>{@link Tds#TOKEN_DONE} - the end.</li>
 * </ul>
 */
public final class LoginResponse {

    private boolean loggedIn;
    private String serverName = "";
    private int serverVersion;
    private String database = "";
    private int packetSize;
    private SQLException failure;

    /** Built empty; {@link #read} fills it from the answer. */
    public LoginResponse() {
    }

    /** Reads the answer and evaluates it. */
    public void read(TdsChannel channel) throws IOException {
        int type = channel.receive();
        if (type != Tds.TYPE_TABULAR_RESULT) {
            throw new IOException("expected a login answer, got type 0x"
                    + Integer.toHexString(type));
        }
        WireBuffer in = channel.message();
        int length = channel.messageLength();
        int at = 0;

        while (at < length) {
            int token = in.getByte(at) & 0xff;
            at++;
            switch (token) {
                case Tds.TOKEN_LOGIN_ACK -> at = readLoginAck(in, at);
                case Tds.TOKEN_ENVCHANGE -> at = readEnvChange(in, at);
                case Tds.TOKEN_ERROR -> at = readError(in, at, true);
                case Tds.TOKEN_INFO -> at = readError(in, at, false);
                case Tds.TOKEN_FEATURE_EXT_ACK -> at = skipFeatureExtAck(in, at);
                case Tds.TOKEN_SSPI -> at = readSspi(in, at, length);
                case Tds.TOKEN_DONE, Tds.TOKEN_DONE_PROC, Tds.TOKEN_DONE_IN_PROC -> at += 12;
                default -> throw new IOException(
                        "unexpected token " + Tds.tokenName(token) + " in the login answer");
            }
        }
    }

    /** The server's token of an integrated login - protocol data, the proof of a key. */
    private byte[] sspi;

    /** The SSPI token of this answer, or null. */
    public byte[] sspi() {
        return sspi;
    }

    private int readSspi(WireBuffer in, int at, int limit) throws IOException {
        int tokenLength = readUShort(in, at);
        if (at + 2 + tokenLength > limit) {
            throw new IOException("an SSPI token runs past the end of the login answer");
        }
        sspi = new byte[tokenLength]; // seclume-allow: a Kerberos token (AP-REP), not a secret
        for (int i = 0; i < tokenLength; i++) {
            sspi[i] = in.getByte(at + 2 + i);
        }
        return at + 2 + tokenLength;
    }

    private int readLoginAck(WireBuffer in, int at) {
        int tokenLength = readUShort(in, at);
        int end = at + 2 + tokenLength;
        int p = at + 2;
        p++;                                    // interface
        serverVersion = readInt(in, p);
        p += 4;
        int nameChars = in.getByte(p) & 0xff;
        p++;
        serverName = readUtf16(in, p, nameChars);
        loggedIn = true;
        return end;
    }

    /**
     * Changes to the session state. Only two of them matter while connecting:
     * the database and the packet size.
     */
    private int readEnvChange(WireBuffer in, int at) {
        int tokenLength = readUShort(in, at);
        int end = at + 2 + tokenLength;
        int p = at + 2;
        int kind = in.getByte(p) & 0xff;
        p++;
        int newChars = in.getByte(p) & 0xff;
        p++;
        String newValue = readUtf16(in, p, newChars);
        switch (kind) {
            case 1 -> database = newValue;      // database
            case 4 -> {                         // packet size
                try {
                    packetSize = Integer.parseInt(newValue.trim());
                } catch (NumberFormatException e) {
                    packetSize = 0;
                }
            }
            default -> {
                // Language, collation, transactions - of no concern here.
            }
        }
        return end;
    }

    /** An error or a message: number, severity, text. */
    private int readError(WireBuffer in, int at, boolean isError) {
        int tokenLength = readUShort(in, at);
        int end = at + 2 + tokenLength;
        int p = at + 2;
        int number = readInt(in, p);
        p += 4;
        p++;                                    // status
        int severity = in.getByte(p) & 0xff;
        p++;
        int messageChars = readUShort(in, p);
        p += 2;
        String message = readUtf16(in, p, messageChars);
        if (isError && failure == null) {
            // TDS carries no SQLState; 28000 is the fitting one for a
            // rejected login, otherwise it stays generic.
            String sqlState = number == 18456 ? "28000" : "S0001";
            failure = new SQLException(message + " (error " + number
                    + ", severity " + severity + ")", sqlState, number);
        }
        return end;
    }

    private int skipFeatureExtAck(WireBuffer in, int at) {
        int p = at;
        while (true) {
            int feature = in.getByte(p) & 0xff;
            p++;
            if (feature == 0xff) {
                return p;
            }
            int dataLength = readInt(in, p);
            p += 4 + dataLength;
        }
    }

    private static int readUShort(WireBuffer in, int at) {
        return (in.getByte(at) & 0xff) | ((in.getByte(at + 1) & 0xff) << 8);
    }

    private static int readInt(WireBuffer in, int at) {
        return (in.getByte(at) & 0xff)
                | ((in.getByte(at + 1) & 0xff) << 8)
                | ((in.getByte(at + 2) & 0xff) << 16)
                | ((in.getByte(at + 3) & 0xff) << 24);
    }

    /** UTF-16LE from the buffer; {@code chars} is the number of characters. */
    private static String readUtf16(WireBuffer in, int at, int chars) {
        char[] text = new char[chars]; // seclume-allow: server name and messages, protocol text and never a secret
        for (int i = 0; i < chars; i++) {
            text[i] = (char) ((in.getByte(at + i * 2) & 0xff)
                    | ((in.getByte(at + i * 2 + 1) & 0xff) << 8));
        }
        return new String(text); // seclume-allow: protocol text, never a secret
    }

    /** Whether the login succeeded. */
    public boolean isLoggedIn() {
        return loggedIn;
    }

    /** The error from the server, if there was one. */
    public SQLException failure() {
        return failure;
    }

    public String serverName() {
        return serverName;
    }

    public int serverVersion() {
        return serverVersion;
    }

    /** The database the session ended up in. */
    public String database() {
        return database;
    }

    /** The packet size the server settled on; 0 means unchanged. */
    public int packetSize() {
        return packetSize;
    }
}
