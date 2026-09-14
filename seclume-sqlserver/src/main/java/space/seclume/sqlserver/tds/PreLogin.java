package space.seclume.sqlserver.tds;

import java.io.IOException;

import space.seclume.internal.WireBuffer;

/**
 * The first exchange with a SQL Server: PRELOGIN.
 *
 * <p>Both sides state their version and say whether they want to encrypt. The
 * layout is a small table: per option one token byte, an offset and a length
 * (both big-endian), terminated by {@code 0xFF} - and after that the values
 * themselves.
 *
 * <p>The answer to the encryption question decides everything that follows:
 *
 * <ul>
 *   <li>{@link Tds#ENCRYPT_OFF} - only the login is encrypted, everything
 *       after it runs in the clear.</li>
 *   <li>{@link Tds#ENCRYPT_ON}/{@link Tds#ENCRYPT_REQ} - the whole connection
 *       is encrypted.</li>
 *   <li>{@link Tds#ENCRYPT_NOT_SUP} - the server cannot do it.</li>
 * </ul>
 *
 * <p>With SQL Server this is no side issue: the password encoding in LOGIN7 is
 * reversible (see {@code TdsPassword}). Without encryption, a capture of the
 * login packet is equivalent to the password.
 *
 * <p>Follows {@code MS-TDS}, the open specification - nothing here is derived
 * or guessed.
 */
public final class PreLogin {

    /** The version number the client reports for itself. */
    private static final int CLIENT_MAJOR = 16;
    private static final int CLIENT_MINOR = 0;
    private static final int CLIENT_BUILD = 1000;

    private int encryption = Tds.ENCRYPT_NOT_SUP;
    private int serverMajor;
    private int serverMinor;
    private int serverBuild;

    /** Built empty; {@link #exchange} fills it from the answer. */
    public PreLogin() {
    }

    /**
     * Sends the PRELOGIN and reads the answer.
     *
     * @param requestEncryption what the client wants - {@link Tds#ENCRYPT_ON}
     *                          or {@link Tds#ENCRYPT_OFF}
     */
    public void exchange(TdsChannel channel, int requestEncryption) throws IOException {
        WireBuffer out = channel.begin();
        int tableStart = out.position();
        // Three options, five bytes each, then the terminator byte.
        int optionCount = 3;
        int valuesAt = tableStart + optionCount * 5 + 1;

        writeOption(out, Tds.PRELOGIN_VERSION, valuesAt - tableStart, 6);
        writeOption(out, Tds.PRELOGIN_ENCRYPTION, valuesAt - tableStart + 6, 1);
        writeOption(out, Tds.PRELOGIN_MARS, valuesAt - tableStart + 7, 1);
        out.putByte((byte) Tds.PRELOGIN_TERMINATOR);

        // Values: version (6), encryption (1), MARS (1).
        out.putByte((byte) CLIENT_MAJOR);
        out.putByte((byte) CLIENT_MINOR);
        out.putByte((byte) (CLIENT_BUILD >>> 8));
        out.putByte((byte) CLIENT_BUILD);
        out.putShort((short) 0);                   // sub-version
        out.putByte((byte) requestEncryption);
        out.putByte((byte) 0);                     // MARS: no

        channel.send(Tds.TYPE_PRELOGIN);
        read(channel);
    }

    /** One entry of the option table: token, offset, length. */
    private static void writeOption(WireBuffer out, int token, int offset, int length) {
        out.putByte((byte) token);
        out.putByte((byte) (offset >>> 8));
        out.putByte((byte) offset);
        out.putByte((byte) (length >>> 8));
        out.putByte((byte) length);
    }

    private void read(TdsChannel channel) throws IOException {
        int type = channel.receive();
        if (type != Tds.TYPE_TABULAR_RESULT && type != Tds.TYPE_PRELOGIN) {
            throw new IOException("expected a PRELOGIN answer, got type 0x"
                    + Integer.toHexString(type));
        }
        WireBuffer in = channel.message();
        int length = channel.messageLength();

        // Walk the option table and pick up the two values that matter.
        int at = 0;
        while (at + 1 <= length) {
            int token = in.getByte(at) & 0xff;
            if (token == Tds.PRELOGIN_TERMINATOR) {
                break;
            }
            if (at + 5 > length) {
                throw new IOException("the PRELOGIN answer ends inside its option table");
            }
            int offset = ((in.getByte(at + 1) & 0xff) << 8) | (in.getByte(at + 2) & 0xff);
            int valueLength = ((in.getByte(at + 3) & 0xff) << 8) | (in.getByte(at + 4) & 0xff);
            if (offset + valueLength > length) {
                throw new IOException("the PRELOGIN answer points past its own end");
            }
            switch (token) {
                case Tds.PRELOGIN_VERSION -> {
                    if (valueLength >= 6) {
                        serverMajor = in.getByte(offset) & 0xff;
                        serverMinor = in.getByte(offset + 1) & 0xff;
                        serverBuild = ((in.getByte(offset + 2) & 0xff) << 8)
                                | (in.getByte(offset + 3) & 0xff);
                    }
                }
                case Tds.PRELOGIN_ENCRYPTION -> {
                    if (valueLength >= 1) {
                        encryption = in.getByte(offset) & 0xff;
                    }
                }
                default -> {
                    // Everything else is of no interest to this driver.
                }
            }
            at += 5;
        }
    }

    /** What the server says about encryption. */
    public int encryption() {
        return encryption;
    }

    /** Whether the server can encrypt at all. */
    public boolean supportsEncryption() {
        return encryption != Tds.ENCRYPT_NOT_SUP;
    }

    /** Whether the server insists on encryption. */
    public boolean requiresEncryption() {
        return encryption == Tds.ENCRYPT_REQ;
    }

    public int serverMajor() {
        return serverMajor;
    }

    public int serverMinor() {
        return serverMinor;
    }

    public int serverBuild() {
        return serverBuild;
    }

    /** The server version in readable form - for example {@code 16.0.4215}. */
    public String serverVersion() {
        return serverMajor + "." + serverMinor + "." + serverBuild;
    }
}
