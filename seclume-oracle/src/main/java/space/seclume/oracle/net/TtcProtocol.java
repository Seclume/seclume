package space.seclume.oracle.net;

import java.io.IOException;

import space.seclume.internal.WireBuffer;

/**
 * The protocol negotiation of TTC - the first exchange after the NS ACCEPT.
 *
 * <p>The client names its protocol level and its name, the server answers with
 * its level, its banner, the character set and two capability arrays.
 * Afterwards both sides know what the other can do.
 *
 * <p>Derived from python-oracledb v4.0.2 and checked against Oracle Free 23ai
 * see {@code docs/protocol/oracle.md}.
 */
public final class TtcProtocol {

    /** Built empty; {@link #negotiate} fills it from the answer. */
    public TtcProtocol() {
    }

    /** Protocol level 6 means "Oracle 8.1 and newer" - still true today. */
    private static final byte CLIENT_VERSION = 6;
    /** The name the server lists the client under. */
    private static final String DRIVER_NAME = "seclume";

    private String serverBanner = "";
    private int serverVersion;
    private int characterSet;

    /**
     * Sends the protocol negotiation and reads the answer.
     *
     * @throws IOException if the server sends anything other than a protocol
     *         answer - then an assumption is wrong, and carrying on would mean
     *         guessing on suspicion
     */
    public void negotiate(NsChannel channel) throws IOException {
        WireBuffer out = channel.beginData();
        out.putByte((byte) TtcMessage.TYPE_PROTOCOL);
        out.putByte(CLIENT_VERSION);
        out.putByte((byte) 0);                     // end of the list
        out.putText(DRIVER_NAME);
        out.putByte((byte) 0);
        channel.sendData();

        int packetType = channel.nextPacket();
        if (packetType != NsPacket.TYPE_DATA) {
            throw new IOException("expected a DATA packet, got "
                    + NsPacket.typeName(packetType));
        }
        WireBuffer in = channel.packet();
        int messageType = in.getByte() & 0xff;
        if (messageType != TtcMessage.TYPE_PROTOCOL) {
            throw new IOException("expected a PROTOCOL message, got "
                    + TtcMessage.typeName(messageType));
        }

        serverVersion = in.getByte() & 0xff;
        in.skip(1);                                // one zero byte
        serverBanner = in.readCString();
        characterSet = (in.getByte() & 0xff) | ((in.getByte() & 0xff) << 8);
        in.skip(1);                                // server flags
        int elements = (in.getByte() & 0xff) | ((in.getByte() & 0xff) << 8);
        if (elements > 0) {
            in.skip(elements * 5);
        }
    }

    /** The banner the server sends about itself - with version and edition. */
    public String serverBanner() {
        return serverBanner;
    }

    public int serverVersion() {
        return serverVersion;
    }

    /** The character set the server assumes for this session. */
    public int characterSet() {
        return characterSet;
    }
}
