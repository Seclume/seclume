package space.seclume.oracle.net;

import java.io.IOException;

import space.seclume.internal.WireBuffer;

/**
 * The whole opening in one packet.
 *
 * <p>{@code FAST_AUTH} bundles what used to take three exchanges: the protocol
 * negotiation, the data-type negotiation and the first login stage. One
 * request, one answer - two round trips saved on every connection, which on a
 * pool that opens connections under load is not a detail.
 *
 * <p>It is also the only way that works. Sent on its own after the classic
 * negotiation, the first login stage is answered by the server with two MARKER
 * packets - a no without a reason. The message is byte for byte the same in
 * both cases; only the wrapper differs. See {@code docs/protocol/oracle.md}.
 *
 * <p>The wrapper:
 *
 * <pre>
 *   1   message type = 34
 *   4   01 01 00 01     - observed, meaning not established
 *   2   06 00           - protocol version 6, end of the list
 *   n   the driver name, with a terminating zero
 *   6   00 00 00 00 00 0d - observed, meaning not established
 *   n   the data-type message, exactly as on its own
 *   n   the first login stage, exactly as on its own
 * </pre>
 *
 * <p>The two byte runs marked "observed" are taken from a recorded handshake
 * and are not interpreted here. That is the same treatment the fixed fields of
 * the CONNECT packet get: written down as seen, marked as seen, and checked
 * against a live server - which is worth more than a plausible-sounding
 * explanation.
 */
public final class TtcFastAuth {

    /** Between the message type and the protocol version. */
    private static final int[] PREFIX = {0x01, 0x01, 0x00, 0x01};
    /** Protocol level 6 means "Oracle 8.1 and newer" - still true today. */
    private static final int[] PROTOCOL_VERSIONS = {0x06, 0x00};
    /** Between the driver name and the data-type message. */
    private static final int[] AFTER_NAME = {0x00, 0x00, 0x00, 0x00, 0x00, 0x0d};

    private TtcFastAuth() {
    }

    /**
     * Sends the combined opening and reads the challenge.
     *
     * @param user the database user; not a secret, and it goes over as text
     */
    public static TtcAuth.Challenge open(NsChannel channel, String driverName, String user)
            throws IOException {
        WireBuffer out = channel.beginData();
        out.putByte((byte) TtcMessage.TYPE_FAST_AUTH);
        putAll(out, PREFIX);
        putAll(out, PROTOCOL_VERSIONS);
        out.putText(driverName);
        out.putByte((byte) 0);
        putAll(out, AFTER_NAME);
        TtcDataTypes.putMessage(out);
        TtcAuth.putPhaseOne(out, user);
        channel.sendData();

        return TtcAuth.readChallenge(channel);
    }

    private static void putAll(WireBuffer out, int[] bytes) {
        for (int value : bytes) {
            out.putByte((byte) value);
        }
    }
}
