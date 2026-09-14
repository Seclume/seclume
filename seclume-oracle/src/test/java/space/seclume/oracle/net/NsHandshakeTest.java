package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The NS connect against a <b>real</b> Oracle listener.
 *
 * <p>This is the test Oracle has been missing. Everything else in this module
 * could only be cross-checked against the JCA - computed correctly, but with no
 * evidence that it is the right computation. Here a server answers for the
 * first time.
 *
 * <p>What is checked is the packet layer: header layout, length field, packet
 * types, and that the server answers a CONNECT with ACCEPT, REDIRECT or RESEND
 * instead of throwing the connection away. This is exactly where it shows
 * whether the offsets derived from the third-party source are right - one
 * shifted field and the listener hangs up without a word.
 *
 * <p>Without a reachable server this is skipped, not failed: on someone else's
 * machine its absence is not an error.
 */
class NsHandshakeTest {

    private static final String HOST =
            System.getProperty("seclume.oracle.host", "db.example.invalid");
    private static final int PORT =
            Integer.getInteger("seclume.oracle.port", 1521);
    private static final String USER =
            System.getProperty("seclume.oracle.user", "seclume_test");
    private static final String SERVICE =
            System.getProperty("seclume.oracle.service", "FREEPDB1");

    @BeforeAll
    static void findTheListener() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no Oracle listener on " + HOST + ":" + PORT);
        }
    }

    private static String connectString() {
        return "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=" + HOST + ")(PORT=" + PORT + "))"
                + "(CONNECT_DATA=(SERVICE_NAME=" + SERVICE + ")"
                + "(CID=(PROGRAM=seclume)(HOST=seclume)(USER=seclume))))";
    }

    /**
     * The listener accepts the CONNECT - or redirects. Either is a success:
     * it means it understood the packet.
     */
    @Test
    void theListenerUnderstandsOurConnectPacket() throws Exception {
        try (NsChannel channel = NsChannel.connect(HOST, PORT, 10_000)) {
            int type = channel.sendConnect(connectString());
            switch (type) {
                case NsPacket.TYPE_ACCEPT -> {
                    channel.readAccept();
                    assertTrue(channel.protocolVersion() >= NsPacket.VERSION_MINIMUM,
                            "the server negotiated version " + channel.protocolVersion());
                    assertTrue(channel.negotiatedSdu() > 0,
                            "the server negotiated an SDU of " + channel.negotiatedSdu());
                    System.out.println("ACCEPT: version=" + channel.protocolVersion()
                            + ", sdu=" + channel.negotiatedSdu());
                }
                case NsPacket.TYPE_REDIRECT -> {
                    String target = channel.readRedirect();
                    assertTrue(target.contains("ADDRESS") || target.contains("PORT"),
                            "the redirect did not name an address: " + target);
                    System.out.println("REDIRECT to: " + target);
                }
                case NsPacket.TYPE_RESEND -> System.out.println("RESEND - the server wants it again");
                case NsPacket.TYPE_REFUSE -> fail("the server refused: " + channel.readRefuse());
                default -> fail("unexpected packet type: " + NsPacket.typeName(type));
            }
        }
    }

    /**
     * After the ACCEPT comes the protocol negotiation of TTC. Only then are
     * you talking to the database rather than just to the listener.
     */
    @Test
    void theServerNegotiatesTheTtcProtocol() throws Exception {
        try (NsChannel channel = NsChannel.connect(HOST, PORT, 10_000)) {
            int type = channel.sendConnect(connectString());
            Assumptions.assumeTrue(type == NsPacket.TYPE_ACCEPT,
                    "expected ACCEPT, got " + NsPacket.typeName(type));
            channel.readAccept();

            TtcProtocol protocol = new TtcProtocol();
            protocol.negotiate(channel);

            assertTrue(protocol.serverVersion() > 0,
                    "the server did not name its protocol version");
            // The banner is the server's platform, not its name -
            // with Oracle Free 23ai something like "x86_64/Linux 2.4.xx".
            assertFalse(protocol.serverBanner().isBlank(),
                    "the server did not send a banner");
            assertEquals(6, protocol.serverVersion(),
                    "unexpected TTC version: " + protocol.serverVersion());
            System.out.println("TTC: version=" + protocol.serverVersion()
                    + ", charset=" + protocol.characterSet()
                    + ", banner=" + protocol.serverBanner());
        }
    }

    /**
     * After the protocol comes the data-type negotiation - and that is the
     * step at which the server hung up until now.
     *
     * <p>It is the first real proof that the capability arrays and the type
     * list are right: the server checks them, and if it does not like them it
     * closes the connection without an error packet. An answer therefore means
     * more here than an answer usually does.
     */
    @Test
    void theServerAcceptsOurDataTypes() throws Exception {
        try (NsChannel channel = NsChannel.connect(HOST, PORT, 10_000)) {
            int type = channel.sendConnect(connectString());
            Assumptions.assumeTrue(type == NsPacket.TYPE_ACCEPT,
                    "expected ACCEPT, got " + NsPacket.typeName(type));
            channel.readAccept();

            new TtcProtocol().negotiate(channel);
            new TtcDataTypes().negotiate(channel);
            System.out.println("DATA_TYPES accepted");
        }
    }

    /**
     * The combined opening: protocol, data types and the first login stage in
     * one packet - and the server answers with the challenge.
     *
     * <p>Two round trips saved, and the only shape the server accepts for the
     * login. No password is involved yet, so this test needs none.
     */
    @Test
    void theServerAnswersTheCombinedOpening() throws Exception {
        try (NsChannel channel = NsChannel.connect(HOST, PORT, 10_000)) {
            int type = channel.sendConnect(connectString());
            Assumptions.assumeTrue(type == NsPacket.TYPE_ACCEPT,
                    "expected ACCEPT, got " + NsPacket.typeName(type));
            channel.readAccept();

            TtcAuth.Challenge challenge = TtcFastAuth.open(channel, "seclume", USER);

            assertFalse(challenge.sessionKey().isBlank(), "no AUTH_SESSKEY");
            assertFalse(challenge.salt().isBlank(), "no AUTH_VFR_DATA");
            assertTrue(challenge.is12c(), "unexpected verifier type: 0x"
                    + Integer.toHexString(challenge.verifierType()));
            assertTrue(challenge.generationCount() > 0, "no PBKDF2 iteration count");
            System.out.println("FAST_AUTH: verifier=0x"
                    + Integer.toHexString(challenge.verifierType())
                    + ", sesskey=" + challenge.sessionKey().length() + " hex chars"
                    + ", salt=" + challenge.salt().length() + " hex chars"
                    + ", vgen=" + challenge.generationCount()
                    + ", sder=" + challenge.derivationCount()
                    + ", cskSalt=" + challenge.saltForComboKey().length() + " hex chars");
        }
    }

    /**
     * The first login stage - and the finding that it does not work on its
     * own.
     *
     * <p>The message itself is right: byte for byte the same as what
     * {@code python-oracledb} sends. But it sends it <b>inside</b> a
     * {@code FAST_AUTH} packet, which bundles protocol, data types and the
     * first login stage into one. Sent on its own after the classic
     * negotiation, the server answers with two MARKER packets - its way of
     * saying no without saying why.
     *
     * <p>So the next step is the FAST_AUTH wrapper, not more fiddling with
     * this message. Recorded in {@code docs/protocol/oracle.md}; the test is
     * disabled rather than deleted, because it is the evidence.
     */
    @org.junit.jupiter.api.Disabled("the server wants FAST_AUTH; see docs/protocol/oracle.md")
    @Test
    void theServerAnswersTheFirstLoginStage() throws Exception {
        try (NsChannel channel = NsChannel.connect(HOST, PORT, 10_000)) {
            int type = channel.sendConnect(connectString());
            Assumptions.assumeTrue(type == NsPacket.TYPE_ACCEPT,
                    "expected ACCEPT, got " + NsPacket.typeName(type));
            channel.readAccept();
            new TtcProtocol().negotiate(channel);
            new TtcDataTypes().negotiate(channel);

            TtcAuth.Challenge challenge = TtcAuth.phaseOne(channel, USER);

            assertFalse(challenge.sessionKey().isBlank(), "no AUTH_SESSKEY");
            assertTrue(challenge.is12c(), "unexpected verifier type");
        }
    }

    /**
     * After a REDIRECT a client connects afresh to the address it names. The
     * second time an ACCEPT has to arrive - otherwise one would go in
     * circles.
     */
    @Test
    void aRedirectLeadsToAnAccept() throws Exception {
        String description = connectString();
        for (int attempt = 0; attempt < 3; attempt++) {
            try (NsChannel channel = NsChannel.connect(HOST, PORT, 10_000)) {
                int type = channel.sendConnect(description);
                if (type == NsPacket.TYPE_ACCEPT) {
                    channel.readAccept();
                    System.out.println("ACCEPT after " + attempt + " redirect(s), version="
                            + channel.protocolVersion());
                    return;
                }
                if (type == NsPacket.TYPE_RESEND) {
                    continue;
                }
                if (type == NsPacket.TYPE_REDIRECT) {
                    description = channel.readRedirect();
                    continue;
                }
                fail("unexpected packet: " + NsPacket.typeName(type));
            }
        }
        fail("no ACCEPT after three attempts - the client is going in circles");
    }
}
