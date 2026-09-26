package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import space.seclume.tls.ScriptedTlsServer.Outgoing;

/**
 * What a server may still say in the handshake protocol once the handshake
 * is over - RFC 8446 section 4.6 - and what it may not.
 *
 * <p>Two messages are legal on an established connection: NewSessionTicket,
 * which this client does not use and drops, and KeyUpdate, whose one byte
 * has to be 0 or 1. Everything else is refused with {@code unexpected_message},
 * a KeyUpdate of any other shape with {@code illegal_parameter}, and in both
 * cases the connection is closed rather than read on. Before this, any other
 * message was dropped without a word and a KeyUpdate of 2 to 255 counted as
 * "not requested".
 */
@Timeout(60)
class PostHandshakeTest {

    private static final String HOSTNAME = "db.example.com";
    private static final byte[] AFTER = "after".getBytes(StandardCharsets.US_ASCII);

    private static TestCertificates certificates;
    private static byte[] leaf;
    private static PrivateKey key;

    @BeforeAll
    static void issueAServerCertificate() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        TestCertificates.Issued server = certificates.issueEc("server",
                "san=dns:" + HOSTNAME, "ku:c=digitalSignature", "eku=serverAuth");
        leaf = server.certificate().getEncoded();
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(server.keystore())) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        key = (PrivateKey) store.getKey("server", TestCertificates.PASSWORD.toCharArray());
    }

    @AfterAll
    static void removeTheAuthority() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    // ---- what is allowed -------------------------------------------------

    @Test
    void aNewSessionTicketIsDroppedAndTheDataAfterItArrives() throws IOException {
        byte[] ticket = {Handshake.NEW_SESSION_TICKET, 0, 0, 15,
            0, 0, 0, 60,                 // lifetime
            0, 0, 0, 1,                  // age_add
            1, 7,                        // nonce
            0, 1, 9,                     // ticket
            0, 0};                       // extensions
        ScriptedTlsServer server = server(Outgoing.handshake(ticket), Outgoing.data(AFTER));
        try (TlsConnection connection = connect(server)) {
            assertArrayEquals(ScriptedTlsServer.GREETING,
                    read(connection, ScriptedTlsServer.GREETING.length));
            assertArrayEquals(AFTER, read(connection, AFTER.length));
            assertEquals(List.of(), server.clientMessagesAfterFinished());
        }
    }

    @Test
    void aKeyUpdateNotRequestingOneIsFollowedAndNotAnswered() throws IOException {
        ScriptedTlsServer server = server(Outgoing.keyUpdate(0), Outgoing.data(AFTER));
        try (TlsConnection connection = connect(server)) {
            read(connection, ScriptedTlsServer.GREETING.length);
            assertArrayEquals(AFTER, read(connection, AFTER.length),
                    "the record after the KeyUpdate is under the next key");
            assertEquals(List.of(), server.clientMessagesAfterFinished());
        }
    }

    @Test
    void aKeyUpdateRequestingOneIsAnsweredWithOne() throws IOException {
        ScriptedTlsServer server = server(Outgoing.keyUpdate(1), Outgoing.data(AFTER));
        try (TlsConnection connection = connect(server)) {
            read(connection, ScriptedTlsServer.GREETING.length);
            assertArrayEquals(AFTER, read(connection, AFTER.length));
            assertEquals(List.of(24), server.clientMessagesAfterFinished(),
                    "update_requested has to be answered by a KeyUpdate of our own");
        }
    }

    // ---- what is refused -------------------------------------------------

    static Stream<Arguments> refused() {
        List<Arguments> cases = new ArrayList<>();
        int illegal = TlsAlertException.ILLEGAL_PARAMETER;
        int unexpected = TlsAlertException.UNEXPECTED_MESSAGE;
        cases.add(Arguments.of("KeyUpdate with value 2", keyUpdate(2), illegal));
        cases.add(Arguments.of("KeyUpdate with value 255", keyUpdate(255), illegal));
        cases.add(Arguments.of("KeyUpdate of length 0", new byte[] {24, 0, 0, 0}, illegal));
        cases.add(Arguments.of("KeyUpdate of length 2", new byte[] {24, 0, 0, 2, 0, 0}, illegal));
        cases.add(Arguments.of("KeyUpdate followed by a ticket in the same record",
                concat(keyUpdate(0), new byte[] {Handshake.NEW_SESSION_TICKET, 0, 0, 13,
                    0, 0, 0, 60, 0, 0, 0, 1, 0, 0, 0, 0, 0}), unexpected));
        cases.add(Arguments.of("ClientHello", new byte[] {Handshake.CLIENT_HELLO, 0, 0, 1, 0},
                unexpected));
        cases.add(Arguments.of("ServerHello", new byte[] {Handshake.SERVER_HELLO, 0, 0, 1, 0},
                unexpected));
        cases.add(Arguments.of("EncryptedExtensions",
                new byte[] {Handshake.ENCRYPTED_EXTENSIONS, 0, 0, 2, 0, 0}, unexpected));
        cases.add(Arguments.of("Certificate", new byte[] {Handshake.CERTIFICATE, 0, 0, 4,
            0, 0, 0, 0}, unexpected));
        cases.add(Arguments.of("CertificateRequest (post-handshake authentication)",
                new byte[] {Handshake.CERTIFICATE_REQUEST, 0, 0, 11, 1, 5, 0, 8,
                    0, 13, 0, 4, 0, 2, 4, 3}, unexpected));
        cases.add(Arguments.of("CertificateVerify",
                new byte[] {Handshake.CERTIFICATE_VERIFY, 0, 0, 4, 4, 3, 0, 0}, unexpected));
        cases.add(Arguments.of("Finished", new byte[] {Handshake.FINISHED, 0, 0, 1, 0},
                unexpected));
        cases.add(Arguments.of("EndOfEarlyData",
                new byte[] {Handshake.END_OF_EARLY_DATA, 0, 0, 0}, unexpected));
        cases.add(Arguments.of("an unknown type", new byte[] {99, 0, 0, 1, 0}, unexpected));
        return cases.stream();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("refused")
    void isRefusedAndTheConnectionClosed(String name, byte[] message, int alert)
            throws IOException {
        ScriptedTlsServer server = server(Outgoing.handshake(message), Outgoing.data(AFTER));
        TlsConnection connection = connect(server);
        try {
            read(connection, ScriptedTlsServer.GREETING.length);
            IOException refused = assertThrows(IOException.class,
                    () -> read(connection, AFTER.length), name + " was accepted");
            assertTrue(refused instanceof TlsProtocolException,
                    "not a refusal of ours: " + refused);
            assertEquals(alert, ((TlsProtocolException) refused).alert(), refused.getMessage());
            assertEquals(alert, server.alertReceived(), "the server has to be told why");
            assertFalse(connection.isOpen(), "a connection that refused a message is closed");
            assertFalse(server.isOpen(), "and so is the transport beneath it");
            assertThrows(IOException.class, () -> read(connection, 1),
                    "nothing may be read after the refusal");
        } finally {
            connection.close();
        }
    }

    // ---- plumbing ---------------------------------------------------------

    private static byte[] keyUpdate(int value) {
        return new byte[] {24, 0, 0, 1, (byte) value};
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = java.util.Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static ScriptedTlsServer server(Outgoing... after) {
        return new ScriptedTlsServer(ScriptedTlsServer.COMPLETE, leaf, key, false, null,
                List.of(after));
    }

    private static TlsConnection connect(ScriptedTlsServer server) throws IOException {
        return ClientHandshake.connectWithoutAuthenticating(server, HOSTNAME);
    }

    private static byte[] read(TlsConnection connection, int count) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(count);
        while (buffer.hasRemaining()) {
            if (connection.read(buffer) < 0) {
                throw new IOException("the connection ended after "
                        + (count - buffer.remaining()) + " of " + count + " bytes");
            }
        }
        return buffer.array();
    }
}
