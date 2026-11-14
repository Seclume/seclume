package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.function.UnaryOperator;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The handshake checks the shape of the server's Certificate before it reads
 * a certificate out of it: {@link CertificateMessage#certificates} walks
 * whatever fits and stops, which is right for the client's own message and
 * too kind to a server's. {@link CertificateMessageTest} proves the check;
 * this proves the handshake makes it - that a list whose length lies, or an
 * extension on an entry, is refused with the alert RFC 8446 gives it, and
 * not left to fail later as something else.
 *
 * <p>Without the call the handshake went on: a short list read as no
 * certificate at all, a signature then checked over a transcript the server
 * never signed. PIT let the removed call survive on a fast runner.
 */
@Timeout(120)
class ServerCertificateShapeTest {

    private static final String HOSTNAME = "db.example.com";

    private static TestCertificates certificates;
    private static CertificateTrust trust;
    private static byte[] leaf;
    private static PrivateKey key;

    @BeforeAll
    static void issueAServerCertificate() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        TestCertificates.Issued server = certificates.issueEc("server",
                "san=dns:" + HOSTNAME, "ku:c=digitalSignature", "eku=serverAuth");
        trust = CertificateTrust.of(certificates.trustStore());
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

    @Test
    void aListLengthOneShortIsADecodeError() {
        TlsProtocolException refused = refused(message -> {
            byte[] changed = message.clone();
            int at = Handshake.HEADER + 1;                       // after the empty request context
            int list = ((changed[at] & 0xff) << 16) | ((changed[at + 1] & 0xff) << 8) | (changed[at + 2] & 0xff);
            changed[at] = (byte) ((list - 1) >>> 16);
            changed[at + 1] = (byte) ((list - 1) >>> 8);
            changed[at + 2] = (byte) (list - 1);
            return changed;
        }, TlsAlertException.DECODE_ERROR);
        assertTrue(refused.getMessage().contains("the certificate list says"), refused.getMessage());
    }

    @Test
    void anExtensionOnTheServersCertificateIsUnsupported() {
        // status_request (5), empty, as the leaf's entry's only extension:
        // this client asks for none, so none may come back.
        refused(message -> {
            byte[] extension = {0, 5, 0, 0};
            byte[] changed = new byte[message.length + extension.length];
            System.arraycopy(message, 0, changed, 0, message.length - 2);
            changed[message.length - 2] = 0;
            changed[message.length - 1] = (byte) extension.length;
            System.arraycopy(extension, 0, changed, message.length, extension.length);
            grow(changed, 1, extension.length);                 // the message's own length
            grow(changed, Handshake.HEADER + 1, extension.length); // the list's
            return changed;
        }, TlsAlertException.UNSUPPORTED_EXTENSION);
    }

    @Test
    void theSameFlightUnchangedIsAccepted() throws IOException {
        ScriptedTlsServer server = new ScriptedTlsServer(ScriptedTlsServer.COMPLETE, leaf, key, false,
                inCertificate(UnaryOperator.identity()));
        ClientHandshake.connect(server, HOSTNAME, trust).close();
        assertTrue(server.clientFinishedSeen());
    }

    /** Adds {@code by} to the three-byte length at {@code at}. */
    private static void grow(byte[] message, int at, int by) {
        int value = ((message[at] & 0xff) << 16) | ((message[at + 1] & 0xff) << 8) | (message[at + 2] & 0xff);
        value += by;
        message[at] = (byte) (value >>> 16);
        message[at + 1] = (byte) (value >>> 8);
        message[at + 2] = (byte) value;
    }

    private static TlsProtocolException refused(UnaryOperator<byte[]> change, int alert) {
        // With a trust store and without one: the shape is checked either way.
        TlsProtocolException last = null;
        for (boolean withTrust : new boolean[] {true, false}) {
            ScriptedTlsServer server = new ScriptedTlsServer(ScriptedTlsServer.COMPLETE, leaf, key, false,
                    inCertificate(change));
            last = assertThrows(TlsProtocolException.class,
                    () -> {
                        if (withTrust) {
                            ClientHandshake.connect(server, HOSTNAME, trust).close();
                        } else {
                            ClientHandshake.connectWithoutAuthenticating(server, HOSTNAME).close();
                        }
                    }, "with trust: " + withTrust);
            assertEquals(alert, last.alert(), last.getMessage());
            assertEquals(alert, server.alertReceived(), "the server is told why");
            assertFalse(server.clientFinishedSeen(), "no Finished of ours follows a refusal");
        }
        return last;
    }

    /** A tamper that applies {@code change} to the server's Certificate and leaves the rest. */
    private static UnaryOperator<byte[]> inCertificate(UnaryOperator<byte[]> change) {
        return flight -> {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int at = 0;
            boolean found = false;
            while (at + Handshake.HEADER <= flight.length) {
                int length = ((flight[at + 1] & 0xff) << 16) | ((flight[at + 2] & 0xff) << 8)
                        | (flight[at + 3] & 0xff);
                byte[] message = java.util.Arrays.copyOfRange(flight, at, at + Handshake.HEADER + length);
                if (message[0] == Handshake.CERTIFICATE) {
                    message = change.apply(message);
                    found = true;
                }
                out.writeBytes(message);
                at += Handshake.HEADER + length;
            }
            assertEquals(flight.length, at, "the flight is whole messages");
            assertTrue(found, "the flight has a Certificate");
            return out.toByteArray();
        };
    }
}
