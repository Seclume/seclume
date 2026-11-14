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
 * A server certificate the client will not go on with is refused with an
 * alert, so that the server learns why instead of seeing the connection
 * drop: RFC 8446 section 4.4.2.4 asks for {@code decode_error} for an empty
 * Certificate, and section 6.2 names {@code bad_certificate} for one that is
 * corrupt and {@code certificate_unknown} for one that is unacceptable for
 * another reason.
 *
 * <p>Each was refused before, as a plain {@code IOException} and without an
 * alert - the TLS 1.2 handshake alone sent {@code decode_error} for the empty
 * list.
 */
@Timeout(120)
class ServerCertificateAlertTest {

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
    void anEmptyCertificateListIsADecodeError() {
        // Request context, and a list of length zero.
        byte[] empty = {Handshake.CERTIFICATE, 0, 0, 4, 0, 0, 0, 0};
        for (boolean withTrust : new boolean[] {true, false}) {
            ScriptedTlsServer server = new ScriptedTlsServer(ScriptedTlsServer.COMPLETE, leaf, key, false,
                    inCertificate(message -> empty));
            TlsProtocolException refused = assertThrows(TlsProtocolException.class,
                    () -> connect(server, HOSTNAME, withTrust), "with trust: " + withTrust);
            assertEquals(TlsAlertException.DECODE_ERROR, refused.alert(), refused.getMessage());
            assertTrue(refused.getMessage().contains("has no certificate in it"),
                    "refused by the shape check, before anything is read: " + refused.getMessage());
            told(server, TlsAlertException.DECODE_ERROR);
        }
    }

    @Test
    void aCertificateThatCannotBeReadIsABadCertificate() {
        // The DER of the leaf with its outer SEQUENCE tag changed: still the
        // right length, no longer a certificate.
        for (boolean withTrust : new boolean[] {true, false}) {
            ScriptedTlsServer server = new ScriptedTlsServer(ScriptedTlsServer.COMPLETE, leaf, key, false,
                    inCertificate(message -> {
                        byte[] changed = message.clone();
                        int der = Handshake.HEADER + 1 + 3 + 3;
                        assertEquals(0x30, changed[der] & 0xff, "the leaf starts with a SEQUENCE");
                        changed[der] = 0x04;
                        return changed;
                    }));
            TlsProtocolException refused = assertThrows(TlsProtocolException.class,
                    () -> connect(server, HOSTNAME, withTrust), "with trust: " + withTrust);
            assertEquals(TlsAlertException.BAD_CERTIFICATE, refused.alert(), refused.getMessage());
            assertTrue(refused.getMessage().contains("cannot be read"), refused.getMessage());
            told(server, TlsAlertException.BAD_CERTIFICATE);
        }
    }

    @Test
    void aCertificateForAnotherNameIsUnacceptable() {
        ScriptedTlsServer server = new ScriptedTlsServer(ScriptedTlsServer.COMPLETE, leaf, key);
        TlsProtocolException refused = assertThrows(TlsProtocolException.class,
                () -> ClientHandshake.connect(server, "other.example.com", trust));
        assertEquals(TlsAlertException.CERTIFICATE_UNKNOWN, refused.alert(), refused.getMessage());
        assertTrue(refused.getMessage().contains("the server's certificate was refused"), refused.getMessage());
        told(server, TlsAlertException.CERTIFICATE_UNKNOWN);
    }

    @Test
    void theRightCertificateForTheRightNameIsAccepted() throws IOException {
        ScriptedTlsServer server = new ScriptedTlsServer(ScriptedTlsServer.COMPLETE, leaf, key, false,
                inCertificate(UnaryOperator.identity()));
        ClientHandshake.connect(server, HOSTNAME, trust).close();
        assertTrue(server.clientFinishedSeen());
        assertEquals(-1, server.alertReceived());
    }

    private static void told(ScriptedTlsServer server, int alert) {
        assertEquals(alert, server.alertReceived(), "the server has to be told why");
        assertFalse(server.clientFinishedSeen(), "no Finished of ours follows a refusal");
    }

    private static TlsConnection connect(ScriptedTlsServer server, String host, boolean withTrust)
            throws IOException {
        return withTrust
                ? ClientHandshake.connect(server, host, trust)
                : ClientHandshake.connectWithoutAuthenticating(server, host);
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
