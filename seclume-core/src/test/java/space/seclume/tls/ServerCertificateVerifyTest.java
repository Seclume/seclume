package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.function.UnaryOperator;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The server's CertificateVerify is checked in the handshake, not only by
 * {@link HandshakeSignature} on its own: a server that presents a certificate
 * it holds no key for is refused, with the alert RFC 8446 section 4.4.3 asks
 * for, before any Finished of ours goes out.
 *
 * <p>Without this the call that checks the signature could go and every test
 * would still pass - {@link CertificateVerificationTest} proves the check, not
 * that the handshake makes it. Mutation testing found exactly that: removing
 * the call survived, and in slow runs only timed out. Without a valid
 * CertificateVerify, a certificate somebody copied off the real server is as
 * good as the real server's key, and the Finished proves nothing about who is
 * at the other end.
 *
 * <p>Every flight is built by {@link ScriptedTlsServer}, with the right
 * certificate for the right name and a correct Finished; only what is named
 * is wrong. Checked with and without a trust store, as the handshake checks
 * the signature in both.
 */
@Timeout(120)
class ServerCertificateVerifyTest {

    private static final String HOSTNAME = "db.example.com";

    private static TestCertificates certificates;
    private static CertificateTrust trust;
    private static byte[] leaf;
    private static PrivateKey key;
    private static PrivateKey anotherKey;

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
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        anotherKey = generator.generateKeyPair().getPrivate();
    }

    @AfterAll
    static void removeTheAuthority() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    @ParameterizedTest(name = "with trust: {0}")
    @ValueSource(booleans = {true, false})
    void aCertificateVerifyByAnotherKeyIsRefusedWithDecryptError(boolean withTrust) {
        ScriptedTlsServer server = new ScriptedTlsServer(ScriptedTlsServer.COMPLETE, leaf, anotherKey);
        TlsProtocolException refused = assertThrows(TlsProtocolException.class,
                () -> connect(server, withTrust),
                "a server without the certificate's key has to be refused with an alert");
        assertTrue(refused.getMessage().contains("does not hold the key it presented"), refused.getMessage());
        assertEquals(TlsAlertException.DECRYPT_ERROR, refused.alert());
        assertEquals(TlsAlertException.DECRYPT_ERROR, server.alertReceived(),
                "RFC 8446 4.4.3: a CertificateVerify that does not verify ends in decrypt_error");
        assertFalse(server.clientFinishedSeen(), "no Finished of ours may follow a refusal");
    }

    @ParameterizedTest(name = "with trust: {0}")
    @ValueSource(booleans = {true, false})
    void aSignatureShorterThanItsMessageIsADecodeError(boolean withTrust) {
        // The signature's own length one less than the bytes that follow it.
        refusedForItsShape(withTrust, message -> {
            byte[] changed = message.clone();
            int declared = ((changed[Handshake.HEADER + 2] & 0xff) << 8) | (changed[Handshake.HEADER + 3] & 0xff);
            changed[Handshake.HEADER + 2] = (byte) ((declared - 1) >>> 8);
            changed[Handshake.HEADER + 3] = (byte) (declared - 1);
            return changed;
        });
    }

    @ParameterizedTest(name = "with trust: {0}")
    @ValueSource(booleans = {true, false})
    void aByteAfterTheSignatureIsADecodeError(boolean withTrust) {
        refusedForItsShape(withTrust, message -> {
            byte[] changed = new byte[message.length + 1];
            System.arraycopy(message, 0, changed, 0, message.length);
            int body = message.length - Handshake.HEADER + 1;
            changed[1] = (byte) (body >>> 16);
            changed[2] = (byte) (body >>> 8);
            changed[3] = (byte) body;
            return changed;
        });
    }

    @ParameterizedTest(name = "with trust: {0}")
    @ValueSource(booleans = {true, false})
    void theSameFlightUnchangedIsAccepted(boolean withTrust) throws IOException {
        // The control: the tamper path itself, handing the flight on as it is.
        ScriptedTlsServer server = new ScriptedTlsServer(ScriptedTlsServer.COMPLETE, leaf, key, false,
                inCertificateVerify(UnaryOperator.identity()));
        connect(server, withTrust).close();
        assertTrue(server.clientFinishedSeen());
    }

    private static void refusedForItsShape(boolean withTrust, UnaryOperator<byte[]> change) {
        ScriptedTlsServer server = new ScriptedTlsServer(ScriptedTlsServer.COMPLETE, leaf, key, false,
                inCertificateVerify(change));
        TlsProtocolException refused = assertThrows(TlsProtocolException.class,
                () -> connect(server, withTrust));
        assertTrue(refused.getMessage().contains("does not fill it exactly"), refused.getMessage());
        assertEquals(TlsAlertException.DECODE_ERROR, server.alertReceived());
        assertFalse(server.clientFinishedSeen());
    }

    private static TlsConnection connect(ScriptedTlsServer server, boolean withTrust) throws IOException {
        return withTrust
                ? ClientHandshake.connect(server, HOSTNAME, trust)
                : ClientHandshake.connectWithoutAuthenticating(server, HOSTNAME);
    }

    /** A tamper that applies {@code change} to the CertificateVerify of a flight and leaves the rest. */
    private static UnaryOperator<byte[]> inCertificateVerify(UnaryOperator<byte[]> change) {
        return flight -> {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int at = 0;
            boolean found = false;
            while (at < flight.length) {
                int length = ((flight[at + 1] & 0xff) << 16) | ((flight[at + 2] & 0xff) << 8)
                        | (flight[at + 3] & 0xff);
                byte[] message = java.util.Arrays.copyOfRange(flight, at, at + Handshake.HEADER + length);
                if (message[0] == Handshake.CERTIFICATE_VERIFY) {
                    message = change.apply(message);
                    found = true;
                }
                out.writeBytes(message);
                at += Handshake.HEADER + length;
            }
            assertTrue(found, "the flight has a CertificateVerify");
            return out.toByteArray();
        };
    }
}
