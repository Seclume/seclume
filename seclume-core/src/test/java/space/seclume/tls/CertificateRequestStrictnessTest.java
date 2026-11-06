package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The server's CertificateRequest, RFC 8446 section 4.3.2. The client used to
 * take only its request context from it - by the context's own length byte,
 * with nothing to say that the context, or anything after it, was inside the
 * message. Now it is read like every other message of the flight: an empty
 * context, one extensions block that fills the rest, and a well-formed
 * signature_algorithms in it - and an unknown extension is ignored, as the RFC
 * asks of a client.
 *
 * <p>Every flight is built by {@link ScriptedTlsServer} with the request in
 * the transcript as sent, so signatures and Finished are right throughout:
 * what is refused is refused for the request, with the alert the RFC names.
 */
@Timeout(60)
class CertificateRequestStrictnessTest {

    private static final String HOSTNAME = "db.example.com";
    private static final byte CR = Handshake.CERTIFICATE_REQUEST;

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
    static void cleanUp() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    /** A CertificateRequest of this body, its header worked out. */
    private static byte[] request(int... body) {
        byte[] message = new byte[Handshake.HEADER + body.length];
        message[0] = CR;
        message[1] = (byte) (body.length >>> 16);
        message[2] = (byte) (body.length >>> 8);
        message[3] = (byte) body.length;
        for (int i = 0; i < body.length; i++) {
            message[Handshake.HEADER + i] = (byte) body[i];
        }
        return message;
    }

    static Stream<Arguments> refused() {
        return Stream.of(
                Arguments.of("an empty message", request(),
                        TlsAlertException.DECODE_ERROR),
                Arguments.of("a context longer than the message", request(5, 0),
                        TlsAlertException.DECODE_ERROR),
                Arguments.of("a context during the handshake",
                        request(1, 7, 0, 8, 0, 13, 0, 4, 0, 2, 4, 3),
                        TlsAlertException.ILLEGAL_PARAMETER),
                Arguments.of("no extensions block", request(0),
                        TlsAlertException.DECODE_ERROR),
                Arguments.of("an extensions block longer than the message",
                        request(0, 0, 9, 0, 13, 0, 4, 0, 2, 4, 3),
                        TlsAlertException.DECODE_ERROR),
                Arguments.of("bytes after the extensions block",
                        request(0, 0, 8, 0, 13, 0, 4, 0, 2, 4, 3, 0),
                        TlsAlertException.DECODE_ERROR),
                Arguments.of("no extensions at all", request(0, 0, 0),
                        TlsAlertException.MISSING_EXTENSION),
                Arguments.of("only an unknown extension", request(0, 0, 4, 0xfe, 0xfe, 0, 0),
                        TlsAlertException.MISSING_EXTENSION),
                Arguments.of("an empty signature_algorithms list",
                        request(0, 0, 6, 0, 13, 0, 2, 0, 0),
                        TlsAlertException.DECODE_ERROR),
                Arguments.of("a signature_algorithms list of an odd length",
                        request(0, 0, 7, 0, 13, 0, 3, 0, 1, 4),
                        TlsAlertException.DECODE_ERROR),
                Arguments.of("a signature_algorithms list longer than its extension",
                        request(0, 0, 8, 0, 13, 0, 4, 0, 4, 4, 3),
                        TlsAlertException.DECODE_ERROR),
                Arguments.of("a signature_algorithms extension of one byte",
                        request(0, 0, 5, 0, 13, 0, 1, 0),
                        TlsAlertException.DECODE_ERROR),
                Arguments.of("signature_algorithms twice",
                        request(0, 0, 16, 0, 13, 0, 4, 0, 2, 4, 3, 0, 13, 0, 4, 0, 2, 4, 3),
                        TlsAlertException.ILLEGAL_PARAMETER));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("refused")
    void aMalformedRequestIsRefusedWithItsAlert(String name, byte[] message, int alert) {
        for (boolean split : new boolean[] {false, true}) {
            ScriptedTlsServer server = new ScriptedTlsServer(
                    ScriptedTlsServer.COMPLETE_WITH_REQUEST, leaf, key, split, null)
                    .certificateRequest(message);
            IOException refused = assertThrows(IOException.class,
                    () -> ClientHandshake.connect(server, HOSTNAME, trust),
                    name + " was accepted");
            assertEquals(alert, server.alertReceived(), name + ": " + refused.getMessage());
            assertTrue(refused.getMessage().contains(TlsAlertException.name(alert)),
                    refused.getMessage());
            assertTrue(!server.clientFinishedSeen(), name + ": our Finished followed");
        }
    }

    @Test
    void anUnknownExtensionBesideSignatureAlgorithmsIsIgnored() throws IOException {
        accepted(request(0, 0, 14, 0xfe, 0xfe, 0, 2, 9, 9, 0, 13, 0, 4, 0, 2, 4, 3));
    }

    @Test
    void severalSchemesAndTheOtherKnownExtensionsAreAccepted() throws IOException {
        // signature_algorithms with three schemes, signature_algorithms_cert (50)
        // and certificate_authorities (47) with an empty list's worth of bytes.
        accepted(request(0, 0, 24,
                0, 13, 0, 8, 0, 6, 4, 3, 8, 4, 8, 7,
                0, 50, 0, 4, 0, 2, 4, 3,
                0, 47, 0, 0));
    }

    @Test
    void theRequestTheScriptedServerAlwaysSentIsStillAccepted() throws IOException {
        accepted(request(0, 0, 8, 0, 13, 0, 4, 0, 2, 4, 3));
    }

    private static void accepted(byte[] message) throws IOException {
        for (boolean split : new boolean[] {false, true}) {
            ScriptedTlsServer server = new ScriptedTlsServer(
                    ScriptedTlsServer.COMPLETE_WITH_REQUEST, leaf, key, split, null)
                    .certificateRequest(message);
            try (TlsConnection connection = ClientHandshake.connect(server, HOSTNAME, trust)) {
                assertNotNull(connection.peerCertificate());
                assertTrue(server.clientFinishedSeen());
                assertEquals(-1, server.alertReceived());
            }
        }
    }
}
