package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static space.seclume.tls.ScriptedTlsServer.Step.CERTIFICATE;
import static space.seclume.tls.ScriptedTlsServer.Step.CERTIFICATE_REQUEST;
import static space.seclume.tls.ScriptedTlsServer.Step.CERTIFICATE_VERIFY;
import static space.seclume.tls.ScriptedTlsServer.Step.ENCRYPTED_EXTENSIONS;
import static space.seclume.tls.ScriptedTlsServer.Step.FINISHED;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
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

import space.seclume.tls.ScriptedTlsServer.Step;

/**
 * The server's encrypted flight has one legal order, and a client that does
 * not insist on it can be talked out of authenticating the server at all.
 *
 * <p>RFC 8446 section 4.4: without a PSK the server sends EncryptedExtensions,
 * optionally CertificateRequest, then Certificate, CertificateVerify and
 * Finished - each exactly once, in that order. A client that merely reacts to
 * whatever arrives accepts a server that leaves Certificate and
 * CertificateVerify out and goes straight to Finished; the Finished is
 * perfectly valid over the transcript that server produced, the connection is
 * encrypted, and nobody was authenticated. Review, 26.09.2026: a working
 * man-in-the-middle against {@code tls=verify-full, tlsStack=seclume}.
 *
 * <p>Every flight here is built by {@link ScriptedTlsServer}, which makes
 * every signature and every Finished correct where it stands. What is refused
 * is refused for its order and nothing else - and the two complete flights
 * are the control that shows the server is otherwise sound.
 */
@Timeout(120)
class ServerFlightOrderTest {

    private static final String HOSTNAME = "db.example.com";
    /** unexpected_message, RFC 8446 section 6. */
    private static final int UNEXPECTED_MESSAGE = 10;

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

    // ---- what must be refused ---------------------------------------------

    static Stream<Arguments> brokenFlights() {
        List<Arguments> cases = new ArrayList<>();
        for (boolean withTrust : new boolean[] {true, false}) {
            String how = withTrust ? "verify-full" : "without trust";
            cases.add(Arguments.of("neither Certificate nor CertificateVerify, " + how,
                    List.of(ENCRYPTED_EXTENSIONS, FINISHED), withTrust));
            cases.add(Arguments.of("Certificate without CertificateVerify, " + how,
                    List.of(ENCRYPTED_EXTENSIONS, CERTIFICATE, FINISHED), withTrust));
            cases.add(Arguments.of("CertificateVerify before Certificate, " + how,
                    List.of(ENCRYPTED_EXTENSIONS, CERTIFICATE_VERIFY, CERTIFICATE, FINISHED),
                    withTrust));
            cases.add(Arguments.of("Finished before EncryptedExtensions, " + how,
                    List.of(FINISHED, ENCRYPTED_EXTENSIONS, CERTIFICATE, CERTIFICATE_VERIFY),
                    withTrust));
            cases.add(Arguments.of("Certificate twice, " + how,
                    List.of(ENCRYPTED_EXTENSIONS, CERTIFICATE, CERTIFICATE, CERTIFICATE_VERIFY,
                            FINISHED), withTrust));
            cases.add(Arguments.of("no EncryptedExtensions, " + how,
                    List.of(CERTIFICATE, CERTIFICATE_VERIFY, FINISHED), withTrust));
            cases.add(Arguments.of("CertificateRequest after Certificate, " + how,
                    List.of(ENCRYPTED_EXTENSIONS, CERTIFICATE, CERTIFICATE_REQUEST,
                            CERTIFICATE_VERIFY, FINISHED), withTrust));
            // In the same record as the Finished only: in a record of its
            // own it arrives after the key change, and that is the case below.
            cases.add(Arguments.of("a message after Finished, " + how,
                    List.of(ENCRYPTED_EXTENSIONS, CERTIFICATE, CERTIFICATE_VERIFY, FINISHED,
                            ENCRYPTED_EXTENSIONS), withTrust));
        }
        return cases.stream();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("brokenFlights")
    void aFlightOutOfOrderIsRefused(String name, List<Step> script, boolean withTrust) {
        boolean afterFinished = script.indexOf(FINISHED) >= 0
                && script.indexOf(FINISHED) < script.size() - 1
                && script.subList(0, script.indexOf(FINISHED)).equals(
                        ScriptedTlsServer.COMPLETE.subList(0, 3));
        for (boolean split : afterFinished ? new boolean[] {false} : new boolean[] {false, true}) {
            ScriptedTlsServer server = new ScriptedTlsServer(script, leaf, key, split, null);
            IOException refused = assertThrows(IOException.class, () -> connect(server, withTrust),
                    name + (split ? " (one record per message)" : "") + " was accepted");
            assertTrue(refused.getMessage().contains("unexpected_message"),
                    "the reason has to be the order: " + refused.getMessage());
            assertEquals(UNEXPECTED_MESSAGE, server.alertReceived(),
                    "the server has to be told why: unexpected_message");
            assertTrue(!server.clientFinishedSeen(), "no Finished of ours may follow a refusal");
        }
    }

    /**
     * A handshake record after the server's Finished, in a record of its own,
     * arrives under the old key after the switch to the new one. The
     * handshake is over by then and cannot see it; what matters is that it
     * is never read as anything - the first read has to fail rather than
     * hand it, or what follows it, to the caller.
     */
    @Test
    void aHandshakeRecordAfterFinishedIsNeverReadAsData() throws IOException {
        ScriptedTlsServer server = new ScriptedTlsServer(List.of(ENCRYPTED_EXTENSIONS,
                CERTIFICATE, CERTIFICATE_VERIFY, FINISHED, ENCRYPTED_EXTENSIONS), leaf, key,
                true, null);
        try (TlsConnection connection = connect(server, true)) {
            assertThrows(IOException.class, () -> connection.read(ByteBuffer.allocate(64)));
        }
    }

    // ---- the control -------------------------------------------------------

    @Test
    void theCompleteFlightIsAcceptedWithTrust() throws IOException {
        acceptedAndReadable(ScriptedTlsServer.COMPLETE, true, false);
    }

    @Test
    void theCompleteFlightIsAcceptedWithoutTrust() throws IOException {
        acceptedAndReadable(ScriptedTlsServer.COMPLETE, false, false);
    }

    @Test
    void theCompleteFlightIsAcceptedOneRecordPerMessage() throws IOException {
        acceptedAndReadable(ScriptedTlsServer.COMPLETE, true, true);
    }

    @Test
    void aCertificateRequestInItsPlaceIsAccepted() throws IOException {
        acceptedAndReadable(ScriptedTlsServer.COMPLETE_WITH_REQUEST, true, false);
    }

    /**
     * The trust is still what decides about the certificate: the same
     * complete flight to a different name is refused, and not for its order.
     */
    @Test
    void theCompleteFlightToAnotherNameIsStillRefusedForItsName() {
        ScriptedTlsServer server = new ScriptedTlsServer(ScriptedTlsServer.COMPLETE, leaf, key);
        IOException refused = assertThrows(IOException.class,
                () -> ClientHandshake.connect(server, "other.example.com",
                        trust));
        assertTrue(refused.getMessage().contains("other.example.com"), refused.getMessage());
    }

    // ---- the second lock ----------------------------------------------------

    /**
     * The check before the application secrets, on its own - the order above
     * makes it unreachable today, which is exactly why it needs a test of its
     * own to stay in place.
     */
    @Test
    void noApplicationKeysForAServerThatProvedNothing() throws Exception {
        java.security.cert.X509Certificate certificate = (java.security.cert.X509Certificate)
                java.security.cert.CertificateFactory.getInstance("X.509")
                        .generateCertificate(new java.io.ByteArrayInputStream(leaf));
        for (List<java.security.cert.X509Certificate> chain
                : List.<List<java.security.cert.X509Certificate>>of(List.of(), List.of(certificate))) {
            for (boolean verified : new boolean[] {false, true}) {
                if (!chain.isEmpty() && verified) {
                    ClientHandshake.requireAuthenticatedServer(chain, true);
                    continue;
                }
                TlsProtocolException refused = assertThrows(TlsProtocolException.class,
                        () -> ClientHandshake.requireAuthenticatedServer(chain, verified));
                assertEquals(TlsAlertException.HANDSHAKE_FAILURE, refused.alert());
            }
        }
    }

    // ---- every short flight -------------------------------------------------

    /**
     * Every sequence of up to five of the five messages, without trust - the
     * mode that checks least. Exactly the two legal flights may get through;
     * everything else, 3 903 of them, has to be refused.
     */
    @Test
    void ofEveryFlightUpToFiveMessagesOnlyTheTwoLegalOnesAreAccepted() {
        List<List<Step>> accepted = new ArrayList<>();
        List<List<Step>> all = new ArrayList<>();
        sequences(new ArrayList<>(), 5, all);
        for (List<Step> script : all) {
            ScriptedTlsServer server = new ScriptedTlsServer(script, leaf, key);
            try (TlsConnection connection = connect(server, false)) {
                assertNotNull(connection.peerCertificate(), script + " connected without a certificate");
                accepted.add(script);
            } catch (IOException refused) {
                // what everything but the two legal flights has to end in
            }
        }
        assertEquals(java.util.Set.of(ScriptedTlsServer.COMPLETE,
                ScriptedTlsServer.COMPLETE_WITH_REQUEST), java.util.Set.copyOf(accepted),
                "of " + all.size() + " flights");
        assertEquals(2, accepted.size());
    }

    private static void sequences(List<Step> prefix, int remaining, List<List<Step>> out) {
        if (!prefix.isEmpty()) {
            out.add(List.copyOf(prefix));
        }
        if (remaining == 0) {
            return;
        }
        for (Step step : Step.values()) {
            prefix.add(step);
            sequences(prefix, remaining - 1, out);
            prefix.remove(prefix.size() - 1);
        }
    }

    // ---- plumbing ------------------------------------------------------------

    private static void acceptedAndReadable(List<Step> script, boolean withTrust, boolean split)
            throws IOException {
        ScriptedTlsServer server = new ScriptedTlsServer(script, leaf, key, split, null);
        try (TlsConnection connection = connect(server, withTrust)) {
            assertNotNull(connection.peerCertificate(), "the server was not authenticated");
            assertTrue(server.clientFinishedSeen(), "our Finished never reached the server");
            ByteBuffer greeting = ByteBuffer.allocate(ScriptedTlsServer.GREETING.length);
            while (greeting.hasRemaining()) {
                if (connection.read(greeting) < 0) {
                    throw new IOException("the greeting did not arrive");
                }
            }
            assertArrayEquals(ScriptedTlsServer.GREETING, greeting.array(),
                    "application keys derived over a different transcript than the server's");
            assertEquals(-1, server.alertReceived());
        }
    }

    static TlsConnection connect(ScriptedTlsServer server, boolean withTrust) throws IOException {
        return withTrust
                ? ClientHandshake.connect(server, HOSTNAME, trust)
                : ClientHandshake.connectWithoutAuthenticating(server, HOSTNAME);
    }
}
