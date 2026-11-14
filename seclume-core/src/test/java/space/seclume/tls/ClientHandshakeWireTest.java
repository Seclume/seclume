package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Arrays;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.inventory.CryptoInventory;

/**
 * What the client puts on the wire in a whole handshake, read where the
 * server reads it: a fresh random and session id each time, the server name
 * for a name and none for an address, the ChangeCipherSpec of the
 * middlebox-compatible shape - and the connection entered in the
 * cryptographic inventory once it stands.
 *
 * <p>A server accepts a ClientHello of zeroes, a missing ChangeCipherSpec,
 * a missing name; every other handshake test passed with each of them. PIT
 * let those faults survive on a fast runner.
 */
@Timeout(120)
class ClientHandshakeWireTest {

    private static final String HOSTNAME = "db.example.com";
    private static final int SERVER_NAME = 0;

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

    private static ScriptedTlsServer handshake(String host) throws IOException {
        ScriptedTlsServer server = new ScriptedTlsServer(ScriptedTlsServer.COMPLETE, leaf, key);
        ClientHandshake.connectWithoutAuthenticating(server, host).close();
        assertTrue(server.clientFinishedSeen(), "the handshake completed");
        return server;
    }

    /** The ClientHello's body after its header: version, random, session id, ... */
    private static final int RANDOM = Handshake.HEADER + 2;
    private static final int SESSION = RANDOM + 32;

    private static byte[] random(byte[] hello) {
        return Arrays.copyOfRange(hello, RANDOM, RANDOM + 32);
    }

    private static byte[] sessionId(byte[] hello) {
        assertEquals(32, hello[SESSION], "a 32-byte session id, the middlebox-compatible shape");
        return Arrays.copyOfRange(hello, SESSION + 1, SESSION + 1 + 32);
    }

    /** The host_name in the server_name extension, or null without one. */
    private static String serverName(byte[] hello) {
        int at = SESSION + 1 + (hello[SESSION] & 0xff);
        at += 2 + u16(hello, at);                        // cipher suites
        at += 1 + (hello[at] & 0xff);                    // compression methods
        int end = at + 2 + u16(hello, at);
        at += 2;
        while (at + 4 <= end) {
            int type = u16(hello, at);
            int length = u16(hello, at + 2);
            if (type == SERVER_NAME) {
                // server_name_list length (2), name_type (1), host_name length (2), host_name
                int nameLength = u16(hello, at + 4 + 3);
                return new String(hello, at + 4 + 5, nameLength, StandardCharsets.US_ASCII);
            }
            at += 4 + length;
        }
        assertEquals(end, at, "the extensions fill their block");
        return null;
    }

    private static int u16(byte[] b, int at) {
        return ((b[at] & 0xff) << 8) | (b[at + 1] & 0xff);
    }

    private static boolean zeroes(byte[] b) {
        for (byte x : b) {
            if (x != 0) {
                return false;
            }
        }
        return true;
    }

    @Test
    void everyHandshakeHasItsOwnRandomAndSessionId() throws IOException {
        byte[] first = handshake(HOSTNAME).clientHello();
        byte[] second = handshake(HOSTNAME).clientHello();
        assertNotNull(first);
        assertNotNull(second);
        assertFalse(zeroes(random(first)), "a random of zeroes");
        assertFalse(zeroes(sessionId(first)), "a session id of zeroes");
        assertFalse(Arrays.equals(random(first), random(second)), "the same random twice");
        assertFalse(Arrays.equals(sessionId(first), sessionId(second)), "the same session id twice");
    }

    @Test
    void aChangeCipherSpecGoesOutBeforeTheClientsSecondFlight() throws IOException {
        // RFC 8446 appendix D.4: with a session id, the middlebox-compatible
        // shape sends one, immediately before the client's Finished.
        assertEquals(1, handshake(HOSTNAME).changeCipherSpecsReceived());
    }

    @Test
    void aNameIsSentAsTheServerName() throws IOException {
        assertEquals(HOSTNAME, serverName(handshake(HOSTNAME).clientHello()));
        assertEquals("a0.example9", serverName(handshake("a0.example9").clientHello()));
    }

    @Test
    void anAddressIsNotSentAsAServerName() throws IOException {
        // RFC 6066 section 3: "Literal IPv4 and IPv6 addresses are not
        // permitted in HostName". Zero, nine and a leading colon included.
        for (String address : new String[] {"10.0.0.9", "::1", "2001:db8::7", "[::1]"}) {
            assertNull(serverName(handshake(address).clientHello()), address);
        }
    }

    @Test
    void anEstablishedConnectionIsInTheInventory() throws IOException {
        String peer = "inventory-" + System.nanoTime() + ".example";
        handshake(peer);
        assertTrue(CryptoInventory.snapshot().stream()
                .anyMatch(a -> a.kind() == CryptoInventory.Kind.PROTOCOL && peer.equals(a.facts().get("peer"))),
                "no TLS entry for " + peer);
    }

    @Test
    void aMessageOutOfOrderIsCalledByItsName() {
        // ServerFlightOrderTest proves each is refused; this, that the reason
        // names the message that came, for whoever reads it in a log.
        java.util.Map<String, java.util.List<ScriptedTlsServer.Step>> flights = new java.util.LinkedHashMap<>();
        flights.put("CertificateVerify", java.util.List.of(ScriptedTlsServer.Step.ENCRYPTED_EXTENSIONS,
                ScriptedTlsServer.Step.CERTIFICATE_VERIFY, ScriptedTlsServer.Step.CERTIFICATE,
                ScriptedTlsServer.Step.FINISHED));
        flights.put("Finished", java.util.List.of(ScriptedTlsServer.Step.FINISHED,
                ScriptedTlsServer.Step.ENCRYPTED_EXTENSIONS, ScriptedTlsServer.Step.CERTIFICATE,
                ScriptedTlsServer.Step.CERTIFICATE_VERIFY));
        flights.put("Certificate", java.util.List.of(ScriptedTlsServer.Step.CERTIFICATE,
                ScriptedTlsServer.Step.CERTIFICATE_VERIFY, ScriptedTlsServer.Step.FINISHED));
        flights.put("CertificateRequest", java.util.List.of(ScriptedTlsServer.Step.ENCRYPTED_EXTENSIONS,
                ScriptedTlsServer.Step.CERTIFICATE, ScriptedTlsServer.Step.CERTIFICATE_REQUEST,
                ScriptedTlsServer.Step.CERTIFICATE_VERIFY, ScriptedTlsServer.Step.FINISHED));
        flights.put("EncryptedExtensions", java.util.List.of(ScriptedTlsServer.Step.ENCRYPTED_EXTENSIONS,
                ScriptedTlsServer.Step.ENCRYPTED_EXTENSIONS, ScriptedTlsServer.Step.CERTIFICATE,
                ScriptedTlsServer.Step.CERTIFICATE_VERIFY, ScriptedTlsServer.Step.FINISHED));
        flights.forEach((name, script) -> {
            ScriptedTlsServer server = new ScriptedTlsServer(script, leaf, key);
            TlsProtocolException refused = org.junit.jupiter.api.Assertions.assertThrows(
                    TlsProtocolException.class, () -> ClientHandshake.connect(server, HOSTNAME, trust), name);
            assertTrue(refused.getMessage().contains("the server sent " + name + " where"),
                    refused.getMessage());
        });
    }

    @Test
    void theSameHelloIsSentWithATrustStore() throws IOException {
        // The authenticated path builds the same ClientHello.
        ScriptedTlsServer server = new ScriptedTlsServer(ScriptedTlsServer.COMPLETE, leaf, key);
        ClientHandshake.connect(server, HOSTNAME, trust).close();
        byte[] hello = server.clientHello();
        assertNotNull(hello);
        assertEquals(HOSTNAME, serverName(hello));
        assertArrayEquals(new byte[] {3, 3}, Arrays.copyOfRange(hello, Handshake.HEADER, Handshake.HEADER + 2),
                "legacy_version is TLS 1.2");
    }
}
