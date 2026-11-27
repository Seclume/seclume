package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * A server that selects an application protocol the client never offered -
 * h2 where the client said postgresql - is not talked to in a language it did
 * not agree to: the handshake is refused, before the client's Finished.
 */
class AlpnSelectionTest {

    private static final String HOSTNAME = "db.example.com";

    private static CertificateTrust trust;
    private static byte[] leaf;
    private static PrivateKey key;

    @BeforeAll
    static void issueAServerCertificate() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        TestCertificates certificates = TestCertificates.generate();
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

    @Test
    void aProtocolTheClientDidNotOfferIsRefused() {
        ScriptedTlsServer server = new ScriptedTlsServer(ScriptedTlsServer.COMPLETE, leaf, key)
                .encryptedExtensions(ScriptedTlsServer.alpnExtensions("h2"));
        IOException refused = assertThrows(IOException.class,
                () -> ClientHandshake.connect(server, HOSTNAME, trust, null, "postgresql").close());
        assertTrue(String.valueOf(refused.getMessage()).contains("h2")
                || String.valueOf(refused.getMessage()).contains("postgresql"),
                refused.getMessage());
        assertTrue(!server.clientFinishedSeen(), "the client finished a handshake with h2");
    }

    @Test
    void theProtocolOfferedIsTaken() throws IOException {
        ScriptedTlsServer server = new ScriptedTlsServer(ScriptedTlsServer.COMPLETE, leaf, key)
                .encryptedExtensions(ScriptedTlsServer.alpnExtensions("postgresql"));
        ClientHandshake.connect(server, HOSTNAME, trust, null, "postgresql").close();
        assertTrue(server.clientFinishedSeen());
    }
}
