package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.crypto.HybridMlKem;

/**
 * The two system properties that change what the client offers:
 * {@code seclume.tls.tls12=false} keeps it to TLS 1.3, and
 * {@code seclume.tls.postQuantum=false} leaves the post-quantum hybrid out of
 * the ClientHello, which otherwise carries it wherever the native library
 * has ML-KEM. Read where the server reads them, in the ClientHello.
 *
 * <p>Isolated: a system property is the whole JVM's.
 */
@Isolated
@Timeout(120)
class ClientHandshakePropertiesTest {

    private static final String HOSTNAME = "db.example.com";
    private static final int SUPPORTED_GROUPS = 10;
    private static final int X25519MLKEM768 = 0x11ec;

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

    private static void with(String property, String value, Runnable check) {
        String before = System.getProperty(property);
        try {
            if (value == null) {
                System.clearProperty(property);
            } else {
                System.setProperty(property, value);
            }
            check.run();
        } finally {
            if (before == null) {
                System.clearProperty(property);
            } else {
                System.setProperty(property, before);
            }
        }
    }

    @Test
    void tls12IsOfferedUnlessThePropertySaysFalseInAnyCase() {
        with("seclume.tls.tls12", null,
                () -> assertEquals(ClientHello.Offer.TLS13_AND_12, ClientHandshake.defaultOffer()));
        with("seclume.tls.tls12", "true",
                () -> assertEquals(ClientHello.Offer.TLS13_AND_12, ClientHandshake.defaultOffer()));
        with("seclume.tls.tls12", "false",
                () -> assertEquals(ClientHello.Offer.TLS13, ClientHandshake.defaultOffer()));
        with("seclume.tls.tls12", "FALSE",
                () -> assertEquals(ClientHello.Offer.TLS13, ClientHandshake.defaultOffer()));
    }

    /** The groups of the ClientHello the client sends in a whole handshake. */
    private static Set<Integer> offeredGroups() {
        ScriptedTlsServer server = new ScriptedTlsServer(ScriptedTlsServer.COMPLETE, leaf, key);
        try {
            ClientHandshake.connectWithoutAuthenticating(server, HOSTNAME).close();
        } catch (IOException e) {
            throw new AssertionError("the handshake failed", e);
        }
        byte[] hello = server.clientHello();
        assertNotNull(hello);
        int session = Handshake.HEADER + 2 + 32;
        int at = session + 1 + (hello[session] & 0xff);
        at += 2 + u16(hello, at);
        at += 1 + (hello[at] & 0xff);
        int end = at + 2 + u16(hello, at);
        at += 2;
        while (at + 4 <= end) {
            int type = u16(hello, at);
            int length = u16(hello, at + 2);
            if (type == SUPPORTED_GROUPS) {
                Set<Integer> groups = new HashSet<>();
                for (int g = at + 6; g < at + 4 + length; g += 2) {
                    groups.add(u16(hello, g));
                }
                return groups;
            }
            at += 4 + length;
        }
        throw new AssertionError("no supported_groups in the ClientHello");
    }

    private static int u16(byte[] b, int at) {
        return ((b[at] & 0xff) << 8) | (b[at + 1] & 0xff);
    }

    @Test
    void theHybridIsOfferedExactlyWhereTheLibraryHasIt() {
        with("seclume.tls.postQuantum", null,
                () -> assertEquals(HybridMlKem.available(), offeredGroups().contains(X25519MLKEM768)));
    }

    @Test
    void thePropertyLeavesTheHybridOut() {
        with("seclume.tls.postQuantum", "false",
                () -> assertFalse(offeredGroups().contains(X25519MLKEM768)));
        with("seclume.tls.postQuantum", "False",
                () -> assertFalse(offeredGroups().contains(X25519MLKEM768)));
    }
}
