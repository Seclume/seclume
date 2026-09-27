package space.seclume.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.lang.ref.Reference;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import space.seclume.crypto.OpenSslSigningKey;
import space.seclume.tck.NoSecretInHeap;

/**
 * A TLS server whose private key is in OpenSSL: the JDK's own client connects
 * to the JDK's own server, and only the signature comes from here.
 */
class ServerKeyTest {

    @TempDir
    static Path directory;

    static KeyFiles rsa;
    static KeyFiles ec256;
    static KeyFiles ec384;

    @BeforeAll
    static void keys() throws Exception {
        assumeTrue(OpenSslSigningKey.available(), "OpenSSL 3 on 64-bit Linux");
        rsa = KeyFiles.make(directory.resolve("rsa"), "rsa:2048");
        ec256 = KeyFiles.make(directory.resolve("ec256"), "ec:P-256");
        ec384 = KeyFiles.make(directory.resolve("ec384"), "ec:P-384");
    }

    private static KeyFiles files(String name) {
        return switch (name) {
            case "rsa" -> rsa;
            case "ec256" -> ec256;
            default -> ec384;
        };
    }

    @ParameterizedTest
    @CsvSource({
            "rsa,   TLSv1.3, rsa_pss_rsae_sha256",
            "rsa,   TLSv1.3, rsa_pss_rsae_sha512",
            "rsa,   TLSv1.2, rsa_pss_rsae_sha384",
            "rsa,   TLSv1.2, rsa_pkcs1_sha256",
            "rsa,   TLSv1.2, rsa_pkcs1_sha512",
            "ec256, TLSv1.3, ecdsa_secp256r1_sha256",
            "ec384, TLSv1.3, ecdsa_secp384r1_sha384",
            "ec256, TLSv1.2, ecdsa_secp256r1_sha256"})
    void aJdkClientConnects(String key, String protocol, String scheme) throws Exception {
        KeyFiles files = files(key);
        SSLContext server = SeclumeKeys.sslContext(files.certificate(), files.spec());
        assertEquals("hello", roundTrip(server, files, protocol, scheme));
    }

    /** The server's CertificateVerify, signed with the opaque key, is a Signature event. */
    @Test
    void aHandshakeSignatureIsRecorded() throws Exception {
        SSLContext server = SeclumeKeys.sslContext(ec256.certificate(), ec256.spec());
        var events = space.seclume.tck.Recorded.during(
                () -> roundTrip(server, ec256, "TLSv1.3", null), "space.seclume.Signature");
        assertTrue(!events.isEmpty(), "no signature was recorded");
        assertEquals("SHA256withEC", events.get(0).getString("algorithm"));
        assertEquals("sign", events.get(0).getString("operation"));
        assertTrue(events.get(0).getBoolean("succeeded"));
    }

    @Test
    void aCertificateThatIsNotTheKeysIsRefused() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> SeclumeKeys.keyManager(ec256.certificate(), rsa.spec()));
        assertTrue(refused.getMessage().contains("is not the key's"), refused.getMessage());
    }

    @Test
    void theKeyHasNothingToGive() throws Exception {
        PrivateKey key = SeclumeKeys.privateKey(rsa.spec());
        assertEquals("RSA", key.getAlgorithm());
        assertNull(key.getEncoded());
        assertNull(key.getFormat());
        assertThrows(NotSerializableException.class,
                () -> new ObjectOutputStream(new ByteArrayOutputStream()).writeObject(key));

        // the JDK's providers step aside for it; its signature verifies with the JDK
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key);
        signer.update("to be signed".getBytes());
        byte[] signature = signer.sign();
        assertEquals(SeclumeKeyProvider.NAME, signer.getProvider().getName());
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(SeclumeKeys.keyPair(rsa.spec()).getPublic());
        verifier.update("to be signed".getBytes());
        assertTrue(verifier.verify(signature));

        ((javax.security.auth.Destroyable) key).destroy();
        Signature again = Signature.getInstance("SHA256withRSA");
        again.initSign(key);
        again.update(new byte[1]);
        assertThrows(java.security.SignatureException.class, again::sign);
    }

    @Test
    void anEcKeySignsForTheJdkToVerify() throws Exception {
        var pair = SeclumeKeys.keyPair(ec384.spec());
        Signature signer = Signature.getInstance("SHA384withECDSA");
        signer.initSign(pair.getPrivate());
        signer.update(new byte[] {1, 2, 3});
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance("SHA384withECDSA");
        verifier.initVerify(pair.getPublic());
        verifier.update(new byte[] {1, 2, 3});
        assertTrue(verifier.verify(signature));
    }

    @Test
    void theKeyIsNotOnTheHeap() throws Exception {
        for (KeyFiles files : new KeyFiles[] {rsa, ec256}) {
            SSLContext server = SeclumeKeys.sslContext(files.certificate(), files.spec());
            roundTrip(server, files, "TLSv1.3", null);
            roundTrip(server, files, "TLSv1.2", null);
            NoSecretInHeap.assertAbsent(files.der());
            NoSecretInHeap.assertAbsent(files.secret());
        }

        // the control: the same key the usual way, and the search finds it
        PrivateKey usual = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(rsa.der())));
        AssertionError found = assertThrows(AssertionError.class,
                () -> NoSecretInHeap.assertAbsent(rsa.secret()));
        assertTrue(found.getMessage().contains("the secret is on the heap"), found.getMessage());
        Reference.reachabilityFence(usual);
    }

    /** One connection: the client sends "hello", the server echoes it back. */
    static String roundTrip(SSLContext server, KeyFiles files, String protocol, String scheme)
            throws Exception {
        try (SSLServerSocket listener = (SSLServerSocket) server.getServerSocketFactory()
                .createServerSocket(0)) {
            listener.setEnabledProtocols(new String[] {protocol});
            CompletableFuture<Void> served = CompletableFuture.runAsync(() -> {
                try (SSLSocket accepted = (SSLSocket) listener.accept()) {
                    InputStream in = accepted.getInputStream();
                    OutputStream out = accepted.getOutputStream();
                    out.write(in.readNBytes(5));
                    out.flush();
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            });
            SSLContext client = SSLContext.getInstance("TLS");
            client.init(null, trusting(files.certificate()).getTrustManagers(), null);
            try (SSLSocket socket = (SSLSocket) client.getSocketFactory()
                    .createSocket("localhost", listener.getLocalPort())) {
                SSLParameters parameters = socket.getSSLParameters();
                parameters.setProtocols(new String[] {protocol});
                if (scheme != null) {
                    parameters.setSignatureSchemes(new String[] {scheme});
                }
                socket.setSSLParameters(parameters);
                socket.getOutputStream().write("hello".getBytes());
                socket.getOutputStream().flush();
                String echoed = new String(socket.getInputStream().readNBytes(5));
                assertEquals(protocol, socket.getSession().getProtocol());
                served.get(10, TimeUnit.SECONDS);
                return echoed;
            }
        }
    }

    static TrustManagerFactory trusting(Path certificate) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        X509Certificate[] chain = SeclumeKeys.certificates(certificate);
        store.setCertificateEntry("server", chain[0]);
        TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX");
        factory.init(store);
        return factory;
    }
}
