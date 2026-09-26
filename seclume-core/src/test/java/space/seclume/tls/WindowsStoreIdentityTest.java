package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.Transport;

/**
 * A client certificate whose key Windows holds and will not give out.
 *
 * <p>The certificate is enrolled for the test with PowerShell - an ECDSA P-256
 * key in the software key storage provider, <b>non-exportable</b> - and
 * removed again, key and all, when the test is done. Then a real mutual TLS
 * handshake is run with it against a JSSE server that trusts exactly that
 * certificate: the server checking the signature is the proof that Windows
 * signed for the right key.
 *
 * <p>And the property the class exists for is checked from outside it: asking
 * Windows to export the key fails. The identity has no export path of its own
 * to check - there is no call in it that returns a key - so the evidence has
 * to be that the key cannot be had at all.
 *
 * <p>If the machine has a TPM, the same is done once more with the key
 * generated inside it (Microsoft Platform Crypto Provider). Without one that
 * case is skipped and says so.
 */
@Timeout(180)
class WindowsStoreIdentityTest {

    private static final String HOSTNAME = "db.example.com";

    private static TestCertificates serverAuthority;
    private static TestCertificates.Issued server;
    private static final List<String> enrolled = new ArrayList<>();

    @BeforeAll
    static void onWindowsWithAServer() throws Exception {
        Assumptions.assumeTrue(System.getProperty("os.name", "").toLowerCase(Locale.ROOT)
                .contains("windows"), "the Windows certificate store needs Windows");
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        serverAuthority = TestCertificates.generate();
        server = serverAuthority.issue("server", "san=dns:" + HOSTNAME,
                "ku:c=digitalSignature", "eku=serverAuth");
    }

    @AfterAll
    static void removeWhatWasEnrolled() throws Exception {
        for (String thumbprint : enrolled) {
            // -DeleteKey: the certificate and its key, not only the entry.
            powershell("Remove-Item -Path Cert:\\CurrentUser\\My\\" + thumbprint + " -DeleteKey");
        }
        if (serverAuthority != null) {
            serverAuthority.close();
        }
    }

    @Test
    void aKeyWindowsKeepsSignsTheHandshake(@TempDir Path dir) throws Exception {
        Enrolled client = enroll("Microsoft Software Key Storage Provider", dir);

        try (ClientIdentity identity = ClientIdentities.of(Map.of(
                ClientIdentities.THUMBPRINT, client.thumbprint()))) {
            assertInstanceOf(WindowsStoreClientIdentity.class, identity);
            assertArrayEquals(client.certificate().getEncoded(), identity.chain().get(0),
                    "the certificate sent is not the one enrolled");
            handshake(identity, client.certificate());
        }
    }

    /** The key cannot be had - asked of Windows directly, not of this class. */
    @Test
    void theKeyCannotBeExported(@TempDir Path dir) throws Exception {
        Enrolled client = enroll("Microsoft Software Key Storage Provider", dir);
        String answer = powershell(
                "$c = Get-Item Cert:\\CurrentUser\\My\\" + client.thumbprint() + "; "
                + "$k = [System.Security.Cryptography.X509Certificates."
                + "ECDsaCertificateExtensions]::GetECDsaPrivateKey($c); "
                + "try { $k.ExportParameters($true) | Out-Null; 'EXPORTED' } "
                + "catch { 'REFUSED' }");
        assertEquals("REFUSED", answer,
                "Windows handed the private key out - then it was never only in Windows");
    }

    /** And inside the TPM, where there is a TPM. */
    @Test
    void aKeyInsideTheTpmSignsTheHandshake(@TempDir Path dir) throws Exception {
        Enrolled client;
        try {
            client = enroll("Microsoft Platform Crypto Provider", dir);
        } catch (IOException noTpm) {
            Assumptions.abort("no TPM usable for this account: " + noTpm.getMessage());
            return;
        }
        try (ClientIdentity identity = ClientIdentities.of(Map.of(
                ClientIdentities.THUMBPRINT, client.thumbprint()))) {
            handshake(identity, client.certificate());
        }
    }

    @Test
    void aThumbprintThatIsNotThereSaysSo() {
        IllegalArgumentException missing = assertThrows(IllegalArgumentException.class,
                () -> ClientIdentities.of(Map.of(ClientIdentities.THUMBPRINT,
                        "0000000000000000000000000000000000000000")));
        assertEquals(true, missing.getMessage().contains("CurrentUser\\My"),
                missing.getMessage());
    }

    // ------------------------------------------------------------- fixtures --

    private record Enrolled(String thumbprint, X509Certificate certificate) {
    }

    private static Enrolled enroll(String provider, Path dir) throws Exception {
        Path exported = dir.resolve("client-" + UUID.randomUUID() + ".cer");
        String thumbprint = powershell(
                "$c = New-SelfSignedCertificate -Subject 'CN=seclume-d3-test' "
                + "-CertStoreLocation Cert:\\CurrentUser\\My -KeyAlgorithm ECDSA_nistP256 "
                + "-KeyExportPolicy NonExportable -Provider '" + provider + "' "
                + "-KeyUsage DigitalSignature "
                + "-TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2') "
                + "-NotAfter (Get-Date).AddDays(1); "
                + "Export-Certificate -Cert $c -FilePath '" + exported + "' -Type CERT | Out-Null; "
                + "$c.Thumbprint");
        enrolled.add(thumbprint);
        try (InputStream in = Files.newInputStream(exported)) {
            X509Certificate certificate = (X509Certificate) CertificateFactory
                    .getInstance("X.509").generateCertificate(in);
            return new Enrolled(thumbprint, certificate);
        }
    }

    private static String powershell(String script) throws Exception {
        Process process = new ProcessBuilder("powershell", "-NoProfile", "-NonInteractive",
                "-Command", script).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(),
                StandardCharsets.UTF_8).strip();
        if (process.waitFor() != 0 || output.contains("FullyQualifiedErrorId")) {
            throw new IOException(output);
        }
        String[] lines = output.split("\\R");
        return lines[lines.length - 1].strip();
    }

    private static void handshake(ClientIdentity identity, X509Certificate client)
            throws Exception {
        KeyStore clientTrust = KeyStore.getInstance("PKCS12");
        clientTrust.load(null, null);
        clientTrust.setCertificateEntry("client", client);
        SSLContext context = contextFor(server.keystore(), clientTrust);

        try (EchoServer echo = EchoServer.start(context, true);
                Transport socket = SocketTransport.wrap(java.nio.channels.SocketChannel.open(
                        new InetSocketAddress(InetAddress.getLoopbackAddress(), echo.port())));
                TlsConnection tls = ClientHandshake.connect(socket, HOSTNAME,
                        CertificateTrust.of(serverAuthority.trustStore()), identity)) {
            // A handshake that returned is not yet an accepted client
            // certificate in TLS 1.3; data coming back is.
            byte[] sent = "select 1".getBytes(StandardCharsets.US_ASCII);
            tls.write(ByteBuffer.wrap(sent));
            ByteBuffer back = ByteBuffer.allocate(sent.length);
            while (back.hasRemaining()) {
                if (tls.read(back) < 0) {
                    throw new IOException("the server refused the client certificate");
                }
            }
            assertArrayEquals(sent, back.array());
        }
    }

    private static SSLContext contextFor(Path keystore, KeyStore trust) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        KeyManagerFactory keys =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, TestCertificates.PASSWORD.toCharArray());
        TrustManagerFactory trusts =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trusts.init(trust);
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(keys.getKeyManagers(), trusts.getTrustManagers(), null);
        return context;
    }
}
