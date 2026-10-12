package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    /**
     * The intermediate certificate goes with the leaf - built by Windows from
     * the store - and the self-signed root at the top does not.
     */
    @Test
    void theIntermediateGoesWithTheLeaf() throws Exception {
        String unique = UUID.randomUUID().toString().substring(0, 8);
        String thumbprints = powershell(
                "$root = New-SelfSignedCertificate -Subject 'CN=seclume-root-" + unique + "' "
                + "-CertStoreLocation Cert:\\CurrentUser\\My -KeyAlgorithm ECDSA_nistP256 "
                + "-KeyUsage CertSign,DigitalSignature -TextExtension @('2.5.29.19={text}CA=true') "
                + "-NotAfter (Get-Date).AddDays(1); "
                + "$mid = New-SelfSignedCertificate -Subject 'CN=seclume-mid-" + unique + "' "
                + "-Signer $root -CertStoreLocation Cert:\\CurrentUser\\My "
                + "-KeyAlgorithm ECDSA_nistP256 -KeyUsage CertSign,DigitalSignature "
                + "-TextExtension @('2.5.29.19={text}CA=true') -NotAfter (Get-Date).AddDays(1); "
                + "$leaf = New-SelfSignedCertificate -Subject 'CN=seclume-leaf-" + unique + "' "
                + "-Signer $mid -CertStoreLocation Cert:\\CurrentUser\\My "
                + "-KeyAlgorithm ECDSA_nistP256 -KeyExportPolicy NonExportable "
                + "-KeyUsage DigitalSignature "
                + "-TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2') "
                + "-NotAfter (Get-Date).AddDays(1); "
                + "$root.Thumbprint + ',' + $mid.Thumbprint + ',' + $leaf.Thumbprint");
        String[] three = thumbprints.split(",");
        enrolled.addAll(List.of(three));
        try (WindowsStoreClientIdentity identity = new WindowsStoreClientIdentity(three[2],
                false)) {
            assertEquals(2, identity.chain().size(), "leaf and intermediate, no root");
            X509Certificate leaf = parse(identity.chain().get(0));
            X509Certificate middle = parse(identity.chain().get(1));
            assertEquals("CN=seclume-leaf-" + unique, leaf.getSubjectX500Principal().getName());
            assertEquals("CN=seclume-mid-" + unique, middle.getSubjectX500Principal().getName());
            assertEquals(leaf.getIssuerX500Principal(), middle.getSubjectX500Principal());
        }
    }

    /**
     * A renewed certificate - a new key, a new thumbprint, the same subject -
     * is found by its subject, the newest first, and taken up by an identity
     * that is already in use.
     */
    @Test
    void aRenewedCertificateIsTakenUpBySubject(@TempDir Path dir) throws Exception {
        String subject = "seclume-renew-" + UUID.randomUUID().toString().substring(0, 8);
        Enrolled first = enroll("Microsoft Software Key Storage Provider", dir, subject, -2);
        long before = RenewingStoreClientIdentity.lookEveryMillis;
        RenewingStoreClientIdentity.lookEveryMillis = 0;
        try (ClientIdentity identity = ClientIdentities.of(Map.of(
                ClientIdentities.SUBJECT, subject))) {
            assertEquals(first.thumbprint(),
                    WindowsStoreClientIdentity.newestBySubject("CN=" + subject, false));
            handshake(identity.forHandshake(), first.certificate());

            Enrolled renewed = enroll("Microsoft Software Key Storage Provider", dir, subject,
                    -1);
            ClientIdentity now = identity.forHandshake();
            assertArrayEquals(renewed.certificate().getEncoded(), now.chain().get(0),
                    "the renewed certificate was not taken up");
            handshake(now, renewed.certificate());
            assertEquals(1, ((RenewingStoreClientIdentity) identity).renewals());
        } finally {
            RenewingStoreClientIdentity.lookEveryMillis = before;
        }
    }

    @Test
    void aSubjectThatIsNotThereSaysSo() {
        IllegalArgumentException missing = assertThrows(IllegalArgumentException.class,
                () -> WindowsStoreClientIdentity.newestBySubject("seclume-nobody-" + UUID
                        .randomUUID(), false));
        assertTrue(missing.getMessage().contains("valid now"), missing.getMessage());
    }

    private static X509Certificate parse(byte[] der) throws Exception {
        try (InputStream in = new java.io.ByteArrayInputStream(der)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(in);
        }
    }

    // ------------------------------------------------------------- fixtures --

    private record Enrolled(String thumbprint, X509Certificate certificate) {
    }

    private static Enrolled enroll(String provider, Path dir) throws Exception {
        return enroll(provider, dir, "seclume-d3-test", 0);
    }

    /** @param startDays when it becomes valid, in days from now - to tell renewals apart */
    private static Enrolled enroll(String provider, Path dir, String commonName, int startDays)
            throws Exception {
        Path exported = dir.resolve("client-" + UUID.randomUUID() + ".cer");
        String thumbprint = powershell(
                "$c = New-SelfSignedCertificate -Subject 'CN=" + commonName + "' "
                + "-NotBefore (Get-Date).AddDays(" + startDays + ") "
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
