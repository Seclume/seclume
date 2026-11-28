package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.InputStream;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * tls-server-end-point hashes the server's certificate with the hash of its
 * signature. An RSASSA-PSS certificate's name says no hash - it sits in the
 * parameters - and the login failed wherever the server offered
 * SCRAM-SHA-256-PLUS. The hash is read from the parameters now.
 */
class ChannelBindingPssTest {

    @Test
    void aPssCertificateIsHashedWithItsParametersHash(@TempDir Path directory) throws Exception {
        Path store = directory.resolve("pss.p12");
        Process keytool = new ProcessBuilder(List.of(
                Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
                "-genkeypair", "-alias", "server", "-keyalg", "RSASSA-PSS", "-keysize", "3072",
                "-dname", "CN=server", "-validity", "2", "-keystore", store.toString(),
                "-storetype", "PKCS12", "-storepass", "changeit")).redirectErrorStream(true).start();
        String output = new String(keytool.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!keytool.waitFor(60, TimeUnit.SECONDS) || keytool.exitValue() != 0) {
            throw new IllegalStateException("keytool failed: " + output);
        }
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(store)) {
            keys.load(in, "changeit".toCharArray());
        }
        X509Certificate certificate = (X509Certificate) keys.getCertificate("server");
        assertEquals("RSASSA-PSS", certificate.getSigAlgName());

        java.security.AlgorithmParameters parameters =
                java.security.AlgorithmParameters.getInstance("RSASSA-PSS");
        parameters.init(certificate.getSigAlgParams());
        String digest = parameters.getParameterSpec(java.security.spec.PSSParameterSpec.class)
                .getDigestAlgorithm();
        byte[] expected = MessageDigest.getInstance(digest).digest(certificate.getEncoded());

        byte[] out = new byte[64];
        int length = ChannelBinding.endPoint(certificate, MemorySegment.ofArray(out));
        assertArrayEquals(expected, java.util.Arrays.copyOf(out, length), digest);
    }
}
