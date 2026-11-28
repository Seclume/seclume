package space.seclume.ldap;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

/**
 * An LDAP server that answers a simple bind with the password it was sent:
 * "invalid credentials for 'the-password'". JNDI makes a String of that
 * diagnostic, and the exception carries it into every log. The bytes after
 * the bind are masked in native memory before JNDI reads them.
 */
@Timeout(120)
class EchoedBindPasswordTest {

    private static final String DECOY = "DECOY-ldap-bind-" + Long.toHexString(System.nanoTime());
    private static final String STORE_PASSWORD = "echo-test";

    private static Path keytool() {
        return Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name", "").startsWith("Windows") ? "keytool.exe" : "keytool");
    }

    private static void run(String... command) throws Exception {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        process.getInputStream().readAllBytes();
        assertTrue(process.waitFor(60, TimeUnit.SECONDS) && process.exitValue() == 0,
                "keytool failed");
    }

    private static int length(InputStream in) throws Exception {
        int first = in.read();
        if (first < 0x80) {
            return first;
        }
        int value = 0;
        for (int i = 0; i < (first & 0x7f); i++) {
            value = (value << 8) | in.read();
        }
        return value;
    }

    @Test
    void aBindPasswordTheServerRepeatsNeverReachesTheException(@TempDir Path directory)
            throws Exception {
        Path store = directory.resolve("server.p12");
        run(keytool().toString(), "-genkeypair", "-alias", "ldap", "-keyalg", "EC",
                "-groupname", "secp256r1", "-dname", "CN=localhost", "-ext", "san=dns:localhost",
                "-validity", "2", "-storetype", "PKCS12", "-keystore", store.toString(),
                "-storepass", STORE_PASSWORD, "-keypass", STORE_PASSWORD);
        Path certificate = directory.resolve("server.pem");
        run(keytool().toString(), "-exportcert", "-rfc", "-alias", "ldap", "-keystore",
                store.toString(), "-storepass", STORE_PASSWORD, "-file", certificate.toString());
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(store)) {
            keys.load(in, STORE_PASSWORD.toCharArray());
        }
        KeyManagerFactory factory = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keys, STORE_PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(factory.getKeyManagers(), null, null);
        Path passwordFile = directory.resolve("password");
        Files.writeString(passwordFile, DECOY);

        try (SSLServerSocket listener = (SSLServerSocket) context.getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            listener.setSoTimeout(30_000);
            CompletableFuture<Boolean> passwordArrived = CompletableFuture.supplyAsync(() -> {
                try (SSLSocket client = (SSLSocket) listener.accept()) {
                    InputStream in = client.getInputStream();
                    OutputStream out = client.getOutputStream();
                    if (in.read() != 0x30) {
                        return false;
                    }
                    byte[] request = in.readNBytes(length(in));
                    String seen = new String(request, StandardCharsets.ISO_8859_1);
                    int messageId = request[2] & 0xff;            // 02 01 <id>
                    byte[] text = ("invalid credentials for '" + DECOY + "'")
                            .getBytes(StandardCharsets.US_ASCII);
                    ByteArrayOutputStream op = new ByteArrayOutputStream();
                    op.writeBytes(new byte[] {0x0a, 0x01, 49, 0x04, 0x00, 0x04, (byte) text.length});
                    op.writeBytes(text);
                    ByteArrayOutputStream message = new ByteArrayOutputStream();
                    message.writeBytes(new byte[] {0x02, 0x01, (byte) messageId, 0x61,
                        (byte) op.size()});
                    message.writeBytes(op.toByteArray());
                    out.write(0x30);
                    out.write(message.size());
                    out.write(message.toByteArray());
                    out.flush();
                    in.read();                                     // until the client goes
                    return seen.contains(DECOY);
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            });
            SeclumeLdap ldap = SeclumeLdap.of("ldaps://localhost:" + listener.getLocalPort()
                    + "/dc=example,dc=org?user=cn=service,dc=example,dc=org"
                    + "&tlsRootCert=" + certificate.toString().replace('\\', '/')
                    + "&provider=file&path=" + passwordFile.toString().replace('\\', '/'));
            NamingException refused = assertThrows(NamingException.class,
                    () -> SeclumeLdap.asService(() -> new InitialDirContext(ldap.environment()))
                            .close());
            assertTrue(passwordArrived.get(30, TimeUnit.SECONDS),
                    "the stand-in never got the password - the test would prove nothing");
            java.io.StringWriter all = new java.io.StringWriter();
            refused.printStackTrace(new java.io.PrintWriter(all));
            assertFalse(all.toString().contains(DECOY),
                    "the echoed bind password is in the exception: " + refused);
            assertTrue(all.toString().contains("49"), "the result code went too: " + refused);
        }
    }
}
