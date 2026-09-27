package space.seclume.ssh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.ref.Reference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.List;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.crypto.OpenSslSigningKey;
import space.seclume.tck.NoSecretInHeap;

/** SFTP against Apache SSHD's own server, which accepts one public key. */
class SftpLoginTest {

    @TempDir
    static Path directory;

    static KeyFiles rsa;
    static KeyFiles ec256;
    static KeyFiles ec521;

    private SshServer server;

    @BeforeAll
    static void keys() throws Exception {
        assumeTrue(OpenSslSigningKey.available(), "OpenSSL 3 on 64-bit Linux");
        rsa = KeyFiles.make(directory.resolve("rsa"), "rsa:3072");
        ec256 = KeyFiles.make(directory.resolve("ec256"), "ec:P-256");
        ec521 = KeyFiles.make(directory.resolve("ec521"), "ec:P-521");
    }

    private int serve(PublicKey allowed) throws Exception {
        Path root = Files.createDirectories(directory.resolve("root"));
        server = SshServer.setUpDefaultServer();
        server.setHost("127.0.0.1");
        server.setPort(0);
        server.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(
                directory.resolve("hostkey.ser")));
        server.setPublickeyAuthenticator((user, key, session) ->
                user.equals("deploy") && KeyUtils.compareKeys(key, allowed));
        server.setSubsystemFactories(List.of(new SftpSubsystemFactory()));
        server.setFileSystemFactory(new VirtualFileSystemFactory(root));
        server.start();
        return server.getPort();
    }

    @AfterEach
    void stop() throws Exception {
        if (server != null) {
            server.stop(true);
        }
    }

    private static String upload(int port, String keySpec, String name) throws Exception {
        try (SshClient client = SeclumeSsh.withIdentity(SshClient.setUpDefaultClient(),
                keySpec)) {
            client.start();
            try (ClientSession session = client.connect("deploy", "127.0.0.1", port)
                    .verify(Duration.ofSeconds(10)).getSession()) {
                session.auth().verify(Duration.ofSeconds(10));
                try (SftpClient sftp = SftpClientFactory.instance().createSftpClient(session)) {
                    try (OutputStream out = sftp.write(name)) {
                        out.write("report".getBytes(StandardCharsets.UTF_8));
                    }
                    try (InputStream in = sftp.read(name)) {
                        return new String(in.readAllBytes(), StandardCharsets.UTF_8);
                    }
                }
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"rsa", "ec256", "ec521"})
    void logsInWithTheKeyAndTransfers(String kind) throws Exception {
        KeyFiles files = switch (kind) {
            case "rsa" -> rsa;
            case "ec256" -> ec256;
            default -> ec521;
        };
        int port = serve(SeclumeSsh.keyPair(files.spec()).getPublic());
        assertEquals("report", upload(port, files.spec(), kind + ".txt"));
    }

    @Test
    void anotherKeyIsNotLetIn() throws Exception {
        int port = serve(SeclumeSsh.keyPair(rsa.spec()).getPublic());
        Exception refused = assertThrows(Exception.class,
                () -> upload(port, ec256.spec(), "x.txt"));
        assertTrue(String.valueOf(refused.getMessage()).toLowerCase().contains("auth"),
                String.valueOf(refused.getMessage()));
    }

    @Test
    void theKeyIsNotOnTheHeap() throws Exception {
        int port = serve(SeclumeSsh.keyPair(rsa.spec()).getPublic());
        for (int i = 0; i < 2; i++) {
            upload(port, rsa.spec(), "heap" + i + ".txt");
        }
        NoSecretInHeap.assertAbsent(rsa.der());
        NoSecretInHeap.assertAbsent(rsa.secret());

        PrivateKey usual = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(rsa.der())));
        AssertionError found = assertThrows(AssertionError.class,
                () -> NoSecretInHeap.assertAbsent(rsa.secret()));
        assertTrue(found.getMessage().contains("the secret is on the heap"), found.getMessage());
        Reference.reachabilityFence(usual);
    }
}
