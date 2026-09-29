package space.seclume.ssh;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.ref.Reference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;

import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

import space.seclume.crypto.OpenSslSigningKey;
import space.seclume.tck.NoSecretInHeap;

/**
 * JSch against SSHD's SFTP server, with keys as ssh-keygen writes them - Ed25519
 * among them, which the server verifies with net.i2p's EdDSA.
 */
class JschLoginTest {

    @TempDir
    static Path directory;

    private SshServer server;

    @BeforeAll
    static void keys() throws Exception {
        assumeTrue(OpenSslSigningKey.available(), "OpenSSL 3 on 64-bit Linux");
        Path script = directory.resolve("keys.sh");
        Files.writeString(script, String.join("\n",
                "command -v ssh-keygen >/dev/null || exit 3",
                "set -e", "cd '" + directory + "'",
                "ssh-keygen -q -t ed25519 -N '' -f ed25519",
                "ssh-keygen -q -t ecdsa -b 384 -N '' -f ecdsa",
                "ssh-keygen -q -t rsa -b 3072 -N '' -f rsa",
                "cp rsa rsa.pkcs8 && ssh-keygen -q -p -N '' -m PKCS8 -f rsa.pkcs8",
                "openssl pkcs8 -topk8 -nocrypt -in rsa.pkcs8 -outform DER -out rsa.der",
                "openssl pkey -in rsa.pkcs8 -text -noout | sed -n '/^prime1:/,/^[a-zA-Z]/p'"
                        + " | sed '1d;$d' | tr -d ' :\\n' | sed 's/^00//'"
                        + " | perl -ne 'print pack(\"H*\", $_)' > rsa.prime.bin", ""));
        int exit = space.seclume.tck.Shell.builder(script.toString()).start().waitFor();
        assumeTrue(exit != 3, "ssh-keygen is not installed");
        assertEquals(0, exit);
    }

    private int serve(PublicKey allowed) throws Exception {
        Path root = Files.createDirectories(directory.resolve("root"));
        server = SshServer.setUpDefaultServer();
        server.setHost("127.0.0.1");
        server.setPort(0);
        server.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(
                directory.resolve("hostkey.ser")));
        byte[] expected = allowed.getEncoded();
        server.setPublickeyAuthenticator((user, key, session) ->
                user.equals("deploy") && java.util.Arrays.equals(key.getEncoded(), expected));
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

    private static byte[] transfer(int port, String key, String name, byte[] content)
            throws Exception {
        JSch jsch = new JSch();
        SeclumeJschIdentity.add(jsch, "provider=file&path=" + directory.resolve(key));
        Session session = jsch.getSession("deploy", "127.0.0.1", port);
        session.setConfig("StrictHostKeyChecking", "no");
        session.setConfig("PreferredAuthentications", "publickey");
        session.connect(10_000);
        try {
            ChannelSftp sftp = (ChannelSftp) session.openChannel("sftp");
            sftp.connect(10_000);
            sftp.put(new ByteArrayInputStream(content), name);
            ByteArrayOutputStream back = new ByteArrayOutputStream();
            sftp.get(name, back);
            sftp.disconnect();
            return back.toByteArray();
        } finally {
            session.disconnect();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"ed25519", "ecdsa", "rsa"})
    void logsInAndTransfers(String key) throws Exception {
        int port = serve(SeclumeSsh.keyPair("provider=file&path=" + directory.resolve(key))
                .getPublic());
        byte[] content = ("report for " + key).getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(content, transfer(port, key, key + ".txt", content));
    }

    @Test
    void anotherKeyIsNotLetIn() throws Exception {
        int port = serve(SeclumeSsh.keyPair("provider=file&path=" + directory.resolve("rsa"))
                .getPublic());
        assertThrows(JSchException.class, () -> transfer(port, "ed25519", "x.txt",
                new byte[] {1}));
    }

    @Test
    void theKeyIsNotOnTheHeap() throws Exception {
        int port = serve(SeclumeSsh.keyPair("provider=file&path=" + directory.resolve("rsa"))
                .getPublic());
        transfer(port, "rsa", "heap.txt", new byte[] {1, 2, 3});
        NoSecretInHeap.assertAbsent(directory.resolve("rsa.der"));
        NoSecretInHeap.assertAbsent(directory.resolve("rsa.prime.bin"));
        PrivateKey usual = KeyFactory.getInstance("RSA").generatePrivate(
                new PKCS8EncodedKeySpec(Files.readAllBytes(directory.resolve("rsa.der"))));
        AssertionError found = assertThrows(AssertionError.class,
                () -> NoSecretInHeap.assertAbsent(directory.resolve("rsa.prime.bin")));
        assertTrue(found.getMessage().contains("the secret is on the heap"), found.getMessage());
        Reference.reachabilityFence(usual);
    }
}
