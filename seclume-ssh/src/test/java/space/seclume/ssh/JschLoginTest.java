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
 * among them, which the server verifies with its configured Ed25519 provider.
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
                "ssh-keygen -q -t ecdsa -b 256 -N '' -f ecdsa256",
                "ssh-keygen -q -t ecdsa -b 521 -N '' -f ecdsa521",
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
    @ValueSource(strings = {"ed25519", "ecdsa", "ecdsa256", "ecdsa521", "rsa"})
    void logsInAndTransfers(String key) throws Exception {
        int port = serve(SeclumeSsh.keyPair("provider=file&path=" + directory.resolve(key))
                .getPublic());
        byte[] content = ("report for " + key).getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(content, transfer(port, key, key + ".txt", content));
    }

    /**
     * The public key blob is the one ssh-keygen wrote into the {@code .pub}
     * file, for every curve and key type.
     */
    @ParameterizedTest
    @ValueSource(strings = {"ed25519", "ecdsa", "ecdsa256", "ecdsa521", "rsa"})
    void thePublicKeyBlobIsSshKeygens(String key) throws Exception {
        SeclumeJschIdentity identity = SeclumeJschIdentity.of("provider=file&path="
                + directory.resolve(key));
        String[] pub = Files.readString(directory.resolve(key + ".pub")).strip().split(" ");
        assertEquals(pub[0], identity.getAlgName());
        assertArrayEquals(java.util.Base64.getDecoder().decode(pub[1]),
                identity.getPublicKeyBlob());
        // A copy each time: the caller cannot change the identity's.
        identity.getPublicKeyBlob()[0] ^= 1;
        assertArrayEquals(java.util.Base64.getDecoder().decode(pub[1]),
                identity.getPublicKeyBlob());
    }

    /**
     * An ECDSA signature is SSH's two mpints, converted from the DER JCA
     * makes - P-521's SEQUENCE is longer than 127 bytes and its length takes
     * the long form - and each verifies against the public key once made DER
     * again.
     */
    @ParameterizedTest
    @ValueSource(strings = {"ecdsa256:SHA256withECDSA:ecdsa-sha2-nistp256",
        "ecdsa:SHA384withECDSA:ecdsa-sha2-nistp384", "ecdsa521:SHA512withECDSA:ecdsa-sha2-nistp521"})
    void anEcdsaSignatureIsTwoMpintsThatVerify(String spec) throws Exception {
        String[] parts = spec.split(":");
        String keySpec = "provider=file&path=" + directory.resolve(parts[0]);
        SeclumeJschIdentity identity = SeclumeJschIdentity.of(keySpec);
        PublicKey publicKey = SeclumeSsh.keyPair(keySpec).getPublic();
        for (int i = 0; i < 20; i++) {
            byte[] data = ("session " + i).getBytes(StandardCharsets.UTF_8);
            java.nio.ByteBuffer blob = java.nio.ByteBuffer.wrap(identity.getSignature(data));
            assertEquals(parts[2], new String(sshString(blob), StandardCharsets.US_ASCII));
            java.nio.ByteBuffer signature = java.nio.ByteBuffer.wrap(sshString(blob));
            assertEquals(0, blob.remaining());
            byte[] r = sshString(signature);
            byte[] s = sshString(signature);
            assertEquals(0, signature.remaining());
            for (byte[] mpint : new byte[][] {r, s}) {
                // an mpint is minimal: no leading zero unless the next bit is set
                assertTrue(mpint.length > 0 && (mpint[0] != 0 || (mpint[1] & 0x80) != 0));
                assertTrue((mpint[0] & 0x80) == 0, "an mpint here is positive");
            }
            java.security.Signature verifier = java.security.Signature.getInstance(parts[1]);
            verifier.initVerify(publicKey);
            verifier.update(data);
            assertTrue(verifier.verify(der(r, s)), spec + " #" + i);
        }
    }

    @Test
    void rsaSignsWithSha2AndNeverSha1() throws Exception {
        SeclumeJschIdentity identity = SeclumeJschIdentity.of("provider=file&path="
                + directory.resolve("rsa"));
        assertEquals("ssh-rsa", identity.getAlgName());
        PublicKey publicKey = SeclumeSsh.keyPair("provider=file&path="
                + directory.resolve("rsa")).getPublic();
        byte[] data = "exchange hash".getBytes(StandardCharsets.UTF_8);
        for (String[] alg : new String[][] {{"rsa-sha2-256", "SHA256withRSA"},
            {"rsa-sha2-512", "SHA512withRSA"}}) {
            java.nio.ByteBuffer blob = java.nio.ByteBuffer.wrap(identity.getSignature(data, alg[0]));
            assertEquals(alg[0], new String(sshString(blob), StandardCharsets.US_ASCII));
            java.security.Signature verifier = java.security.Signature.getInstance(alg[1]);
            verifier.initVerify(publicKey);
            verifier.update(data);
            assertTrue(verifier.verify(sshString(blob)), alg[0]);
        }
        java.nio.ByteBuffer plain = java.nio.ByteBuffer.wrap(identity.getSignature(data));
        assertEquals("rsa-sha2-512", new String(sshString(plain), StandardCharsets.US_ASCII));
        assertEquals(null, identity.getSignature(data, "ssh-rsa"));
        assertEquals(null, identity.getSignature(data, "ssh-dss"));
        assertEquals(null, identity.getSignature(data, "ecdsa-sha2-nistp256"));
        assertTrue(!identity.isEncrypted() && identity.setPassphrase(null));
    }

    private static byte[] sshString(java.nio.ByteBuffer from) {
        byte[] out = new byte[from.getInt()];
        from.get(out);
        return out;
    }

    /** {@code SEQUENCE { INTEGER r, INTEGER s }}, DER. */
    private static byte[] der(byte[] r, byte[] s) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (byte[] integer : new byte[][] {r, s}) {
            body.write(0x02);
            body.write(integer.length);
            body.writeBytes(integer);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30);
        if (body.size() > 127) {
            out.write(0x81);
        }
        out.write(body.size());
        out.writeBytes(body.toByteArray());
        return out.toByteArray();
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
