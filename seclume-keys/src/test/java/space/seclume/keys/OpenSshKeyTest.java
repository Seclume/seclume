package space.seclume.keys;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.lang.ref.Reference;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import space.seclume.crypto.OpenSslSigningKey;
import space.seclume.tck.NoSecretInHeap;

/**
 * Keys as {@code ssh-keygen} writes them - OpenSSH's own format - read in
 * native memory and handed to OpenSSL. The public key that comes out has to be
 * the one {@code ssh-keygen} exports, and the signatures verify with the JDK.
 */
class OpenSshKeyTest {

    @TempDir
    static Path directory;

    @BeforeAll
    static void keys() throws Exception {
        assumeTrue(OpenSslSigningKey.available(), "OpenSSL 3 on 64-bit Linux");
        Process probe = space.seclume.tck.Shell.builder("-c", "command -v ssh-keygen").start();
        assumeTrue(probe.waitFor() == 0, "ssh-keygen is not installed");
        Path script = directory.resolve("keys.sh");
        Files.writeString(script, String.join("\n",
                "set -e", "cd '" + directory + "'",
                "ssh-keygen -q -t ed25519 -N '' -C test -f ed25519",
                "ssh-keygen -q -t ecdsa -b 256 -N '' -f ecdsa256",
                "ssh-keygen -q -t ecdsa -b 384 -N '' -f ecdsa384",
                "ssh-keygen -q -t ecdsa -b 521 -N '' -f ecdsa521",
                "ssh-keygen -q -t rsa -b 3072 -N '' -f rsa",
                "ssh-keygen -q -t ed25519 -N 'a passphrase' -f protected",
                "{ perl -e 'print pack(\"H*\", \"302a300506032b6570032100\")';"
                        + " awk '{print $2}' ed25519.pub | base64 -d | tail -c 32; }"
                        + " > ed25519.public.der",
                "for k in ecdsa256 ecdsa384 ecdsa521 rsa; do",
                "  ssh-keygen -e -m PKCS8 -f $k.pub | openssl pkey -pubin -outform DER -out $k.public.der",
                "done",
                "cp rsa rsa.pkcs8 && ssh-keygen -q -p -N '' -m PKCS8 -f rsa.pkcs8",
                "openssl pkcs8 -topk8 -nocrypt -in rsa.pkcs8 -outform DER -out rsa.der",
                "openssl pkey -in rsa.pkcs8 -text -noout | sed -n '/^prime1:/,/^[a-zA-Z]/p'"
                        + " | sed '1d;$d' | tr -d ' :\\n' | sed 's/^00//'"
                        + " | perl -ne 'print pack(\"H*\", $_)' > rsa.prime.bin",
                "grep -q 'BEGIN OPENSSH PRIVATE KEY' rsa", ""));
        Process process = space.seclume.tck.Shell.builder(script.toString())
                .redirectErrorStream(true).start();
        assertEquals(0, process.waitFor(), new String(process.getInputStream().readAllBytes()));
    }

    private static String spec(String name) {
        return "provider=file&path=" + directory.resolve(name);
    }

    @ParameterizedTest
    @CsvSource({"ed25519, Ed25519", "ecdsa256, SHA256withECDSA", "ecdsa384, SHA384withECDSA",
            "ecdsa521, SHA512withECDSA", "rsa, SHA256withRSA", "rsa, SHA512withRSA"})
    void readsWhatSshKeygenWrites(String name, String algorithm) throws Exception {
        KeyPair pair = SeclumeKeys.keyPair(spec(name));
        assertArrayEquals(Files.readAllBytes(directory.resolve(name + ".public.der")),
                pair.getPublic().getEncoded(), "the public key from the private key file");
        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(pair.getPrivate());
        signer.update("challenge".getBytes());
        byte[] signature = signer.sign();
        assertEquals(SeclumeKeyProvider.NAME, signer.getProvider().getName());
        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(pair.getPublic());
        verifier.update("challenge".getBytes());
        assertTrue(verifier.verify(signature));
    }

    @Test
    void anEd25519KeyIsWhatTheJdkCallsEdDsa() {
        PrivateKey key = SeclumeKeys.privateKey(spec("ed25519"));
        assertEquals("EdDSA", key.getAlgorithm());
        assertEquals(null, key.getEncoded());
    }

    @Test
    void aPassphraseProtectedKeyIsRefusedWithTheWayOut() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> SeclumeKeys.privateKey(spec("protected")));
        assertTrue(refused.getMessage().contains("passphrase"), refused.getMessage());
    }

    @Test
    void theRsaKeyIsNotOnTheHeap() throws Exception {
        KeyPair pair = SeclumeKeys.keyPair(spec("rsa"));
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(pair.getPrivate());
        signer.update(new byte[] {1});
        signer.sign();
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
