package space.seclume.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.crypto.PrivateSigningKey;
import space.seclume.internal.Checkpoint;

/**
 * A server's TLS key, an SSH client's, a service account's: in OpenSSL's
 * memory for as long as the application runs - and so in a CRaC or SnapStart
 * image of it. A key named by a keySpec is dropped before the checkpoint and
 * read again from its file on the first signature after the restore.
 */
@Isolated
@Timeout(120)
class CheckpointKeyTest {

    @TempDir
    static Path directory;
    static KeyFiles ec;
    static KeyFiles other;

    @BeforeAll
    static void keys() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(PrivateSigningKey.available(),
                "neither OpenSSL 3 nor CNG here");
        ec = KeyFiles.make(directory.resolve("ec"), "ec:P-256");
        other = KeyFiles.make(directory.resolve("other"), "ec:P-256");
    }

    private static byte[] sign(PrivateKey key, byte[] message) throws Exception {
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(key);
        signer.update(message);
        return signer.sign();
    }

    private static boolean verifies(PublicKey key, byte[] message, byte[] signature)
            throws Exception {
        Signature verifier = Signature.getInstance("SHA256withECDSA", "SunEC");
        verifier.initVerify(key);
        verifier.update(message);
        return verifier.verify(signature);
    }

    @Test
    void aKeySpecsKeyIsDroppedAndReadAgain() throws Exception {
        Checkpoint.wipeAll();
        int before = PrivateSigningKey.held();
        var pair = SeclumeKeys.keyPair(ec.spec());
        byte[] message = {1, 2, 3};
        assertTrue(verifies(pair.getPublic(), message, sign(pair.getPrivate(), message)));
        assertEquals(before + 1, PrivateSigningKey.held());

        Checkpoint.wipeAll();
        assertEquals(before, PrivateSigningKey.held(), "the key would be in the image");

        assertTrue(verifies(pair.getPublic(), message, sign(pair.getPrivate(), message)),
                "after the restore the key signs again - read from its file");
        ((OpenSslPrivateKey) pair.getPrivate()).destroy();
        assertEquals(before, PrivateSigningKey.held());
    }

    @Test
    void anotherKeyInTheFileAfterTheRestoreIsRefused() throws Exception {
        Path moving = directory.resolve("moving.pem");
        Files.copy(ec.key(), moving, StandardCopyOption.REPLACE_EXISTING);
        PrivateKey key = SeclumeKeys.privateKey("provider=file&path=" + moving);
        Checkpoint.wipeAll();
        Files.copy(other.key(), moving, StandardCopyOption.REPLACE_EXISTING);
        Exception refused = assertThrows(Exception.class, () -> sign(key, new byte[] {1}));
        Throwable cause = refused;
        while (cause != null && !(cause instanceof IllegalStateException)) {
            cause = cause.getCause();
        }
        assertTrue(cause != null && cause.getMessage().contains("is another key"),
                String.valueOf(refused));
        assertTrue(refused instanceof SignatureException || refused instanceof ProviderException
                || refused instanceof IllegalStateException, refused.toString());
        ((OpenSslPrivateKey) key).destroy();
    }

    @Test
    void aKeyServerAfterTheRestoreHandshakesWithTheSameKey() throws Exception {
        Checkpoint.wipeAll();
        int before = PrivateSigningKey.held();
        var manager = SeclumeKeys.keyManager(ec.certificate(), ec.spec());
        String alias = manager.getServerAliases("EC", null)[0];
        PrivateKey key = manager.getPrivateKey(alias);
        Checkpoint.wipeAll();
        assertEquals(before, PrivateSigningKey.held());
        byte[] message = {9};
        assertTrue(verifies(manager.getCertificateChain(alias)[0].getPublicKey(), message,
                sign(key, message)));
        ((OpenSslPrivateKey) key).destroy();
    }

    @Test
    void aProviderHandedInCannotBeReadAgainAndIsCounted() throws Exception {
        Checkpoint.wipeAll();
        int before = PrivateSigningKey.held();
        byte[] pem = Files.readAllBytes(ec.key());
        PrivateKey key = SeclumeKeys.privateKey(new space.seclume.secret.SecretProvider() {
            @Override
            public int writeSecret(java.lang.foreign.MemorySegment target) {
                java.lang.foreign.MemorySegment.copy(pem, 0, target,
                        java.lang.foreign.ValueLayout.JAVA_BYTE, 0, pem.length);
                return pem.length;
            }

            @Override
            public int maxSecretLength() {
                return pem.length;
            }
        });
        Checkpoint.wipeAll();
        assertEquals(before + 1, PrivateSigningKey.held(), "a key that cannot be read again "
                + "stays - and a checkpoint is refused while it does");
        ((OpenSslPrivateKey) key).destroy();
        assertEquals(before, PrivateSigningKey.held());
    }
}
