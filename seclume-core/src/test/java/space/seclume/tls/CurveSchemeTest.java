package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import org.junit.jupiter.api.Test;

/**
 * A TLS 1.3 ECDSA scheme names its curve. A P-384 key's signature offered
 * under ecdsa_secp256r1_sha256 verified - the JCA checks the hash, not that
 * the curve is the one the scheme names.
 */
class CurveSchemeTest {

    private static KeyPair ec(String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    private static byte[] sign(KeyPair keys, String algorithm, byte[] content) throws Exception {
        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(keys.getPrivate());
        signer.update(content);
        return signer.sign();
    }

    @Test
    void aP384KeyUnderTheP256SchemeIsRefused() throws Exception {
        KeyPair p384 = ec("secp384r1");
        byte[] hash = new byte[32];
        byte[] signature = sign(p384, "SHA256withECDSA", HandshakeSignature.content(true, hash));
        assertFalse(HandshakeSignature.verifyServer(p384.getPublic(), hash,
                HandshakeSignature.ECDSA_SECP256R1_SHA256, signature));
    }

    @Test
    void theCurveTheSchemeNamesVerifies() throws Exception {
        KeyPair p256 = ec("secp256r1");
        byte[] hash = new byte[32];
        byte[] signature = sign(p256, "SHA256withECDSA", HandshakeSignature.content(true, hash));
        assertTrue(HandshakeSignature.verifyServer(p256.getPublic(), hash,
                HandshakeSignature.ECDSA_SECP256R1_SHA256, signature));
    }

    @Test
    void inTls12TheSchemeNamesOnlyTheHash() throws Exception {
        KeyPair p384 = ec("secp384r1");
        byte[] signed = new byte[96];
        byte[] signature = sign(p384, "SHA256withECDSA", signed);
        assertTrue(HandshakeSignature.verifyTls12(p384.getPublic(),
                HandshakeSignature.ECDSA_SECP256R1_SHA256, signed, signature));
    }
}
