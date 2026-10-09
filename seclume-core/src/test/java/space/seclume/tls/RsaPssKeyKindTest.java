package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.junit.jupiter.api.Test;

/**
 * RFC 8446 section 4.2.3: {@code rsa_pss_rsae_*} is for rsaEncryption keys,
 * {@code rsa_pss_pss_*} for RSASSA-PSS keys. The JDK's verifier takes either
 * key for either, so the scheme has to be held to the key here.
 */
class RsaPssKeyKindTest {

    private static final byte[] HASH = new byte[32];

    @Test
    void anRsaEncryptionKeyGoesWithRsaeOnly() throws Exception {
        KeyPair rsa = generate("RSA");
        byte[] signature = sign(rsa);
        assertTrue(HandshakeSignature.verifyServer(rsa.getPublic(), HASH,
                HandshakeSignature.RSA_PSS_RSAE_SHA256, signature));
        assertFalse(HandshakeSignature.verifyServer(rsa.getPublic(), HASH,
                HandshakeSignature.RSA_PSS_PSS_SHA256, signature));
    }

    @Test
    void aPssKeyGoesWithPssOnly() throws Exception {
        KeyPair pss = generate("RSASSA-PSS");
        byte[] signature = sign(pss);
        assertTrue(HandshakeSignature.verifyServer(pss.getPublic(), HASH,
                HandshakeSignature.RSA_PSS_PSS_SHA256, signature));
        assertFalse(HandshakeSignature.verifyServer(pss.getPublic(), HASH,
                HandshakeSignature.RSA_PSS_RSAE_SHA256, signature));
    }

    private static KeyPair generate(String algorithm) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static byte[] sign(KeyPair pair) throws Exception {
        Signature signer = Signature.getInstance("RSASSA-PSS");
        signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                32, 1));
        signer.initSign(pair.getPrivate());
        signer.update(HandshakeSignature.content(true, HASH));
        return signer.sign();
    }
}
