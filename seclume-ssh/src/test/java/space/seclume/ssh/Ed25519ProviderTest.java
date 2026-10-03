package space.seclume.ssh;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HexFormat;

import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.junit.jupiter.api.Test;

class Ed25519ProviderTest {
    @Test
    void theServerAcceptsARfcSignatureAndRejectsItsNoncanonicalScalar() throws Exception {
        byte[] publicKey = HexFormat.of().parseHex(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] signature = HexFormat.of().parseHex(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        var key = SecurityUtils.generateEDDSAPublicKey("ssh-ed25519", publicKey);
        var verifier = BuiltinSignatures.ed25519.create();
        verifier.initVerifier(null, key);
        verifier.update(null, new byte[0]);
        assertTrue(verifier.verify(null, signature), "RFC 8032 test vector 1");

        // Adding the group order to S must not create another accepted signature.
        byte[] order = HexFormat.of().parseHex(
                "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        int carry = 0;
        for (int i = 0; i < order.length; i++) {
            int sum = (signature[32 + i] & 0xff) + (order[i] & 0xff) + carry;
            signature[32 + i] = (byte) sum;
            carry = sum >>> 8;
        }
        verifier = BuiltinSignatures.ed25519.create();
        verifier.initVerifier(null, key);
        verifier.update(null, new byte[0]);
        assertFalse(verifier.verify(null, signature), "S + group order is noncanonical");
    }
}
