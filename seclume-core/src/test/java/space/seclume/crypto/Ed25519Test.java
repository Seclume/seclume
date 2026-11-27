package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Random;

import org.junit.jupiter.api.Test;

/**
 * Ed25519 against RFC 8032's vectors, against the JDK's own implementation
 * (which holds keys on the heap and is therefore used only here), and
 * against the public key MariaDB documents for the password "secret".
 */
class Ed25519Test {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void rfc8032TestOne() {
        check("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bac"
                        + "c61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    }

    @Test
    void rfc8032TestTwo() {
        check("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e"
                        + "458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
    }

    @Test
    void rfc8032TestThree() {
        check("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290"
                        + "ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
    }

    /**
     * RFC 8032's last Ed25519 vector, a 64-byte message (SHA-512 of "abc").
     * Wycheproof's Ed25519 file is for verifiers - public keys only - and
     * seclume only signs, so it has nothing to check here; RFC 8032's vectors
     * and the JDK differential below are what the signer is held to.
     */
    @Test
    void rfc8032TestShaAbc() {
        check("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
                "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a8"
                        + "36ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ec"
                        + "fdfbc7c66431e0303dca179c138ac17ad9bef1177331a704");
    }

    @Test
    void theSameAsTheJdkForManyKeysAndMessages() throws Exception {
        Random random = new Random(25519);
        KeyFactory factory = KeyFactory.getInstance("Ed25519");
        for (int round = 0; round < 200; round++) {
            byte[] seed = new byte[32];
            random.nextBytes(seed);
            byte[] message = new byte[random.nextInt(200)];
            random.nextBytes(message);
            PrivateKey key = factory.generatePrivate(
                    new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed));
            Signature jdk = Signature.getInstance("Ed25519");
            jdk.initSign(key);
            jdk.update(message);
            byte[] expected = jdk.sign();
            assertArrayEquals(expected, sign(seed, message), "round " + round);
        }
    }

    @Test
    void theSignatureVerifiesWithTheJdk() throws Exception {
        byte[] seed = HEX.parseHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        byte[] message = "server scramble and client scramble".getBytes(StandardCharsets.UTF_8);
        byte[] signature = sign(seed, message);
        PublicKey publicKey = jdkPublicKey(publicKey(seed));
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(publicKey);
        verifier.update(message);
        assertTrue(verifier.verify(signature));
    }

    /** MariaDB's documentation: ed25519_password('secret'). */
    @Test
    void mariadbExpandsThePasswordItself() throws Exception {
        byte[] password = "secret".getBytes(StandardCharsets.UTF_8);
        assertEquals("ZIgUREUg5PVgQ6LskhXmO+eZLS0nC8be6HPjYWR4YJY",
                Base64.getEncoder().withoutPadding().encodeToString(publicKey(password)));
        // and what it signs verifies under that key
        byte[] nonce = new byte[32];
        new Random(1).nextBytes(nonce);
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(jdkPublicKey(publicKey(password)));
        verifier.update(nonce);
        assertTrue(verifier.verify(sign(password, nonce)));
    }

    private static void check(String seed, String publicKey, String message, String signature) {
        assertEquals(publicKey, HEX.formatHex(publicKey(HEX.parseHex(seed))));
        assertEquals(signature, HEX.formatHex(sign(HEX.parseHex(seed), HEX.parseHex(message))));
    }

    private static byte[] sign(byte[] seed, byte[] message) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment s = arena.allocateFrom(ValueLayout.JAVA_BYTE, seed);
            MemorySegment m = arena.allocate(Math.max(1, message.length));
            MemorySegment.copy(message, 0, m, ValueLayout.JAVA_BYTE, 0, message.length);
            MemorySegment out = arena.allocate(Ed25519.SIGNATURE_LENGTH);
            Ed25519.sign(s, 0, seed.length, m, 0, message.length, out, 0);
            return out.toArray(ValueLayout.JAVA_BYTE);
        }
    }

    private static byte[] publicKey(byte[] seed) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment s = arena.allocateFrom(ValueLayout.JAVA_BYTE, seed);
            MemorySegment out = arena.allocate(Ed25519.PUBLIC_KEY_LENGTH);
            Ed25519.publicKey(s, 0, seed.length, out, 0);
            return out.toArray(ValueLayout.JAVA_BYTE);
        }
    }

    /** The JDK's key from an encoding: X.509 SubjectPublicKeyInfo with the Ed25519 OID. */
    private static PublicKey jdkPublicKey(byte[] raw) throws Exception {
        byte[] prefix = HEX.parseHex("302a300506032b6570032100");
        byte[] encoded = new byte[prefix.length + raw.length];
        System.arraycopy(prefix, 0, encoded, 0, prefix.length);
        System.arraycopy(raw, 0, encoded, prefix.length, raw.length);
        return KeyFactory.getInstance("Ed25519")
                .generatePublic(new java.security.spec.X509EncodedKeySpec(encoded));
    }
}
