package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Signatures made by OpenSSL from a key decoded in native memory, checked by
 * the JDK: RSA PKCS#1 v1.5, RSA-PSS and ECDSA on all three curves, from PEM
 * and from DER. The keys are made by the JDK here, for the test only.
 */
class OpenSslSigningKeyTest {

    private static final byte[] MESSAGE = "header.payload".getBytes(StandardCharsets.US_ASCII);

    @BeforeAll
    static void openSsl() {
        Assumptions.assumeTrue(OpenSslSigningKey.available(), "no OpenSSL 3 here");
    }

    private static byte[] sign(KeyPair pair, boolean pem, String digest, boolean pss) {
        byte[] encoded = pair.getPrivate().getEncoded();
        byte[] input = pem ? ("-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(encoded)
                + "\n-----END PRIVATE KEY-----\n").getBytes(StandardCharsets.US_ASCII) : encoded;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocate(input.length);
            MemorySegment.copy(input, 0, key, ValueLayout.JAVA_BYTE, 0, input.length);
            MemorySegment message = arena.allocate(MESSAGE.length);
            MemorySegment.copy(MESSAGE, 0, message, ValueLayout.JAVA_BYTE, 0, MESSAGE.length);
            MemorySegment out = arena.allocate(OpenSslSigningKey.MAX_SIGNATURE);
            try (OpenSslSigningKey signing = OpenSslSigningKey.decode(key, input.length)) {
                int n = signing.sign(digest, pss, message, MESSAGE.length, out);
                return out.asSlice(0, n).toArray(ValueLayout.JAVA_BYTE);
            }
        }
    }

    @Test
    void rsaPkcs1AndPssFromPemAndDer() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        for (String[] alg : new String[][] {{"SHA256", "SHA256withRSA"},
                {"SHA384", "SHA384withRSA"}, {"SHA512", "SHA512withRSA"}}) {
            for (boolean pem : new boolean[] {true, false}) {
                Signature check = Signature.getInstance(alg[1]);
                check.initVerify(pair.getPublic());
                check.update(MESSAGE);
                assertTrue(check.verify(sign(pair, pem, alg[0], false)), alg[1]);
            }
        }
        Signature pss = Signature.getInstance("RSASSA-PSS");
        pss.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        pss.initVerify(pair.getPublic());
        pss.update(MESSAGE);
        assertTrue(pss.verify(sign(pair, true, "SHA256", true)), "PS256");
    }

    @Test
    void ecdsaOnAllThreeCurvesAndItsRawForm() throws Exception {
        String[][] curves = {{"secp256r1", "SHA256", "SHA256withECDSA", "32"},
                {"secp384r1", "SHA384", "SHA384withECDSA", "48"},
                {"secp521r1", "SHA512", "SHA512withECDSA", "66"}};
        for (String[] curve : curves) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curve[0]));
            KeyPair pair = generator.generateKeyPair();
            byte[] der = sign(pair, true, curve[1], false);
            Signature check = Signature.getInstance(curve[2]);
            check.initVerify(pair.getPublic());
            check.update(MESSAGE);
            assertTrue(check.verify(der), curve[0]);

            int field = Integer.parseInt(curve[3]);
            byte[] raw = OpenSslSigningKey.rawEcdsa(der, field);
            assertEquals(2 * field, raw.length);
            Signature p1363 = Signature.getInstance(curve[2] + "inP1363Format");
            p1363.initVerify(pair.getPublic());
            p1363.update(MESSAGE);
            assertTrue(p1363.verify(raw), curve[0] + " raw");
        }
    }

    @Test
    void theKeyTypeIsKnownAndAMismatchedAlgorithmRefused() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        byte[] encoded = generator.generateKeyPair().getPrivate().getEncoded();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocate(encoded.length);
            MemorySegment.copy(encoded, 0, key, ValueLayout.JAVA_BYTE, 0, encoded.length);
            try (OpenSslSigningKey signing = OpenSslSigningKey.decode(key, encoded.length)) {
                assertTrue(signing.is("EC"));
                assertFalse(signing.is("RSA"));
                MemorySegment out = arena.allocate(OpenSslSigningKey.MAX_SIGNATURE);
                assertThrows(IllegalStateException.class,
                        () -> signing.sign("SHA256", true, out, 4, out));
            }
        }
    }

    @Test
    void garbageIsRefusedWithAReason() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment junk = arena.allocateFrom("not a key");
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> OpenSslSigningKey.decode(junk, 9));
            assertTrue(e.getMessage().contains("could not be read"), e.getMessage());
        }
    }
}
