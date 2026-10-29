package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/** A key generated in the backend signs, and the JDK checks it with the public half it reports. */
class SigningKeysTest {

    private static final byte[] MESSAGE = "a certification request".getBytes(StandardCharsets.US_ASCII);

    @Test
    void aGeneratedP256KeySignsAndItsPublicHalfVerifies() throws Exception {
        Assumptions.assumeTrue(PrivateSigningKey.available(), "no OpenSSL 3 or CNG here");
        byte[] first;
        try (PrivateSigningKey key = PrivateSigningKey.generateP256();
             Arena arena = Arena.ofConfined()) {
            assertTrue(key.is("EC"));
            first = key.publicKey();
            PublicKey publicKey = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(first));
            assertEquals(256, ((ECPublicKey) publicKey).getParams().getCurve().getField()
                    .getFieldSize());
            MemorySegment message = arena.allocate(MESSAGE.length);
            MemorySegment.copy(MESSAGE, 0, message, ValueLayout.JAVA_BYTE, 0, MESSAGE.length);
            MemorySegment out = arena.allocate(PrivateSigningKey.MAX_SIGNATURE);
            int n = key.sign("SHA256", false, message, MESSAGE.length, out);
            Signature check = Signature.getInstance("SHA256withECDSA");
            check.initVerify(publicKey);
            check.update(MESSAGE);
            assertTrue(check.verify(out.asSlice(0, n).toArray(ValueLayout.JAVA_BYTE)));
        }
        try (PrivateSigningKey other = PrivateSigningKey.generateP256()) {
            assertFalse(Arrays.equals(first, other.publicKey()), "two keys, one public half");
        }
    }
}
