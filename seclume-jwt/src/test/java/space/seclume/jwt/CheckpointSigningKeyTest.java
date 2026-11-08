package space.seclume.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.crypto.PrivateSigningKey;
import space.seclume.internal.Checkpoint;

/**
 * An ES256 signing key, decoded into OpenSSL on first use and kept: in a
 * CRaC or SnapStart image for as long as it was. Dropped before a
 * checkpoint, decoded again from its provider for the next token.
 */
@Isolated
class CheckpointSigningKeyTest {

    @Test
    void theDecodedKeyIsDroppedAndTheNextTokenSignedAsBefore(@TempDir Path dir) throws Exception {
        Assumptions.assumeTrue(PrivateSigningKey.available(), "neither OpenSSL 3 nor CNG here");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair();
        Path key = dir.resolve("es256.pem");
        Files.writeString(key, "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'})
                        .encodeToString(pair.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n");
        Checkpoint.wipeAll();
        int before = PrivateSigningKey.held();
        try (SeclumeJwt jwt = SeclumeJwt.of("ES256?provider=file&path="
                + key.toString().replace('\\', '/'))) {
            verify(pair, jwt.sign(Map.of("sub", "a")));
            assertEquals(before + 1, PrivateSigningKey.held());

            Checkpoint.wipeAll();
            assertEquals(before, PrivateSigningKey.held(), "the key would be in the image");

            verify(pair, jwt.sign(Map.of("sub", "b")));
            assertEquals(before + 1, PrivateSigningKey.held());
        }
        assertEquals(before, PrivateSigningKey.held());
    }

    private static void verify(KeyPair pair, String token) throws Exception {
        String[] parts = token.split("\\.");
        Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(pair.getPublic());
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(verifier.verify(Base64.getUrlDecoder().decode(parts[2])), token);
    }
}
