package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import space.seclume.crypto.HashAlgorithm;

/**
 * The generic SCRAM client against a server recomputed with the JCA - for
 * SHA-512 there is no published vector, and Kafka (Amazon MSK among others)
 * uses it. The server side here may hold the password on the heap: it is only
 * the yardstick.
 */
class ScramTest {

    enum Hash {
        SHA_256(HashAlgorithm.SHA_256, "SHA-256", "HmacSHA256", "PBKDF2WithHmacSHA256"),
        SHA_512(HashAlgorithm.SHA_512, "SHA-512", "HmacSHA512", "PBKDF2WithHmacSHA512");

        final HashAlgorithm algorithm;
        final String digest;
        final String mac;
        final String pbkdf2;

        Hash(HashAlgorithm algorithm, String digest, String mac, String pbkdf2) {
            this.algorithm = algorithm;
            this.digest = digest;
            this.mac = mac;
            this.pbkdf2 = pbkdf2;
        }
    }

    private static final String PASSWORD = "correct horse battery staple";
    private static final byte[] SALT = "a salt of sixteen".getBytes(StandardCharsets.US_ASCII);
    private static final int ITERATIONS = 4096;

    @ParameterizedTest
    @EnumSource(Hash.class)
    void aWholeExchangeAgreesWithTheJca(Hash hash) throws Exception {
        try (Arena arena = Arena.ofConfined();
             Scram scram = new Scram(hash.algorithm)) {
            MemorySegment out = arena.allocate(1024);
            String clientFirst = text(out, scram.clientFirst(out, "app,user=1"));
            assertTrue(clientFirst.startsWith("n,,n=app=2Cuser=3D1,r="), clientFirst);
            String clientFirstBare = clientFirst.substring(3);
            String clientNonce = clientFirstBare.substring(clientFirstBare.indexOf(",r=") + 3);

            String serverFirst = "r=" + clientNonce + "Server%Nonce,s="
                    + Base64.getEncoder().encodeToString(SALT) + ",i=" + ITERATIONS;
            scram.serverFirst(ascii(arena, serverFirst), 0, serverFirst.length());

            String clientFinal = text(out, scram.clientFinal(out, ascii(arena, PASSWORD)));
            String withoutProof = clientFinal.substring(0, clientFinal.indexOf(",p="));
            assertEquals("c=biws,r=" + clientNonce + "Server%Nonce", withoutProof);

            String authMessage = clientFirstBare + "," + serverFirst + "," + withoutProof;
            byte[] salted = SecretKeyFactory.getInstance(hash.pbkdf2).generateSecret(
                    new PBEKeySpec(PASSWORD.toCharArray(), SALT, ITERATIONS,
                            hash.algorithm.digestLength() * 8)).getEncoded();
            byte[] clientKey = mac(hash, salted, "Client Key".getBytes(StandardCharsets.US_ASCII));
            byte[] storedKey = MessageDigest.getInstance(hash.digest).digest(clientKey);
            byte[] signature = mac(hash, storedKey, authMessage.getBytes(StandardCharsets.US_ASCII));
            byte[] proof = new byte[clientKey.length];
            for (int i = 0; i < proof.length; i++) {
                proof[i] = (byte) (clientKey[i] ^ signature[i]);
            }
            assertEquals(Base64.getEncoder().encodeToString(proof),
                    clientFinal.substring(clientFinal.indexOf(",p=") + 3));

            byte[] serverKey = mac(hash, salted, "Server Key".getBytes(StandardCharsets.US_ASCII));
            String serverFinal = "v=" + Base64.getEncoder().encodeToString(
                    mac(hash, serverKey, authMessage.getBytes(StandardCharsets.US_ASCII)));
            scram.verifyServerFinal(ascii(arena, serverFinal), 0, serverFinal.length());

            String forged = "v=" + Base64.getEncoder().encodeToString(signature);
            assertThrows(IllegalStateException.class,
                    () -> scram.verifyServerFinal(ascii(arena, forged), 0, forged.length()));
        }
    }

    @ParameterizedTest
    @EnumSource(Hash.class)
    void aServerErrorIsNamed(Hash hash) {
        try (Arena arena = Arena.ofConfined();
             Scram scram = new Scram(hash.algorithm)) {
            String error = "e=invalid-proof";
            IllegalStateException refused = assertThrows(IllegalStateException.class,
                    () -> scram.verifyServerFinal(ascii(arena, error), 0, error.length()));
            assertEquals("the server refused the login: invalid-proof", refused.getMessage());
        }
    }

    private static byte[] mac(Hash hash, byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance(hash.mac);
        mac.init(new SecretKeySpec(key, hash.mac));
        return mac.doFinal(data);
    }

    private static MemorySegment ascii(Arena arena, String text) {
        MemorySegment segment = arena.allocate(text.length());
        for (int i = 0; i < text.length(); i++) {
            segment.set(ValueLayout.JAVA_BYTE, i, (byte) text.charAt(i));
        }
        return segment;
    }

    private static String text(MemorySegment segment, int length) {
        byte[] bytes = new byte[length];
        MemorySegment.copy(segment, ValueLayout.JAVA_BYTE, 0, bytes, 0, length);
        return new String(bytes, StandardCharsets.US_ASCII);
    }
}
