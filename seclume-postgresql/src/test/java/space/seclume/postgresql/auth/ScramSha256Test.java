package space.seclume.postgresql.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.MessageDigest;

import org.junit.jupiter.api.Test;

/**
 * SCRAM-SHA-256 against the published vector from RFC 7677 and against an
 * independent recomputation with the JCA.
 *
 * <p>The vector alone is not enough: it uses a user name in the {@code n=}
 * field, PostgreSQL leaves it empty. Exactly the case the driver really takes
 * appears in no RFC - hence the recomputation.
 */
class ScramSha256Test {

    private static final String CLIENT_NONCE = "rOprNGfwEbeRWgbNEkqO";
    private static final String SERVER_FIRST =
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
            + "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";

    @Test
    void rfc7677Vector() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nonce = ascii(arena, CLIENT_NONCE);
            try (ScramSha256 scram = new ScramSha256(nonce, CLIENT_NONCE.length())) {
                MemorySegment out = arena.allocate(512);
                int length = scram.clientFirst(out, "user");
                assertEquals("n,,n=user,r=" + CLIENT_NONCE, text(out, length));

                MemorySegment serverFirst = ascii(arena, SERVER_FIRST);
                scram.serverFirst(serverFirst, 0, SERVER_FIRST.length());
                assertEquals(4096, scram.iterations());

                MemorySegment password = ascii(arena, "pencil");
                int finalLength = scram.clientFinal(out, password);
                assertEquals("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
                        + "p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
                        text(out, finalLength));

                String serverFinal = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
                MemorySegment response = ascii(arena, serverFinal);
                scram.verifyServerFinal(response, 0, serverFinal.length());
            }
        }
    }

    /** A wrongly signed server must not get through. */
    @Test
    void rejectsAWrongServerSignature() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nonce = ascii(arena, CLIENT_NONCE);
            try (ScramSha256 scram = new ScramSha256(nonce, CLIENT_NONCE.length())) {
                MemorySegment out = arena.allocate(512);
                scram.clientFirst(out, "user");
                MemorySegment serverFirst = ascii(arena, SERVER_FIRST);
                scram.serverFirst(serverFirst, 0, SERVER_FIRST.length());
                scram.clientFinal(out, ascii(arena, "pencil"));

                String wrong = "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
                MemorySegment response = ascii(arena, wrong);
                assertThrows(IllegalStateException.class,
                        () -> scram.verifyServerFinal(response, 0, wrong.length()));
            }
        }
    }

    /** A server sending a foreign nonce is not our server. */
    @Test
    void rejectsAForeignNonce() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nonce = ascii(arena, CLIENT_NONCE);
            try (ScramSha256 scram = new ScramSha256(nonce, CLIENT_NONCE.length())) {
                MemorySegment out = arena.allocate(512);
                scram.clientFirst(out);
                String foreign = "r=somethingElseEntirely,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
                MemorySegment serverFirst = ascii(arena, foreign);
                assertThrows(IllegalStateException.class,
                        () -> scram.serverFirst(serverFirst, 0, foreign.length()));
            }
        }
    }

    /**
     * The case PostgreSQL really takes: an empty {@code n=}. Recomputed with
     * the JCA - in a test it is allowed, in the driver it is not.
     */
    @Test
    void emptyUsernameMatchesAnIndependentComputation() throws Exception {
        String password = "s3cr3t-pässwörd";
        String serverNonce = CLIENT_NONCE + "ServerPartOfTheNonce";
        String salt = Base64.getEncoder().encodeToString("some salt bytes!".getBytes(
                StandardCharsets.US_ASCII));
        String serverFirst = "r=" + serverNonce + ",s=" + salt + ",i=4096";

        String clientFirstBare = "n=,r=" + CLIENT_NONCE;
        String clientFinalWithoutProof = "c=biws,r=" + serverNonce;
        String authMessage = clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof;

        byte[] saltedPassword = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(new PBEKeySpec(password.toCharArray(),
                        Base64.getDecoder().decode(salt), 4096, 256)).getEncoded();
        byte[] clientKey = hmac(saltedPassword, "Client Key");
        byte[] storedKey = MessageDigest.getInstance("SHA-256").digest(clientKey);
        byte[] clientSignature = hmac(storedKey, authMessage);
        byte[] proof = new byte[clientKey.length];
        for (int i = 0; i < proof.length; i++) {
            proof[i] = (byte) (clientKey[i] ^ clientSignature[i]);
        }
        String expected = clientFinalWithoutProof + ",p=" + Base64.getEncoder().encodeToString(proof);

        byte[] serverSignature = hmac(hmac(saltedPassword, "Server Key"), authMessage);
        String serverFinal = "v=" + Base64.getEncoder().encodeToString(serverSignature);

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nonce = ascii(arena, CLIENT_NONCE);
            try (ScramSha256 scram = new ScramSha256(nonce, CLIENT_NONCE.length())) {
                MemorySegment out = arena.allocate(512);
                scram.clientFirst(out);
                MemorySegment first = ascii(arena, serverFirst);
                scram.serverFirst(first, 0, serverFirst.length());

                byte[] utf8 = password.getBytes(StandardCharsets.UTF_8);
                MemorySegment secret = arena.allocate(utf8.length);
                MemorySegment.copy(MemorySegment.ofArray(utf8), 0, secret, 0, utf8.length);

                int length = scram.clientFinal(out, secret);
                assertEquals(expected, text(out, length));

                MemorySegment response = ascii(arena, serverFinal);
                scram.verifyServerFinal(response, 0, serverFinal.length());
            }
        }
    }

    /**
     * SCRAM-SHA-256-PLUS, computed a second time independently.
     *
     * <p>Two things have to be right and both are silent when they are not:
     * the GS2 header has to carry the {@code p=} form <b>and</b> the same
     * bytes have to reappear base64-encoded in {@code c=} with the certificate
     * fingerprint behind them. Get either wrong and the server answers with an
     * authentication failure that looks exactly like a wrong password.
     */
    @Test
    void channelBindingMatchesAnIndependentComputation() throws Exception {
        String password = "pencil";
        String serverNonce = CLIENT_NONCE + "ServerPartOfTheNonce";
        String salt = Base64.getEncoder().encodeToString("some salt bytes!".getBytes(
                StandardCharsets.US_ASCII));
        String serverFirst = "r=" + serverNonce + ",s=" + salt + ",i=4096";

        // Stands in for the certificate hash - the length is what a SHA-256
        // fingerprint has, the content does not matter to the arithmetic.
        byte[] fingerprint = MessageDigest.getInstance("SHA-256")
                .digest("a certificate".getBytes(StandardCharsets.US_ASCII));
        String header = "p=tls-server-end-point,,";
        byte[] headerBytes = header.getBytes(StandardCharsets.US_ASCII);
        byte[] bound = new byte[headerBytes.length + fingerprint.length];
        System.arraycopy(headerBytes, 0, bound, 0, headerBytes.length);
        System.arraycopy(fingerprint, 0, bound, headerBytes.length, fingerprint.length);

        String clientFirstBare = "n=,r=" + CLIENT_NONCE;
        String clientFinalWithoutProof =
                "c=" + Base64.getEncoder().encodeToString(bound) + ",r=" + serverNonce;
        String authMessage = clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof;

        byte[] saltedPassword = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(new PBEKeySpec(password.toCharArray(),
                        Base64.getDecoder().decode(salt), 4096, 256)).getEncoded();
        byte[] clientKey = hmac(saltedPassword, "Client Key");
        byte[] storedKey = MessageDigest.getInstance("SHA-256").digest(clientKey);
        byte[] clientSignature = hmac(storedKey, authMessage);
        byte[] proof = new byte[clientKey.length];
        for (int i = 0; i < proof.length; i++) {
            proof[i] = (byte) (clientKey[i] ^ clientSignature[i]);
        }
        String expected = clientFinalWithoutProof + ",p="
                + Base64.getEncoder().encodeToString(proof);

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nonce = ascii(arena, CLIENT_NONCE);
            try (ScramSha256 scram = new ScramSha256(nonce, CLIENT_NONCE.length())) {
                MemorySegment data = arena.allocate(fingerprint.length);
                MemorySegment.copy(MemorySegment.ofArray(fingerprint), 0, data, 0,
                        fingerprint.length);
                scram.useChannelBinding(data, fingerprint.length);

                MemorySegment out = arena.allocate(512);
                int firstLength = scram.clientFirst(out);
                assertEquals(header + clientFirstBare, text(out, firstLength));

                MemorySegment first = ascii(arena, serverFirst);
                scram.serverFirst(first, 0, serverFirst.length());
                int length = scram.clientFinal(out, ascii(arena, password));
                assertEquals(expected, text(out, length));
            }
        }
    }

    /**
     * The {@code y} header - „I can bind, you did not offer it".
     *
     * <p>Worth a test of its own because it is the one case where the client
     * says something about a capability it is <b>not</b> using, and the whole
     * downgrade protection rests on it being sent.
     */
    @Test
    void saysYWhenTheServerDidNotOfferBinding() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nonce = ascii(arena, CLIENT_NONCE);
            try (ScramSha256 scram = new ScramSha256(nonce, CLIENT_NONCE.length())) {
                scram.channelBindingNotOffered();
                MemorySegment out = arena.allocate(256);
                int length = scram.clientFirst(out);
                assertEquals("y,,n=,r=" + CLIENT_NONCE, text(out, length));
            }
        }
    }

    private static byte[] hmac(byte[] key, String message) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
    }

    private static MemorySegment ascii(Arena arena, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        MemorySegment segment = arena.allocate(bytes.length);
        MemorySegment.copy(MemorySegment.ofArray(bytes), 0, segment, 0, bytes.length);
        return segment;
    }

    private static String text(MemorySegment segment, int length) {
        byte[] bytes = new byte[length];
        MemorySegment.copy(segment, ValueLayout.JAVA_BYTE, 0, bytes, 0, length);
        return new String(bytes, StandardCharsets.UTF_8);
    }
}
