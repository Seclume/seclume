package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

import org.junit.jupiter.api.Test;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.RsaPublicKey;
import space.seclume.crypto.X509;

/**
 * The server's {@code CertificateVerify} from RFC 8448's trace 3, checked
 * against its actual certificate rather than against a printed "should be
 * true" - the same shape as the AEAD-tag checks in
 * {@code LocalP256HandshakeTest} and {@code Rfc8448VectorsTest}: build
 * everything the specification describes and let a real cryptographic
 * verification be the verdict, not an assertion this test wrote itself.
 *
 * <p>Every message body used here is the exact bytes RFC 8448 prints for its
 * trace 3, extracted mechanically by {@code tools/rfc8448_vectors.py} - never
 * typed out, per the project's own rule (see {@code Rfc8448VectorsTest}'s
 * class comment for why that rule exists).
 */
class CertificateVerificationTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void theServersCertificateVerifySignatureIsGenuine() throws IOException {
        Map<String, byte[]> messages = new HashMap<>();
        load((who, type, hex) -> messages.put(who + " " + type, HEX.parseHex(hex)));

        try (Arena arena = Arena.ofConfined()) {
            byte[] certificateMessage = messages.get("server Certificate");
            MemorySegment certMsg = segment(arena, certificateMessage);
            int certBodyLength = Handshake.length(certMsg, 0);

            long[] leafAt = new long[1];
            int[] leafLength = new int[1];
            boolean[] found = {false};
            CertificateMessage.certificates(certMsg, Handshake.HEADER, certBodyLength,
                    (at, length, extAt, extLength) -> {
                        if (!found[0]) {                 // the first entry is the leaf
                            leafAt[0] = at;
                            leafLength[0] = length;
                            found[0] = true;
                        }
                    });
            assertTrue(found[0], "the Certificate message carries at least one entry");

            RsaPublicKey leafKey = X509.rsaPublicKey(certMsg, leafAt[0], leafLength[0]);
            try {
                // Transcript hash of ClientHello..Certificate - built from the same
                // recorded messages, in the order the handshake actually sent them.
                byte[] transcriptHash;
                try (TranscriptHash transcript = new TranscriptHash(HashAlgorithm.SHA_256)) {
                    feed(transcript, arena, messages.get("client ClientHello"));
                    feed(transcript, arena, messages.get("server ServerHello"));
                    feed(transcript, arena, messages.get("server EncryptedExtensions"));
                    feed(transcript, arena, messages.get("server Certificate"));
                    MemorySegment digest = arena.allocate(HashAlgorithm.SHA_256.digestLength());
                    transcript.current(digest, 0);
                    transcriptHash = digest.toArray(ValueLayout.JAVA_BYTE);
                }

                byte[] certVerifyMessage = messages.get("server CertificateVerify");
                MemorySegment cvMsg = segment(arena, certVerifyMessage);
                long body = Handshake.HEADER;
                int scheme = CertificateVerifyMessage.signatureScheme(cvMsg, body);
                assertEquals(HandshakeSignature.RSA_PSS_RSAE_SHA256, scheme);
                int sigLength = CertificateVerifyMessage.signatureLength(cvMsg, body);
                long sigAt = CertificateVerifyMessage.signatureOffset(body);

                assertTrue(HandshakeSignature.verifyServer(leafKey, transcriptHash, scheme,
                        cvMsg, sigAt, sigLength), "the recorded signature must verify against "
                        + "the recorded certificate and the recorded transcript");

                // Negative controls: each of the three inputs, alone, must be able to break it.
                byte[] wrongTranscript = transcriptHash.clone();
                wrongTranscript[0] ^= 1;
                assertFalse(HandshakeSignature.verifyServer(leafKey, wrongTranscript, scheme,
                        cvMsg, sigAt, sigLength), "a one-bit wrong transcript hash must fail");

                MemorySegment tamperedSignature = arena.allocate(sigLength);
                MemorySegment.copy(cvMsg, sigAt, tamperedSignature, 0, sigLength);
                tamperedSignature.set(ValueLayout.JAVA_BYTE, 0,
                        (byte) (tamperedSignature.get(ValueLayout.JAVA_BYTE, 0) ^ 1));
                assertFalse(HandshakeSignature.verifyServer(leafKey, transcriptHash, scheme,
                        tamperedSignature, 0, sigLength), "a one-bit wrong signature must fail");

                assertFalse(HandshakeSignature.verifyServer(leafKey, transcriptHash,
                        0x0403 /* ecdsa_secp256r1_sha256 */, cvMsg, sigAt, sigLength),
                        "an unsupported scheme must not be silently accepted");
            } finally {
                leafKey.close();
            }
        }
    }

    private static void feed(TranscriptHash transcript, Arena arena, byte[] message) {
        MemorySegment segment = segment(arena, message);
        transcript.update(segment, 0, (int) segment.byteSize());
    }

    private static MemorySegment segment(Arena arena, byte[] data) {
        MemorySegment segment = arena.allocate(data.length);
        MemorySegment.copy(data, 0, segment, ValueLayout.JAVA_BYTE, 0, data.length);
        return segment;
    }

    @FunctionalInterface
    private interface MessageConsumer {
        void accept(String who, String type, String hex);
    }

    /** Trace 3's "message" rows: who sent it, the handshake type, the full bytes header included. */
    private static void load(MessageConsumer consumer) throws IOException {
        try (InputStream in = CertificateVerificationTest.class.getResourceAsStream("/rfc8448-vectors.txt")) {
            assertTrue(in != null, "rfc8448-vectors.txt is not on the test classpath");
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] parts = line.split("\t", -1);
                if (!parts[0].equals("message") || !parts[1].equals("3")) {
                    continue;
                }
                consumer.accept(parts[2], parts[3], parts[4]);
            }
        }
    }
}
