package space.seclume.kafka;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import javax.security.sasl.SaslClient;

import org.apache.kafka.common.message.SaslAuthenticateRequestData;
import org.apache.kafka.common.protocol.ApiKeys;
import org.apache.kafka.common.protocol.ByteBufferAccessor;
import org.apache.kafka.common.requests.RequestHeader;
import org.apache.kafka.common.requests.SaslAuthenticateRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.internal.SeclumeSslEngine;
import space.seclume.secret.SecretProviders;
import space.seclume.secret.SecretScope;

/**
 * The SaslAuthenticate request as Kafka's own code writes it - every version
 * - rewritten with the secret, and read back by Kafka's own code: what the
 * broker gets is exactly the message with the secret where the placeholder
 * was, and the lengths around it agree.
 */
class SaslAuthenticateRewriterTest {

    @TempDir
    static Path dir;

    @BeforeAll
    static void theEngineFactoryIsInUse() {
        new SeclumeSslEngineFactory().configure(Map.of());
    }

    @ParameterizedTest
    @ValueSource(shorts = {0, 1, 2})
    void plainGetsItsPasswordInEveryVersion(short version) throws Exception {
        String password = "Kafka-9f3c1e,with=signs";
        SaslClient client = new PlainClient("orders", file(password));
        byte[] message = client.evaluateChallenge(new byte[0]);
        assertFalse(new String(message, StandardCharsets.UTF_8).contains(password));

        byte[] sent = rewrite(frame(message, version, "producer-1"));
        assertArrayEquals(("\0orders\0" + password).getBytes(StandardCharsets.UTF_8),
                authBytes(sent, version));
        client.dispose();
    }

    @Test
    void aLongTokenMovesTheVarintAcrossItsBoundary() throws Exception {
        // 127 bytes and more take a second varint byte, and every length after moves.
        String token = "eyJ" + "a".repeat(300) + ".payload.signature";
        SaslClient client = new OAuthBearerClient(file(token),
                new java.util.LinkedHashMap<>(Map.of("logicalCluster", "lkc-123")));
        byte[] message = client.evaluateChallenge(new byte[0]);
        byte[] sent = rewrite(frame(message, (short) 2, null));
        assertEquals("n,,\u0001auth=Bearer " + token + "\u0001logicalCluster=lkc-123\u0001\u0001",
                new String(authBytes(sent, (short) 2), StandardCharsets.UTF_8));
        client.dispose();
    }

    @Test
    void aRequestWithoutPlaceholderGoesAsItIs() throws Exception {
        ByteBuffer request = frame("n,,\u0001auth=Bearer abc\u0001\u0001"
                .getBytes(StandardCharsets.UTF_8), (short) 2, "c");
        int size = request.remaining();
        SeclumeSslEngine.Outgoing.Step step = new SaslAuthenticateRewriter().next(request);
        assertNull(step.replacement());
        assertEquals(size, step.unchanged());
    }

    @Test
    void framesAreFollowedAcrossBuffers() throws Exception {
        // A request whose body comes in a second buffer, as Kafka sends records.
        SaslAuthenticateRewriter rewriter = new SaslAuthenticateRewriter();
        ByteBuffer head = ByteBuffer.allocate(10).putInt(20).putShort((short) 0)
                .putShort((short) 9).putShort((short) 0).flip();
        assertEquals(10, rewriter.next(head).unchanged());
        head.position(10);
        ByteBuffer body = ByteBuffer.allocate(14);
        assertEquals(14, rewriter.next(body).unchanged());
        body.position(14);

        // The next request starts a frame again - and is recognised.
        SaslClient client = new PlainClient("orders", file("pw"));
        ByteBuffer next = frame(client.evaluateChallenge(new byte[0]), (short) 2, "c");
        assertNotNull(rewriter.next(next).replacement());
        client.dispose();
    }

    @Test
    void aPlaceholderIsSpentOnce() throws Exception {
        SaslClient client = new PlainClient("orders", file("pw"));
        byte[] message = client.evaluateChallenge(new byte[0]);
        rewrite(frame(message, (short) 2, "c"));
        IOException twice = assertThrows(IOException.class,
                () -> rewrite(frame(message, (short) 2, "c")));
        assertTrue(twice.getMessage().contains("stands for nothing"), twice.getMessage());
        client.dispose();
    }

    @Test
    void aDisposedLoginLeavesNothingToSend() throws Exception {
        SaslClient client = new PlainClient("orders", file("pw"));
        byte[] message = client.evaluateChallenge(new byte[0]);
        client.dispose();
        assertThrows(IOException.class, () -> rewrite(frame(message, (short) 2, "c")));
    }

    private static space.seclume.secret.SecretProvider file(String secret) throws IOException {
        Path file = Files.createTempFile(dir, "secret", ".txt");
        Files.writeString(file, secret);
        return SecretProviders.of(Map.of("provider", "file", "path", file.toString(),
                "max-length", "16384"));
    }

    /** The request as Kafka sends it: size, header, body. */
    private static ByteBuffer frame(byte[] authBytes, short version, String clientId) {
        SaslAuthenticateRequest request = new SaslAuthenticateRequest.Builder(
                new SaslAuthenticateRequestData().setAuthBytes(authBytes)).build(version);
        ByteBuffer body = request.serializeWithHeader(
                new RequestHeader(ApiKeys.SASL_AUTHENTICATE, version, clientId, 7));
        ByteBuffer framed = ByteBuffer.allocate(4 + body.remaining());
        framed.putInt(body.remaining()).put(body).flip();
        return framed;
    }

    private static byte[] rewrite(ByteBuffer frame) throws IOException {
        SeclumeSslEngine.Outgoing.Step step = new SaslAuthenticateRewriter().next(frame);
        assertNotNull(step.replacement(), "not rewritten");
        assertEquals(frame.remaining(), step.replaced());
        try (SecretScope out = step.replacement()) {
            byte[] bytes = new byte[out.length()];
            java.lang.foreign.MemorySegment.copy(out.segment(), java.lang.foreign.ValueLayout.JAVA_BYTE,
                    0, bytes, 0, bytes.length);
            return bytes;
        }
    }

    /** What the broker reads: the frame's size checked, the header and the request parsed. */
    private static byte[] authBytes(byte[] sent, short version) {
        ByteBuffer in = ByteBuffer.wrap(sent);
        assertEquals(sent.length - 4, in.getInt(), "the frame's size");
        RequestHeader header = RequestHeader.parse(in);
        assertEquals(ApiKeys.SASL_AUTHENTICATE, header.apiKey());
        assertEquals(version, header.apiVersion());
        SaslAuthenticateRequest request = SaslAuthenticateRequest.parse(
                new ByteBufferAccessor(in), version);
        assertFalse(in.hasRemaining(), "bytes after the request");
        return request.data().authBytes();
    }
}
