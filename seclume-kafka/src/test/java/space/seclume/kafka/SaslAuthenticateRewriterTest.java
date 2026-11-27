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

    /**
     * A broker that answers the login with the password in its error message
     * would put it into a String of Kafka's, and into every log of the
     * failure. After the rewritten request the answer is masked before Kafka
     * reads it - and once the guard's bytes are through, nothing is kept.
     */
    @Test
    void theBrokersAnswerIsMaskedBeforeKafkaReadsIt() throws Exception {
        String password = "Kafka-echo-7d1e0b";
        SaslClient client = new PlainClient("orders", file(password));
        byte[] message = client.evaluateChallenge(new byte[0]);
        SaslAuthenticateRewriter rewriter = new SaslAuthenticateRewriter();
        assertFalse(rewriter.guarding(), "guarding before any secret went out");
        try (SecretScope out = rewriter.next(frame(message, (short) 2, "producer-1"))
                .replacement()) {
            assertNotNull(out);
        }
        assertTrue(rewriter.guarding(), "nothing guards the broker's answer");
        byte[] answer = ("Authentication failed: invalid password " + password + " for orders")
                .getBytes(StandardCharsets.US_ASCII);
        try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
            java.lang.foreign.MemorySegment plain = arena.allocate(answer.length);
            java.lang.foreign.MemorySegment.copy(answer, 0, plain,
                    java.lang.foreign.ValueLayout.JAVA_BYTE, 0, answer.length);
            rewriter.mask(plain, answer.length);
            String seen = new String(plain.toArray(java.lang.foreign.ValueLayout.JAVA_BYTE),
                    StandardCharsets.US_ASCII);
            assertFalse(seen.contains(password) || seen.contains("echo-7d1e"), seen);
            assertTrue(seen.startsWith("Authentication failed"), seen);
            java.lang.foreign.MemorySegment rest = arena.allocate(
                    SaslAuthenticateRewriter.ECHO_GUARD_BYTES);
            rewriter.mask(rest, SaslAuthenticateRewriter.ECHO_GUARD_BYTES);
        }
        assertFalse(rewriter.guarding(), "the copy of the secret was kept past its guard");
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

    /**
     * A broker the cluster announced beyond bootstrap.servers' domains - a
     * compromised one, a changed advertised.listeners - would collect the
     * PLAIN password: the placeholder is not replaced for it, and nothing goes.
     */
    @Test
    void aBrokerOutsideTheBootstrapDomainsGetsNoPassword() throws Exception {
        SaslClient client = new PlainClient("orders", file("never-to-evil"));
        ByteBuffer request = frame(client.evaluateChallenge(new byte[0]), (short) 2, "p");
        java.io.IOException refused = org.junit.jupiter.api.Assertions.assertThrows(
                java.io.IOException.class, () -> new SaslAuthenticateRewriter("evil.example:9093",
                        "not sending the credential to broker evil.example").next(request));
        assertTrue(refused.getMessage().contains("evil.example"), refused.getMessage());
        client.dispose();
    }

    @Test
    void theBrokersThatMayGetTheCredential() {
        SeclumeSslEngineFactory factory = new SeclumeSslEngineFactory();
        factory.configure(Map.of("bootstrap.servers", java.util.List.of("b1.kafka.corp.example:9093",
                "10.0.0.5:9093"), SeclumeSslEngineFactory.ALLOWED_BROKERS, "*.partner.example"));
        assertNull(factory.refusalFor("b1.kafka.corp.example"));
        assertNull(factory.refusalFor("b7.kafka.corp.example"), "a broker in the seed's domain");
        assertNull(factory.refusalFor("10.0.0.5"));
        assertNull(factory.refusalFor("k.partner.example"), "an allowed suffix");
        assertTrue(factory.refusalFor("evil.example") != null);
        assertTrue(factory.refusalFor("10.0.0.6") != null, "an address admits itself only");

        SeclumeSslEngineFactory unseen = new SeclumeSslEngineFactory();
        unseen.configure(Map.of());
        assertTrue(unseen.refusalFor("b1.kafka.corp.example").contains(
                SeclumeSslEngineFactory.ALLOWED_BROKERS), "no seeds seen: nothing is sent");
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

    /**
     * The placeholder belongs in the auth bytes and nowhere else: put into
     * the client id - a field the broker logs - it is refused, not filled in.
     */
    @Test
    void aPlaceholderOutsideTheAuthBytesIsRefused() throws Exception {
        SaslClient client = new PlainClient("orders", file("pw-outside"));
        String message = new String(client.evaluateChallenge(new byte[0]), StandardCharsets.UTF_8);
        String placeholder = message.substring(message.lastIndexOf('\0') + 1);
        byte[] plainAuth = "\0orders\0nothing-to-see".getBytes(StandardCharsets.UTF_8);
        IOException refused = assertThrows(IOException.class,
                () -> rewrite(frame(plainAuth, (short) 2, placeholder)));
        assertTrue(refused.getMessage().contains("outside the auth bytes"), refused.getMessage());
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
