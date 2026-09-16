package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.internal.Entropy;
import space.seclume.crypto.NativeP256;

/**
 * Opt in with -Dseclume.tls.hello.host=... and optionally
 * -Dseclume.tls.hello.port=5433. A configured but unavailable server FAILS.
 *
 * <p>The server judges our encoding; this is deliberately not a full handshake.
 * Only the public Hello messages are read. Our native provider generates the
 * private key and exports only the public share for the encoder. JSSE's
 * independent full handshake uses a SECOND connection, not the same session.
 * No database password is read or sent. The test-only trust manager permits the
 * fixture's self-signed certificate; this does not test peer authentication.
 */
class LocalClientHelloTest {
    private record Reply(int type, byte[] body, byte[] sessionId) { }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"localhost"})
    void postgresAcceptsOurHelloAndJsseAgreesOnTheSuite(String sni) throws Exception {
        Reply reply = exchange(sni, false);
        assertEquals(22, reply.type(), "expected handshake, got "
                + reply.type() + " / " + java.util.HexFormat.of().formatHex(reply.body()));
        MemorySegment message = MemorySegment.ofArray(reply.body());
        assertEquals(Handshake.SERVER_HELLO, Handshake.type(message, 0));
        assertEquals(reply.body().length, Handshake.totalLength(message, 0));
        long body = Handshake.HEADER;
        assertEquals(0x0303, Handshake.u16(message, body));
        assertEquals(32, Handshake.sessionIdLength(message, body));
        assertEquals(-1, MemorySegment.ofArray(reply.sessionId()).mismatch(
                message.asSlice(Handshake.sessionIdOffset(body), 32)));
        // HRR is a ServerHello with this fixed random; it is not an accepted share.
        assertNotEquals("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c",
                java.util.HexFormat.of().formatHex(Arrays.copyOfRange(reply.body(), 6, 38)));
        int suite = Handshake.cipherSuite(message, body);
        assertTrue(suite == 0x1301 || suite == 0x1302, "unoffered cipher suite");
        assertEquals(0, message.get(ValueLayout.JAVA_BYTE,
                Handshake.sessionIdOffset(body) + 32 + 2));
        int[] size = new int[1];
        long at = Handshake.serverHelloExtensions(message, body, size);
        assertEquals(message.byteSize(), at + size[0]);
        Set<Integer> seen = new HashSet<>();
        long end = at;
        while (end < at + size[0]) {
            int type = Handshake.u16(message, end);
            int length = Handshake.u16(message, end + 2);
            assertTrue(seen.add(type), "duplicate extension");
            if (type == 43) {
                assertEquals(2, length);
                assertEquals(0x0304, Handshake.selectedVersion(message, end + 4));
            } else if (type == 51) {
                assertEquals(69, length);
                long[] share = new long[2];
                assertEquals(23, Handshake.serverKeyShare(message, end + 4, share));
                assertEquals(65, share[1]);
                assertEquals(4, message.get(ValueLayout.JAVA_BYTE, share[0]));
                assertTrue(message.asSlice(share[0], share[1]).mismatch(
                        MemorySegment.ofArray(new byte[65])) >= 0);
            }
            end += 4 + length;
        }
        assertEquals(at + size[0], end);
        assertEquals(Set.of(43, 51), seen);
        String expected = suite == 0x1302 ? "TLS_AES_256_GCM_SHA384" : "TLS_AES_128_GCM_SHA256";
        try (Socket raw = postgres()) {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] {new FixtureTrust()}, null);
            try (SSLSocket tls = (SSLSocket) context.getSocketFactory()
                    .createSocket(raw, host(), port(), true)) {
                tls.setSoTimeout(5000);
                tls.setEnabledProtocols(new String[] {"TLSv1.3"});
                tls.setEnabledCipherSuites(new String[] {"TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"});
                tls.startHandshake();
                assertEquals("TLSv1.3", tls.getSession().getProtocol());
                assertEquals(expected, tls.getSession().getCipherSuite());
            }
        }
        System.err.println("[ClientHello] PostgreSQL accepted SNI=" + sni
                + ", TLSv1.3 / " + expected + " / P-256; separate JSSE handshake agrees");
    }

    @Test
    void postgresRejectsAnUnofferableVersion() throws Exception {
        Reply reply = exchange(null, true);
        assertEquals(21, reply.type(), "negative control must receive an alert");
        assertEquals(2, reply.body().length);
        assertEquals(2, reply.body()[0], "fatal");
        assertEquals(70, reply.body()[1], "protocol_version");
        System.err.println("[ClientHello] negative control: TLS 0x0305 rejected with fatal protocol_version");
    }

    private static Reply exchange(String sni, boolean corruptVersion) throws Exception {
        // Check opt-in before generating test keys or opening any connection.
        host();
        try (Arena arena = Arena.ofConfined(); Socket socket = postgres(); NativeP256 key = NativeP256.generate()) {
            MemorySegment random = arena.allocate(32);
            MemorySegment session = arena.allocate(32);
            Entropy.fill(random);
            Entropy.fill(session);
            MemorySegment share = arena.allocate(65);
            key.publicKey(share);
            MemorySegment hello = arena.allocate(1024);
            int count = ClientHello.write(hello, 0, random, session, ClientHello.SECP256R1, share, sni);
            if (corruptVersion) {
                int[] size = new int[1];
                long at = Handshake.clientHelloExtensions(hello, 4, size);
                boolean[] changed = {false};
                Handshake.extensions(hello, at, size[0], (type, start, length) -> {
                    if (type == 43) {
                        hello.set(ValueLayout.JAVA_BYTE, start + 2, (byte) 5);
                        changed[0] = true;
                    }
                });
                assertTrue(changed[0]);
            }
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            out.writeByte(22);
            out.writeShort(0x0301); // RFC 8446 permits this for the initial ClientHello
            out.writeShort(count);
            out.write(hello.asSlice(0, count).toArray(ValueLayout.JAVA_BYTE)); // public hello only
            out.flush();
            DataInputStream in = new DataInputStream(socket.getInputStream());
            int type = in.readUnsignedByte();
            int version = in.readUnsignedShort();
            assertTrue(version == 0x0303 || type == 21 && version == 0x0301);
            int length = in.readUnsignedShort();
            assertTrue(length > 0 && length <= 16384);
            byte[] response = new byte[length];
            in.readFully(response);
            return new Reply(type, response, session.toArray(ValueLayout.JAVA_BYTE));
        }
    }

    private static String host() {
        String host = System.getProperty("seclume.tls.hello.host");
        Assumptions.assumeTrue(host != null && !host.isBlank(), "no ClientHello fixture configured");
        return host;
    }

    private static int port() {
        return Integer.getInteger("seclume.tls.hello.port", 5433);
    }

    private static Socket postgres() throws Exception {
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(host(), port()), 5000);
            socket.setSoTimeout(5000);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            out.writeInt(8);
            out.writeInt(80877103);
            out.flush();
            assertEquals('S', socket.getInputStream().read(), "PostgreSQL must accept SSLRequest");
            return socket;
        } catch (Exception | AssertionError e) {
            socket.close();
            throw e;
        }
    }

    private static final class FixtureTrust implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String type) {
            throw new UnsupportedOperationException("client certificates are not used");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String type) {
            // Only the explicit test endpoint, never production trust policy.
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
