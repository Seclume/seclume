package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.Transport;

/**
 * {@link ServerCertificateAlertTest} for TLS 1.2, where the Certificate
 * travels in the clear right after the ServerHello: a certificate that cannot
 * be read is a {@code bad_certificate}, one the trust store refuses a
 * {@code certificate_unknown}, and an empty list stays the
 * {@code decode_error} it already was. The alert goes out in the clear too,
 * and the peer here reads it off the wire.
 */
@Timeout(60)
class Tls12ServerCertificateAlertTest {

    private static final int ECDHE_ECDSA_AES_128_GCM = 0xC02B;

    private static TestCertificates certificates;
    private static CertificateTrust trust;
    private static byte[] leaf;

    @BeforeAll
    static void issueAServerCertificate() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        leaf = certificates.issueEc("server", "san=dns:db.example.com", "ku:c=digitalSignature",
                "eku=serverAuth").certificate().getEncoded();
        trust = CertificateTrust.of(certificates.trustStore());
    }

    @AfterAll
    static void removeTheAuthority() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    @Test
    void aCertificateThatCannotBeReadIsABadCertificate() {
        byte[] notDer = new byte[40];
        Arrays.fill(notDer, (byte) 0x04);
        Peer peer = new Peer(certificate(notDer));
        TlsProtocolException refused = assertThrows(TlsProtocolException.class,
                () -> ClientHandshake.connectWithoutAuthenticating(peer, "db.example.com"));
        assertEquals(TlsAlertException.BAD_CERTIFICATE, refused.alert(), refused.getMessage());
        assertTrue(refused.getMessage().contains("cannot be read"), refused.getMessage());
        assertEquals(TlsAlertException.BAD_CERTIFICATE, peer.alertSent(), "the server has to be told why");
    }

    @Test
    void aCertificateForAnotherNameIsUnacceptable() {
        Peer peer = new Peer(certificate(leaf));
        TlsProtocolException refused = assertThrows(TlsProtocolException.class,
                () -> ClientHandshake.connect(peer, "other.example.com", trust));
        assertEquals(TlsAlertException.CERTIFICATE_UNKNOWN, refused.alert(), refused.getMessage());
        assertEquals(TlsAlertException.CERTIFICATE_UNKNOWN, peer.alertSent(), "the server has to be told why");
    }

    @Test
    void anEmptyListStaysADecodeError() {
        Peer peer = new Peer(new byte[] {Handshake.CERTIFICATE, 0, 0, 3, 0, 0, 0});
        TlsProtocolException refused = assertThrows(TlsProtocolException.class,
                () -> ClientHandshake.connectWithoutAuthenticating(peer, "db.example.com"));
        assertEquals(TlsAlertException.DECODE_ERROR, refused.alert(), refused.getMessage());
        assertEquals(TlsAlertException.DECODE_ERROR, peer.alertSent());
    }

    /** A Certificate message with one entry. */
    private static byte[] certificate(byte[] der) {
        int list = 3 + der.length;
        return concat(new byte[] {Handshake.CERTIFICATE, (byte) ((list + 3) >>> 16), (byte) ((list + 3) >>> 8),
                (byte) (list + 3), (byte) (list >>> 16), (byte) (list >>> 8), (byte) list,
                (byte) (der.length >>> 16), (byte) (der.length >>> 8), (byte) der.length}, der);
    }

    /** Answers the ClientHello with a TLS 1.2 ServerHello and the given Certificate, in the clear. */
    private static final class Peer implements Transport {

        private final byte[] certificate;
        private final ByteArrayOutputStream written = new ByteArrayOutputStream();
        private ByteBuffer toClient = ByteBuffer.allocate(0);
        private boolean answered;

        Peer(byte[] certificate) {
            this.certificate = certificate;
        }

        @Override
        public int read(ByteBuffer into) {
            if (!toClient.hasRemaining()) {
                return -1;
            }
            int n = Math.min(into.remaining(), toClient.remaining());
            into.put(toClient.slice().limit(n));
            toClient.position(toClient.position() + n);
            return n;
        }

        @Override
        public int write(ByteBuffer from) {
            int n = from.remaining();
            byte[] bytes = new byte[n];
            from.get(bytes);
            written.writeBytes(bytes);
            if (!answered) {
                answered = true;
                toClient = ByteBuffer.wrap(concat(serverHello(), record(certificate)));
            }
            return n;
        }

        /** The description of the last alert the client sent in the clear, or -1. */
        int alertSent() {
            byte[] all = written.toByteArray();
            int at = 0;
            int alert = -1;
            while (all.length - at >= 5) {
                int type = all[at] & 0xff;
                int length = ((all[at + 3] & 0xff) << 8) | (all[at + 4] & 0xff);
                if (type == 21 && length >= 2 && at + 6 < all.length) {
                    alert = all[at + 6] & 0xff;
                }
                at += 5 + length;
            }
            return alert;
        }

        @Override
        public boolean isOpen() {
            return true;
        }

        @Override
        public void close() {
        }
    }

    private static byte[] serverHello() {
        byte[] random = new byte[32];
        Arrays.fill(random, (byte) 0x11);
        byte[] sessionId = new byte[32];
        Arrays.fill(sessionId, (byte) 0x22);
        // extended_master_secret, empty; renegotiation_info, empty.
        byte[] extensions = {0, 0x17, 0, 0, (byte) 0xff, 1, 0, 1, 0};
        byte[] body = concat(new byte[] {3, 3}, random, new byte[] {32}, sessionId,
                new byte[] {(byte) (ECDHE_ECDSA_AES_128_GCM >>> 8), (byte) ECDHE_ECDSA_AES_128_GCM, 0,
                        0, (byte) extensions.length}, extensions);
        return record(concat(new byte[] {Handshake.SERVER_HELLO, 0, (byte) (body.length >>> 8),
                (byte) body.length}, body));
    }

    private static byte[] record(byte[] message) {
        return concat(new byte[] {22, 3, 3, (byte) (message.length >>> 8), (byte) message.length}, message);
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }
}
