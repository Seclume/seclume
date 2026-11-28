package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;

/**
 * T18 - the server's ephemeral point in a TLS 1.2 ServerKeyExchange: P-256
 * only in uncompressed form and only at its exact length. Checked before
 * the signature is looked at, so no certificate is needed to reach it.
 */
class ServerKeyExchangePointTest {

    private static int alertFor(byte[] params) throws Exception {
        Method read = Tls12Handshake.class.getDeclaredMethod("readServerKeyExchange",
                MemorySegment.class, long.class, int.class, MemorySegment.class,
                MemorySegment.class, X509Certificate.class, Arena.class);
        read.setAccessible(true);
        try (Arena arena = Arena.ofConfined()) {
            byte[] message = new byte[params.length + 4 + 64];      // signature room, never reached
            System.arraycopy(params, 0, message, 0, params.length);
            message[params.length] = 4;                              // ecdsa_secp256r1_sha256
            message[params.length + 1] = 3;
            message[params.length + 3] = 64;
            MemorySegment segment = arena.allocateFrom(ValueLayout.JAVA_BYTE, message);
            MemorySegment random = arena.allocate(32);
            InvocationTargetException failed = assertThrows(InvocationTargetException.class,
                    () -> read.invoke(null, segment, 0L, message.length, random, random, null, arena));
            TlsProtocolException refused = assertInstanceOf(TlsProtocolException.class, failed.getCause());
            return refused.alert();
        }
    }

    private static byte[] p256(int pointLength, int format) {
        byte[] params = new byte[4 + pointLength];
        params[0] = 3;                      // named_curve
        params[1] = 0;
        params[2] = 0x17;                   // secp256r1
        params[3] = (byte) pointLength;
        params[4] = (byte) format;
        return params;
    }

    @Test
    void aCompressedP256PointIsRefused() throws Exception {
        assertEquals(TlsAlertException.ILLEGAL_PARAMETER, alertFor(p256(65, 2)));
        assertEquals(TlsAlertException.ILLEGAL_PARAMETER, alertFor(p256(65, 3)));
    }

    @Test
    void aP256PointOfTheWrongLengthIsRefused() throws Exception {
        assertEquals(TlsAlertException.ILLEGAL_PARAMETER, alertFor(p256(64, 4)));
        assertEquals(TlsAlertException.ILLEGAL_PARAMETER, alertFor(p256(33, 2)));
    }
}
