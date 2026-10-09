package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.SocketException;

import org.junit.jupiter.api.Test;

/**
 * A TLS 1.2 server refusing our client certificate.
 *
 * <p>Unlike TLS 1.3, where the server judges the certificate after our
 * Finished, a TLS 1.2 server judges it as soon as it reads the Certificate
 * message - and closes while ClientKeyExchange, CertificateVerify,
 * ChangeCipherSpec and Finished are still being written. The reset that
 * follows throws its alert away, so whichever of those writes fails has to
 * name the certificate, as the TLS 1.3 handshake does. Found against a
 * PostgreSQL server held to TLS 1.2 with a certificate from an untrusted
 * issuer: "Connection reset by peer", and nothing else.
 */
class Tls12RefusedCertificateTest {

    @Test
    void aResetAfterTheCertificateNamesTheCertificate() {
        SocketException reset = new SocketException("Connection reset by peer");
        IOException failure = assertThrows(IOException.class,
                () -> Tls12Handshake.afterCertificate(true, () -> {
                    throw reset;
                }));
        assertTrue(failure.getMessage().startsWith("Connection reset by peer - right after the "
                + "client certificate was sent"), failure.getMessage());
        assertSame(reset, failure.getCause(), "the original stays the cause");
    }

    @Test
    void withoutACertificateTheFailureStaysAsItWas() {
        SocketException reset = new SocketException("Connection reset by peer");
        assertSame(reset, assertThrows(IOException.class,
                () -> Tls12Handshake.afterCertificate(false, () -> {
                    throw reset;
                })));
    }

    @Test
    void anAlertThatArrivedIsPassedOnAsItIs() {
        TlsAlertException alert = new TlsAlertException(2, 48);   // fatal unknown_ca
        assertSame(alert, assertThrows(TlsAlertException.class,
                () -> Tls12Handshake.afterCertificate(true, () -> {
                    throw alert;
                })));
    }
}
