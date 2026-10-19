package space.seclume.http;

import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.util.Map;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import space.seclume.internal.SeclumeSslEngine;
import space.seclume.internal.TrustChoice;

/**
 * An {@code SSLContext} for HTTP clients that take one and make engines from
 * it - Apache HttpClient 5 async (the Elasticsearch {@code Rest5Client}, the
 * OpenSearch {@code ApacheHttpClient5Transport}) and HttpAsyncClient 4 (the
 * Elasticsearch {@code RestClient}): its engines are seclume's TLS 1.3, and
 * write secrets into request heads where the client wrote the placeholders
 * of {@link SeclumeSslSocketFactory#placeholder} - see
 * {@link HttpCredentialRewriter}.
 *
 * <pre>
 * SSLContext tls = SeclumeSslContext.of("tlsRootCert=/etc/es/ca.pem");
 * String key = SeclumeSslSocketFactory.placeholder("provider=file&amp;path=/run/secrets/es-key");
 * // the client's default header: Authorization: ApiKey &lt;key&gt;
 * </pre>
 *
 * <p>Every engine checks the server's certificate and name itself, whatever
 * the client configures besides: an engine without a host - no name to check,
 * no SNI - is refused. HTTP/1.1: no ALPN is offered, so a client that would
 * negotiate HTTP/2 stays on HTTP/1.1, whose heads are the ones rewritten.
 * The socket factory of this context is a {@link SeclumeSslSocketFactory}.
 */
public final class SeclumeSslContext extends SSLContext {

    private SeclumeSslContext(Spi spi) {
        super(spi, null, "TLSv1.3");
    }

    /** A context with {@code tlsRootCert} and {@code tlsPin} from {@code options}. */
    public static SSLContext of(String options) {
        Map<String, String> parsed = SeclumeSslSocketFactory.parse(options);
        TrustChoice.Choice trust = SeclumeSslSocketFactory.trust(
                parsed.get(TrustChoice.ROOT_CERT), parsed.get(TrustChoice.PIN));
        return new SeclumeSslContext(new Spi(trust, SeclumeSslSocketFactory.of(options)));
    }

    private static final class Spi extends SSLContextSpi {

        private final TrustChoice.Choice trust;
        private final SeclumeSslSocketFactory sockets;

        Spi(TrustChoice.Choice trust, SeclumeSslSocketFactory sockets) {
            this.trust = trust;
            this.sockets = sockets;
        }

        /** Nothing to set: whom to trust came with {@link #of}, and there is no key to give. */
        @Override
        protected void engineInit(KeyManager[] keys, TrustManager[] trusts, SecureRandom random)
                throws KeyManagementException {
        }

        @Override
        protected SSLEngine engineCreateSSLEngine() {
            throw new UnsupportedOperationException("a seclume TLS engine needs the server's "
                    + "host name - to check its certificate and for SNI");
        }

        @Override
        protected SSLEngine engineCreateSSLEngine(String host, int port) {
            return new SeclumeSslEngine(host, port, trust,
                    new HttpCredentialRewriter(host + ":" + port));
        }

        @Override
        protected SSLSocketFactory engineGetSocketFactory() {
            return sockets;
        }

        @Override
        protected SSLServerSocketFactory engineGetServerSocketFactory() {
            throw new UnsupportedOperationException("seclume's TLS is a client only");
        }

        @Override
        protected SSLSessionContext engineGetServerSessionContext() {
            return null;
        }

        @Override
        protected SSLSessionContext engineGetClientSessionContext() {
            return null;
        }

        /** Asked by clients before they make an engine - so not from an engine without a host. */
        @Override
        protected SSLParameters engineGetDefaultSSLParameters() {
            return parameters();
        }

        @Override
        protected SSLParameters engineGetSupportedSSLParameters() {
            return parameters();
        }

        private static SSLParameters parameters() {
            return new SSLParameters(new String[] {"TLS_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256"}, new String[] {"TLSv1.3"});
        }
    }
}
