package space.seclume.http;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import space.seclume.internal.TrustChoice;
import space.seclume.secret.SecretProviders;

/**
 * An {@code SSLSocketFactory} for HTTP clients that were not written for
 * seclume - OkHttp (and with it the Kubernetes clients), {@code
 * HttpsURLConnection} (and with it JGit), anything that takes a socket factory
 * - whose sockets write secrets into requests from native memory.
 *
 * <pre>
 * SeclumeSslSocketFactory tls = SeclumeSslSocketFactory.of("");          // or "tlsRootCert=/etc/ca.pem"
 * String token = SeclumeSslSocketFactory.placeholder("provider=file&amp;path=/run/secrets/token");
 *
 * OkHttpClient client = new OkHttpClient.Builder()
 *         .sslSocketFactory(tls, tls.trustManager())
 *         .hostnameVerifier(tls.hostnameVerifier())
 *         .build();
 * // ... request.header("Authorization", "Bearer " + token)
 * </pre>
 *
 * <p>The client holds the placeholder and builds its requests with it: as a
 * bearer token, an API key header, or the password of a Basic login. The
 * sockets are seclume's TLS 1.3, checking the server's certificate themselves
 * (the JVM's trust, or {@code tlsRootCert}/{@code tlsPin}), and write the
 * secret where the placeholder is - see {@link CredentialSocket}. HTTP/1.1,
 * without ALPN; or HTTP/2 for a factory from {@link #http2()}.
 */
public final class SeclumeSslSocketFactory extends SSLSocketFactory {

    private final TrustChoice.Choice trust;
    private final int connectTimeout;
    private final boolean http2;

    private SeclumeSslSocketFactory(TrustChoice.Choice trust, int connectTimeout, boolean http2) {
        this.trust = trust;
        this.connectTimeout = connectTimeout;
        this.http2 = http2;
    }

    /**
     * The same factory for HTTP/2 clients - the gRPC OkHttp transport: its
     * sockets offer and require {@code h2}, and write the secrets into header
     * blocks (see {@link Http2Requests}) instead of HTTP/1.1 heads.
     */
    public SeclumeSslSocketFactory http2() {
        return new SeclumeSslSocketFactory(trust, connectTimeout, true);
    }

    /** A factory with {@code tlsRootCert}, {@code tlsPin} and {@code connectTimeout} from {@code options}. */
    public static SeclumeSslSocketFactory of(String options) {
        Map<String, String> parsed = parse(options);
        String rootCert = parsed.remove(TrustChoice.ROOT_CERT);
        String pin = parsed.remove(TrustChoice.PIN);
        int connectTimeout;
        try {
            connectTimeout = Integer.parseInt(parsed.getOrDefault("connectTimeout", "10000"));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("connectTimeout is not a number of milliseconds: '"
                    + parsed.get("connectTimeout") + "'", e);
        }
        TrustChoice.Choice trust = null;
        if (rootCert != null || pin != null) {
            Properties named = new Properties();
            if (rootCert != null) {
                named.setProperty(TrustChoice.ROOT_CERT, rootCert);
            }
            if (pin != null) {
                named.setProperty(TrustChoice.PIN, pin);
            }
            try {
                trust = TrustChoice.of(null, named);
            } catch (SQLException e) {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
        }
        return new SeclumeSslSocketFactory(trust, connectTimeout, false);
    }

    /**
     * A placeholder for the secret named by {@code spec} - the secret
     * provider's options - to give the HTTP client instead of the secret.
     * Read each time a request carries it, so a rotated token is picked up.
     */
    public static String placeholder(String spec) {
        Map<String, String> options = parse(spec);
        if (!options.containsKey("provider")) {
            throw new IllegalArgumentException("no secret named: give the secret provider's "
                    + "options, e.g. provider=file&path=/run/secrets/token");
        }
        if (!options.containsKey("max-length") && !options.containsKey("maxLength")) {
            options.put("max-length", "16384");           // a JWT - a Kubernetes token - is kilobytes
        }
        return CredentialPlaceholders.register(SecretProviders.of(options));
    }

    /** For clients that ask: accepts the hostnames seclume's TLS already checked. */
    public HostnameVerifier hostnameVerifier() {
        return (host, session) -> CredentialSocket.ours(session);
    }

    /**
     * For clients that insist on one (OkHttp): never consulted for seclume's
     * sockets, which check the certificate themselves, and refusing anything
     * else.
     */
    public X509TrustManager trustManager() {
        return new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType)
                    throws CertificateException {
                throw new CertificateException("seclume's sockets check certificates "
                        + "themselves; nothing is trusted through this manager");
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType)
                    throws CertificateException {
                throw new CertificateException("seclume's sockets check certificates "
                        + "themselves; nothing is trusted through this manager");
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
    }

    @Override
    public Socket createSocket(Socket plain, String host, int port, boolean autoClose)
            throws IOException {
        return CredentialSocket.over(plain, host, port, trust, http2);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        Socket plain = new Socket();
        plain.connect(new InetSocketAddress(host, port), connectTimeout);
        return CredentialSocket.over(plain, host, port, trust, http2);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
            throws IOException {
        return createSocket(host, port);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return createSocket(host.getHostName(), port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress,
                               int localPort) throws IOException {
        return createSocket(address.getHostName(), port);
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return new String[] {"TLS_AES_128_GCM_SHA256"};
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return getDefaultCipherSuites();
    }

    private static Map<String, String> parse(String options) {
        Map<String, String> parsed = new LinkedHashMap<>();
        if (options == null || options.isBlank()) {
            return parsed;
        }
        for (String pair : (options.startsWith("?") ? options.substring(1) : options)
                .split("&")) {
            int equals = pair.indexOf('=');
            if (equals > 0) {
                parsed.put(URLDecoder.decode(pair.substring(0, equals), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8));
            }
        }
        return parsed;
    }
}
