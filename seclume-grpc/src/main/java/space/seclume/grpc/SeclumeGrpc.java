package space.seclume.grpc;

import java.util.concurrent.Executor;

import io.grpc.CallCredentials;
import io.grpc.Metadata;
import io.grpc.okhttp.OkHttpChannelBuilder;

import space.seclume.http.SeclumeSslSocketFactory;

/**
 * gRPC with the bearer token or API key off the heap.
 *
 * <pre>
 * ManagedChannel channel = SeclumeGrpc.channel("api.example.com", 443, "tlsRootCert=/etc/ca.pem")
 *         .build();
 * CallCredentials token = SeclumeGrpc.bearer("provider=file&amp;path=/run/secrets/token");
 * GreeterGrpc.newBlockingStub(channel).withCallCredentials(token).sayHello(...);
 * </pre>
 *
 * <p>Call credentials put their token into a {@code Metadata} - a
 * {@code String} on the heap, for every call. Here they put a placeholder
 * (see {@link SeclumeSslSocketFactory#placeholder}); the channel is the OkHttp
 * transport over seclume's TLS 1.3 - which checks the server's certificate
 * itself, against the JVM's trust or {@code tlsRootCert}/{@code tlsPin} - and
 * the socket writes the secret, read for each call so a rotated one is picked
 * up, into the HTTP/2 header block where the placeholder is.
 */
public final class SeclumeGrpc {

    private static final Metadata.Key<String> AUTHORIZATION =
            Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);

    private SeclumeGrpc() {
    }

    /**
     * A channel builder for {@code host:port} over seclume's TLS, with
     * {@code tlsRootCert}, {@code tlsPin} and {@code connectTimeout} from
     * {@code tlsOptions}. Anything else - executors, keep-alive, interceptors
     * - is the application's to set.
     */
    public static OkHttpChannelBuilder channel(String host, int port, String tlsOptions) {
        SeclumeSslSocketFactory tls = SeclumeSslSocketFactory.of(tlsOptions).http2();
        return OkHttpChannelBuilder.forAddress(host, port)
                .sslSocketFactory(tls)
                .hostnameVerifier(tls.hostnameVerifier());
    }

    /** {@code authorization: Bearer <token>}, the token named by the secret provider options {@code spec}. */
    public static CallCredentials bearer(String spec) {
        return header(AUTHORIZATION, "Bearer ", spec);
    }

    /**
     * A header {@code name} - {@code x-api-key}, say - whose value is the
     * secret named by {@code spec}.
     */
    public static CallCredentials header(String name, String spec) {
        return header(Metadata.Key.of(name, Metadata.ASCII_STRING_MARSHALLER), "", spec);
    }

    private static CallCredentials header(Metadata.Key<String> key, String prefix, String spec) {
        String value = prefix + SeclumeSslSocketFactory.placeholder(spec);
        return new CallCredentials() {
            @Override
            public void applyRequestMetadata(RequestInfo info, Executor executor,
                                             MetadataApplier applier) {
                Metadata headers = new Metadata();
                headers.put(key, value);
                applier.apply(headers);
            }
        };
    }
}
