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
 * CallCredentials token = SeclumeGrpc.bearer("provider=file&amp;path=/run/secrets/token",
 *         "api.example.com:443");
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

    /**
     * {@code authorization: Bearer <token>}, the token named by the secret
     * provider options {@code spec}, sent to {@code server} only - the
     * {@code host:port} of the channel. On a channel to another server the
     * call carries the placeholder, which that server refuses.
     *
     * <p>Make it once per channel and keep it: each call of this registers a
     * placeholder that stays until the process ends.
     */
    public static CallCredentials bearer(String spec, String server) {
        return header(AUTHORIZATION, "Bearer ", spec, server);
    }

    /**
     * A header {@code name} - {@code x-api-key}, say - whose value is the
     * secret named by {@code spec}, sent to {@code server} ({@code host:port}) only.
     */
    public static CallCredentials header(String name, String spec, String server) {
        return header(Metadata.Key.of(name, Metadata.ASCII_STRING_MARSHALLER), "", spec, server);
    }

    /**
     * The token bound to whichever server it is first written for - the same
     * credentials used on a second channel, to another host, would give that
     * host the token if it came first.
     *
     * @deprecated names no server; use {@link #bearer(String, String)}
     */
    @Deprecated(since = "0.15.0", forRemoval = true)
    public static CallCredentials bearer(String spec) {
        return header(AUTHORIZATION, "Bearer ", spec, null);
    }

    /**
     * The header bound to whichever server it is first written for.
     *
     * @deprecated names no server; use {@link #header(String, String, String)}
     */
    @Deprecated(since = "0.15.0", forRemoval = true)
    public static CallCredentials header(String name, String spec) {
        return header(Metadata.Key.of(name, Metadata.ASCII_STRING_MARSHALLER), "", spec, null);
    }

    private static CallCredentials header(Metadata.Key<String> key, String prefix, String spec,
                                          String server) {
        String value = prefix + (server == null ? SeclumeSslSocketFactory.placeholder(spec)
                : SeclumeSslSocketFactory.placeholder(spec, java.util.List.of(server)));
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
