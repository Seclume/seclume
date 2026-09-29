package space.seclume.redis;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.resource.ClientResources;
import io.lettuce.core.resource.DefaultClientResources;
import io.lettuce.core.resource.NettyCustomizer;
import io.netty.channel.Channel;
import io.netty.handler.ssl.SslHandler;

import space.seclume.internal.SeclumeSslEngine;

/**
 * Lettuce with the password off the heap:
 *
 * <pre>
 * RedisClient redis = SeclumeLettuce.client(
 *         "rediss://cache:6380?user=orders&amp;provider=file&amp;path=/run/secrets/redis");
 * try (StatefulRedisConnection&lt;String, String&gt; connection = redis.connect()) { ... }
 * redis.shutdown();
 * </pre>
 *
 * <p>Lettuce given a password keeps it as a {@code char[]} in its credentials
 * and encodes it into a Netty buffer for {@code AUTH} or {@code HELLO} at
 * every connect and reconnect; with TLS, the JDK's engine or OpenSSL's then
 * copies it again. Here Lettuce is given a random placeholder instead, and
 * the password is read from its provider into native memory for each of
 * those commands and written in the placeholder's place on the way out:
 * <ul>
 *   <li>{@code rediss://} - by seclume's own TLS 1.3, which Lettuce does not
 *       know about: its connection is plain to it, and the first handler
 *       before the socket is a {@code SslHandler} over
 *       {@link SeclumeSslEngine}, which checks the server's certificate and
 *       name ({@code tlsRootCert=} or {@code tlsPin=} for a CA the JVM does
 *       not know) and puts the password into the cipher from native memory;
 *   <li>{@code redis://} - by the first handler before the socket, which hands
 *       the password to the socket as a direct buffer over native memory.
 * </ul>
 *
 * <p>A standalone server: the certificate is checked against the URL's host,
 * so a cluster or Sentinel topology, whose nodes have names of their own, is
 * not covered. Options as for {@link SeclumeRedisSocketFactory}.
 */
public final class SeclumeLettuce {

    private SeclumeLettuce() {
    }

    /**
     * A client for {@code url}, with client resources of its own - shut down
     * with it by {@link RedisClient#shutdown()}.
     */
    public static RedisClient client(String url) {
        RedisUrl parsed = RedisUrl.parse(url);
        String placeholder = RespPasswordRewriter.newPlaceholder();
        ClientResources resources = DefaultClientResources.builder()
                .nettyCustomizer(customizer(parsed, placeholder)).build();
        return new OwningClient(resources, uri(parsed, placeholder));
    }

    private static RedisURI uri(RedisUrl url, String placeholder) {
        RedisURI.Builder uri = RedisURI.Builder.redis(url.host(), url.port())
                .withSsl(false)                     // seclume's TLS, below Lettuce
                .withTimeout(java.time.Duration.ofMillis(Math.max(url.timeout(), 1)));
        return (url.user() == null ? uri.withPassword(placeholder.toCharArray())
                : uri.withAuthentication(url.user(), placeholder.toCharArray())).build();
    }

    private static NettyCustomizer customizer(RedisUrl url, String placeholder) {
        return new NettyCustomizer() {
            @Override
            public void afterChannelInitialized(Channel channel) {
                RespPasswordRewriter rewriter = new RespPasswordRewriter(placeholder, url.secret());
                if (url.tls()) {
                    SslHandler tls = new SslHandler(new SeclumeSslEngine(url.host(), url.port(),
                            url.trust(), rewriter));
                    tls.setHandshakeTimeoutMillis(Math.max(url.connectTimeout(), 1));
                    channel.pipeline().addFirst("seclume-tls", tls);
                } else {
                    channel.pipeline().addFirst("seclume-password", new RespPasswordHandler(rewriter));
                }
            }
        };
    }

    /** A client that shuts its own resources down with it. */
    private static final class OwningClient extends RedisClient {

        private final ClientResources resources;

        OwningClient(ClientResources resources, RedisURI uri) {
            super(resources, uri);
            this.resources = resources;
        }

        @Override
        public CompletableFuture<Void> shutdownAsync(long quietPeriod, long timeout,
                                                     TimeUnit timeUnit) {
            return super.shutdownAsync(quietPeriod, timeout, timeUnit).thenCompose(done -> {
                CompletableFuture<Void> released = new CompletableFuture<>();
                resources.shutdown(quietPeriod, timeout, timeUnit).addListener(future -> {
                    if (future.isSuccess()) {
                        released.complete(null);
                    } else {
                        released.completeExceptionally(future.cause());
                    }
                });
                return released;
            });
        }
    }
}
