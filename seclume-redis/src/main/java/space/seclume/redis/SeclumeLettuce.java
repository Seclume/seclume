package space.seclume.redis;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import io.lettuce.core.ClientOptions;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.SocketOptions;
import io.lettuce.core.cluster.ClusterClientOptions;
import io.lettuce.core.cluster.RedisClusterClient;
import io.lettuce.core.resource.ClientResources;
import io.lettuce.core.resource.DefaultClientResources;
import io.lettuce.core.resource.NettyCustomizer;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.handler.ssl.SslHandler;

import space.seclume.internal.SeclumeSslEngine;

/**
 * Lettuce with the password off the heap - standalone, Sentinel and Cluster:
 *
 * <pre>
 * // Standalone:
 * RedisClient redis = SeclumeLettuce.client(
 *         "rediss://cache:6380?user=orders&amp;provider=file&amp;path=/run/secrets/redis");
 * // Sentinel:
 * RedisClient sentinel = SeclumeLettuce.client(
 *         "rediss://sentinel-1:26379,sentinel-2:26379?sentinelMasterId=mymaster"
 *         + "&amp;user=orders&amp;provider=file&amp;path=/run/secrets/redis");
 * // Cluster:
 * RedisClusterClient cluster = SeclumeLettuce.clusterClient(
 *         "rediss://node-1:6379,node-2:6379?user=orders&amp;provider=file&amp;path=/run/secrets/redis");
 * </pre>
 *
 * <p>Lettuce given a password keeps it as a {@code char[]} in its credentials
 * and encodes it into a Netty buffer for {@code AUTH} or {@code HELLO} at
 * every connect and reconnect; with TLS, the JDK's engine or OpenSSL's then
 * copies it again. Here Lettuce is given a random placeholder instead, and
 * the password is read from its provider into native memory for each of
 * those commands and written in the placeholder's place on the way out:
 * <ul>
 *   <li>{@code rediss://} and {@code rediss-sentinel://} - by seclume's own
 *       TLS 1.3, which Lettuce does not know about: its connection is plain
 *       to it, and when a channel connects to a node the first handler before
 *       the socket is a {@code SslHandler} over {@link SeclumeSslEngine} for
 *       that node's own host and port, which checks the node's certificate
 *       and name ({@code tlsRootCert=} or {@code tlsPin=} for a CA the JVM
 *       does not know) and puts the password into the cipher from native
 *       memory;
 *   <li>{@code redis://} and {@code redis-sentinel://} - by the first handler
 *       before the socket, which hands the password to the socket as a direct
 *       buffer over native memory.
 * </ul>
 *
 * <p>Every connection opened through the client's resources - to the initial
 * seed nodes, to cluster shards discovered on topology refresh or redirect,
 * to Sentinels and to the master or replica Sentinel names - checks the
 * certificate against the host and port of that node itself. When Sentinel
 * nodes take a login of their own, {@code sentinelUser=} and
 * {@code sentinel-provider=} (with {@code sentinel-path=}, and so on) supply
 * Sentinel's credentials through a second placeholder without touching the
 * heap. Options as for {@link SeclumeRedisSocketFactory}.
 */
public final class SeclumeLettuce {

    private SeclumeLettuce() {
    }

    /**
     * A standalone or Sentinel client for {@code url}, with client resources
     * of its own - shut down with it by {@link RedisClient#shutdown()}.
     */
    public static RedisClient client(String url) {
        RedisUrl parsed = RedisUrl.parse(url);
        if (parsed.sentinelMasterId() == null && parsed.nodes().size() > 1) {
            throw new IllegalArgumentException("more than one node in the URL without "
                    + "sentinelMasterId=<name>: use SeclumeLettuce.clusterClient(url) for a Redis "
                    + "Cluster, or set sentinelMasterId=<name> for Redis Sentinel");
        }
        String placeholder = RespPasswordRewriter.newPlaceholder();
        String sentinelPlaceholder = parsed.sentinelSecret() != null
                ? RespPasswordRewriter.newPlaceholder() : null;
        ClientResources resources = DefaultClientResources.builder()
                .nettyCustomizer(customizer(parsed, placeholder, sentinelPlaceholder)).build();
        OwningClient client = new OwningClient(resources,
                uri(parsed, placeholder, sentinelPlaceholder));
        client.setOptions(ClientOptions.builder()
                .socketOptions(SocketOptions.builder()
                        .connectTimeout(Duration.ofMillis(Math.max(parsed.connectTimeout(), 1)))
                        .build())
                .build());
        return client;
    }

    /**
     * What a client that is built elsewhere needs - Spring Data Redis's
     * {@code LettuceConnectionFactory}: the {@link RedisURI} for {@code url}
     * with the placeholder where the password goes, and client resources
     * whose channels write the password in. Whoever builds the client on them
     * closes this when it is done with them.
     */
    public record Prepared(RedisURI uri, ClientResources resources) implements AutoCloseable {

        @Override
        public void close() {
            resources.shutdown();
        }
    }

    /** See {@link Prepared}; standalone or Sentinel, as {@link #client}. */
    public static Prepared prepare(String url) {
        RedisUrl parsed = RedisUrl.parse(url);
        if (parsed.sentinelMasterId() == null && parsed.nodes().size() > 1) {
            throw new IllegalArgumentException("more than one node in the URL without "
                    + "sentinelMasterId=<name>: a Redis Cluster is not prepared for a client "
                    + "built elsewhere; set sentinelMasterId=<name> for Redis Sentinel");
        }
        String placeholder = RespPasswordRewriter.newPlaceholder();
        String sentinelPlaceholder = parsed.sentinelSecret() != null
                ? RespPasswordRewriter.newPlaceholder() : null;
        ClientResources resources = DefaultClientResources.builder()
                .nettyCustomizer(customizer(parsed, placeholder, sentinelPlaceholder)).build();
        return new Prepared(uri(parsed, placeholder, sentinelPlaceholder), resources);
    }

    /**
     * A Redis Cluster client for {@code url}, with client resources of its
     * own - shut down with it by {@link RedisClusterClient#shutdown()}.
     * Every seed and every cluster node discovered on topology refresh or
     * redirect has its certificate checked against its own host name or IP
     * address and receives the password from native memory.
     */
    public static RedisClusterClient clusterClient(String url) {
        RedisUrl parsed = RedisUrl.parse(url);
        if (parsed.sentinelMasterId() != null) {
            throw new IllegalArgumentException("sentinelMasterId is for Redis Sentinel with "
                    + "SeclumeLettuce.client(url), not SeclumeLettuce.clusterClient(url)");
        }
        String placeholder = RespPasswordRewriter.newPlaceholder();
        ClientResources resources = DefaultClientResources.builder()
                .nettyCustomizer(customizer(parsed, placeholder, null)).build();
        List<RedisURI> uris = new ArrayList<>(parsed.nodes().size());
        for (RedisUrl.Node node : parsed.nodes()) {
            uris.add(nodeUri(node, parsed, placeholder));
        }
        OwningClusterClient cluster = new OwningClusterClient(resources, uris);
        cluster.setOptions(ClusterClientOptions.builder()
                .socketOptions(SocketOptions.builder()
                        .connectTimeout(Duration.ofMillis(Math.max(parsed.connectTimeout(), 1)))
                        .build())
                .build());
        return cluster;
    }

    private static RedisURI uri(RedisUrl url, String placeholder, String sentinelPlaceholder) {
        Duration timeout = Duration.ofMillis(Math.max(url.timeout(), 1));
        if (url.sentinelMasterId() != null) {
            RedisUrl.Node first = url.nodes().get(0);
            RedisURI.Builder builder = RedisURI.Builder
                    .sentinel(first.host(), first.port(), url.sentinelMasterId())
                    .withSsl(false)                 // seclume's TLS, below Lettuce
                    .withTimeout(timeout);
            RedisURI built = (url.user() == null
                    ? builder.withPassword(placeholder.toCharArray())
                    : builder.withAuthentication(url.user(), placeholder.toCharArray())).build();
            built.getSentinels().clear();
            for (RedisUrl.Node node : url.nodes()) {
                RedisURI.Builder sentinel = RedisURI.Builder.redis(node.host(), node.port())
                        .withSsl(false)
                        .withTimeout(timeout);
                if (sentinelPlaceholder != null) {
                    if (url.sentinelUser() == null) {
                        sentinel.withPassword(sentinelPlaceholder.toCharArray());
                    } else {
                        sentinel.withAuthentication(
                                url.sentinelUser(), sentinelPlaceholder.toCharArray());
                    }
                }
                built.getSentinels().add(sentinel.build());
            }
            return built;
        }
        return nodeUri(url.nodes().get(0), url, placeholder);
    }

    private static RedisURI nodeUri(RedisUrl.Node node, RedisUrl url, String placeholder) {
        RedisURI.Builder uri = RedisURI.Builder.redis(node.host(), node.port())
                .withSsl(false)                     // seclume's TLS, below Lettuce
                .withTimeout(Duration.ofMillis(Math.max(url.timeout(), 1)));
        return (url.user() == null ? uri.withPassword(placeholder.toCharArray())
                : uri.withAuthentication(url.user(), placeholder.toCharArray())).build();
    }

    private static NettyCustomizer customizer(RedisUrl url, String placeholder,
                                              String sentinelPlaceholder) {
        return new NettyCustomizer() {
            @Override
            public void afterChannelInitialized(Channel channel) {
                channel.pipeline().addFirst("seclume-connect", new ChannelOutboundHandlerAdapter() {
                    @Override
                    public void connect(ChannelHandlerContext ctx, SocketAddress remoteAddress,
                                        SocketAddress localAddress, ChannelPromise promise)
                            throws Exception {
                        String host = hostOf(remoteAddress, url);
                        int port = portOf(remoteAddress, url);
                        RespPasswordRewriter rewriter = new RespPasswordRewriter(
                                placeholder, url.secret(),
                                sentinelPlaceholder, url.sentinelSecret(),
                                host + ":" + port);
                        if (url.tls()) {
                            SslHandler tls = new SslHandler(new SeclumeSslEngine(
                                    host, port, url.trust(), rewriter));
                            tls.setHandshakeTimeoutMillis(Math.max(url.connectTimeout(), 1));
                            ctx.pipeline().addBefore(ctx.name(), "seclume-tls", tls);
                        } else {
                            ctx.pipeline().addBefore(ctx.name(), "seclume-password",
                                    new RespPasswordHandler(rewriter));
                        }
                        ctx.connect(remoteAddress, localAddress, promise);
                        ctx.pipeline().remove(this);
                    }
                });
            }
        };
    }

    private static String hostOf(SocketAddress remoteAddress, RedisUrl fallback) {
        if (remoteAddress instanceof InetSocketAddress inet) {
            String host = inet.getHostString();
            if (host != null && !host.isEmpty()) {
                if (host.startsWith("[") && host.endsWith("]")) {
                    return host.substring(1, host.length() - 1);
                }
                return host;
            }
        }
        return fallback.host();
    }

    private static int portOf(SocketAddress remoteAddress, RedisUrl fallback) {
        if (remoteAddress instanceof InetSocketAddress inet && inet.getPort() > 0) {
            return inet.getPort();
        }
        return fallback.port();
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
            return super.shutdownAsync(quietPeriod, timeout, timeUnit)
                    .thenCompose(done -> releaseResources(resources, quietPeriod, timeout, timeUnit));
        }
    }

    /** A cluster client that shuts its own resources down with it. */
    private static final class OwningClusterClient extends RedisClusterClient {

        private final ClientResources resources;

        OwningClusterClient(ClientResources resources, Iterable<RedisURI> uris) {
            super(resources, uris);
            this.resources = resources;
        }

        @Override
        public CompletableFuture<Void> shutdownAsync(long quietPeriod, long timeout,
                                                     TimeUnit timeUnit) {
            return super.shutdownAsync(quietPeriod, timeout, timeUnit)
                    .thenCompose(done -> releaseResources(resources, quietPeriod, timeout, timeUnit));
        }
    }

    private static CompletableFuture<Void> releaseResources(ClientResources resources,
                                                            long quietPeriod, long timeout,
                                                            TimeUnit timeUnit) {
        CompletableFuture<Void> released = new CompletableFuture<>();
        resources.shutdown(quietPeriod, timeout, timeUnit).addListener(future -> {
            if (future.isSuccess()) {
                released.complete(null);
            } else {
                released.completeExceptionally(future.cause());
            }
        });
        return released;
    }
}

