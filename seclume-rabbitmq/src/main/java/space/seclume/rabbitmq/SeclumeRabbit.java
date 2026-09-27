package space.seclume.rabbitmq;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

import javax.net.SocketFactory;

import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DefaultSaslConfig;

/**
 * RabbitMQ with the password - or the OAuth 2 token - off the heap.
 *
 * <pre>
 * ConnectionFactory factory = SeclumeRabbit.connectionFactory(
 *         "amqps://mq.example.com/orders?user=app&amp;provider=file&amp;path=/run/secrets/rabbit");
 * try (Connection connection = factory.newConnection()) { ... }
 *
 * // Spring AMQP: RabbitTemplate, @RabbitListener - nothing else changes
 * CachingConnectionFactory spring = new CachingConnectionFactory(factory);
 * </pre>
 *
 * <p>The official Java client given a password keeps it as a {@code String}
 * in its {@code ConnectionFactory} for good, builds the SASL PLAIN response as
 * another one, and sends it through JSSE's heap buffers at every connect and
 * every recovery. Here the client is given a placeholder. Its connections come
 * from a socket factory whose sockets encrypt with seclume's own TLS 1.3 and
 * put the real response into the handshake from native memory (see
 * {@link AmqpSocket}); after that they are a pipe, and channels, publishing,
 * consumers, confirms and automatic recovery are the client's as always.
 *
 * <p>Host, port, virtual host and user are set from the URL. Everything else -
 * heartbeats, recovery, executors - the application may set on the factory as
 * it would; the password, the user, the SASL mechanism and the socket factory
 * are this class's, and a password set on the factory is refused at connect.
 */
public final class SeclumeRabbit {

    /** What the client is given where it wants a password. Not a secret; never sent. */
    static final String PLACEHOLDER = "seclume-logs-in-itself";

    private SeclumeRabbit() {
    }

    /** A client ConnectionFactory for one broker - see the class comment. */
    public static ConnectionFactory connectionFactory(String url) {
        RabbitSettings settings = RabbitSettings.of(url);
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost(settings.host);
        factory.setPort(settings.port);
        factory.setVirtualHost(settings.virtualHost);
        factory.setUsername(settings.user);
        factory.setPassword(PLACEHOLDER);
        factory.setSaslConfig(DefaultSaslConfig.PLAIN);
        factory.setConnectionTimeout(settings.connectTimeout);
        factory.setSocketFactory(new SocketFactory() {
            @Override
            public Socket createSocket() {
                return new AmqpSocket(settings);
            }

            @Override
            public Socket createSocket(String host, int port) throws IOException {
                Socket socket = createSocket();
                socket.connect(null);
                return socket;
            }

            @Override
            public Socket createSocket(String host, int port, InetAddress localHost,
                                       int localPort) throws IOException {
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
        });
        return factory;
    }
}
