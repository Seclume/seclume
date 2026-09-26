package space.seclume.redis;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;

import redis.clients.jedis.JedisSocketFactory;
import redis.clients.jedis.exceptions.JedisConnectionException;
import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;
import space.seclume.secret.SecretScope;

/**
 * Connections for Jedis that are logged in before Jedis gets them - with the
 * password read into native memory, written from there, and wiped.
 *
 * <pre>
 * JedisSocketFactory sockets = SeclumeRedisSocketFactory.of(
 *         "rediss://cache:6380?user=orders&amp;provider=file&amp;path=/run/secrets/redis");
 * try (Jedis jedis = new Jedis(sockets)) { ... }
 * // pooled:
 * RedisClient redis = RedisClient.builder().connectionProvider(new PooledConnectionProvider(
 *         new ConnectionFactory(sockets, DefaultJedisClientConfig.builder().build()))).build();
 * </pre>
 *
 * <p>Jedis given a password keeps it as a {@code String} in its client
 * configuration and sends {@code AUTH} from a heap buffer at every connect.
 * Here Jedis is given no password at all: this factory opens the connection,
 * sends {@code AUTH [user] password} from a {@link SecretScope}, reads the
 * {@code +OK}, and hands Jedis the authenticated socket.
 *
 * <p>{@code rediss://} encrypts with seclume's own TLS 1.3 stack, checking the
 * certificate and the host name ({@code tlsRootCert=} or {@code tlsPin=} for
 * a CA the JVM does not know). Not the JDK's: {@code AUTH} would pass through
 * JSSE's record buffers, which are heap and never wiped. A server that does
 * not speak TLS 1.3 cannot be reached this way.
 *
 * <p>Options besides {@code user}, {@code tlsRootCert}, {@code tlsPin},
 * {@code connectTimeout} and {@code timeout} (milliseconds) are the secret
 * provider's, as in a seclume JDBC URL. A password in the URL is refused.
 */
public final class SeclumeRedisSocketFactory implements JedisSocketFactory {

    private final String host;
    private final int port;
    private final String user;
    private final boolean tls;
    private final TrustChoice.Choice trust;
    private final int connectTimeout;
    private final int timeout;
    private final SecretProvider secret;

    private SeclumeRedisSocketFactory(String host, int port, String user, boolean tls,
                                      TrustChoice.Choice trust, int connectTimeout, int timeout,
                                      SecretProvider secret) {
        this.host = host;
        this.port = port;
        this.user = user;
        this.tls = tls;
        this.trust = trust;
        this.connectTimeout = connectTimeout;
        this.timeout = timeout;
        this.secret = secret;
    }

    /** From a {@code redis://} or {@code rediss://} URL - see the class comment. */
    public static SeclumeRedisSocketFactory of(String url) {
        URI uri = URI.create(url);
        boolean tls = switch (String.valueOf(uri.getScheme())) {
            case "redis" -> false;
            case "rediss" -> true;
            default -> throw new IllegalArgumentException(
                    "a Redis URL begins with redis:// or rediss://");
        };
        if (uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("a user or password in front of the host is not "
                    + "taken: the password would be a String for the life of the application. "
                    + "Name the user with user= and the secret with provider= and path=");
        }
        Map<String, String> options = new LinkedHashMap<>();
        String query = uri.getRawQuery();
        if (query != null) {
            for (String pair : query.split("&")) {
                int equals = pair.indexOf('=');
                if (equals > 0) {
                    options.put(decode(pair.substring(0, equals)), decode(pair.substring(equals + 1)));
                }
            }
        }
        String user = options.remove("user");
        String rootCert = options.remove(TrustChoice.ROOT_CERT);
        String pin = options.remove(TrustChoice.PIN);
        int connectTimeout = Integer.parseInt(options.getOrDefault("connectTimeout", "5000"));
        int timeout = Integer.parseInt(options.getOrDefault("timeout", "2000"));
        options.remove("connectTimeout");
        options.remove("timeout");
        TrustChoice.Choice trust = null;
        if (rootCert != null || pin != null) {
            java.util.Properties named = new java.util.Properties();
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
        return new SeclumeRedisSocketFactory(uri.getHost(), uri.getPort() < 0 ? 6379
                : uri.getPort(), user, tls, trust, connectTimeout, timeout,
                SecretProviders.of(options));
    }

    @Override
    public Socket createSocket() throws JedisConnectionException {
        SocketTransport transport = null;
        TlsLayer layer = null;
        try {
            transport = SocketTransport.connect(host, port, connectTimeout);
            if (tls) {
                SocketTransport plain = transport;
                layer = TrustChoice.using(trust, () -> {
                    try {
                        return TlsLayers.start(TlsStack.SECLUME, plain, host, port, true);
                    } catch (IOException e) {
                        throw new SQLException(e.getMessage(), "08001", e);
                    }
                });
            }
            TransportSocket socket = new TransportSocket(transport, layer, host, port);
            socket.setSoTimeout(timeout);
            authenticate(socket);
            return socket;
        } catch (IOException | SQLException | RuntimeException e) {
            if (layer != null) {
                try {
                    layer.close();
                } catch (Exception ignored) {
                    // closing anyway
                }
            }
            if (transport != null) {
                transport.close();
            }
            if (e instanceof JedisConnectionException refused) {
                throw refused;
            }
            throw new JedisConnectionException("could not connect to Redis at " + host + ":"
                    + port + ": " + e.getMessage(), e);
        }
    }

    /**
     * {@code AUTH [user] password} as one RESP array, built and sent from
     * native memory, then the one-line answer.
     */
    private void authenticate(TransportSocket socket) throws IOException {
        try (SecretScope password = SecretScope.fromProvider(secret)) {
            int length = password.length();
            byte[] head = header(length);                         // no secret in it
            try (SecretScope command = SecretScope.allocate(head.length + length + 2)) {
                MemorySegment out = command.segment();
                MemorySegment.copy(head, 0, out, ValueLayout.JAVA_BYTE, 0, head.length);
                MemorySegment.copy(password.segment(), 0, out, head.length, length);
                out.set(ValueLayout.JAVA_BYTE, head.length + length, (byte) '\r');
                out.set(ValueLayout.JAVA_BYTE, head.length + length + 1, (byte) '\n');
                command.length(head.length + length + 2);
                socket.send(out.asSlice(0, command.length()).asByteBuffer());
            }
        }
        String answer = socket.readLine();
        if (!answer.equals("+OK")) {
            // An error line names the reason (WRONGPASS, NOAUTH); it never echoes the password.
            throw new JedisConnectionException("Redis refused the login"
                    + (user == null ? "" : " of " + user) + ": " + answer);
        }
    }

    /** Everything of the AUTH command before the password - public by construction. */
    private byte[] header(int passwordLength) {
        StringBuilder text = new StringBuilder(); // seclume-allow: the command head, the password is not in it
        if (user == null) {
            text.append("*2\r\n$4\r\nAUTH\r\n");
        } else {
            byte[] name = user.getBytes(StandardCharsets.UTF_8); // seclume-allow: the user name, which is public
            text.append("*3\r\n$4\r\nAUTH\r\n$").append(name.length).append("\r\n")
                    .append(user).append("\r\n");
        }
        text.append('$').append(passwordLength).append("\r\n");
        return text.toString().getBytes(StandardCharsets.UTF_8); // seclume-allow: the command head, no secret in it
    }

    private static String decode(String text) {
        return java.net.URLDecoder.decode(text, StandardCharsets.UTF_8);
    }

    /** For the tests: which way it is encrypted. */
    boolean encrypted() {
        return tls;
    }
}
