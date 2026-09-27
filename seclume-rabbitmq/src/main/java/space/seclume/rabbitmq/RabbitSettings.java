package space.seclume.rabbitmq;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import space.seclume.internal.TrustChoice;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/**
 * Which broker and how to log in - one URL, the way a seclume JDBC URL names
 * its database:
 *
 * <pre>
 * amqps://mq.example.com/orders?user=app&amp;provider=file&amp;path=/run/secrets/rabbit
 * amqps://mq.example.com:5671?user=app&amp;provider=azure-managed-identity&amp;...   (OAuth 2 token)
 * </pre>
 *
 * <ul>
 *   <li>Only {@code amqps://}: the login is never sent in the clear. 5671 by
 *       default; the path is the virtual host ({@code /} when there is none,
 *       {@code %2F} spelled out);
 *   <li>{@code user} is the login; the secret provider's options name the
 *       password - or a token, for RabbitMQ's OAuth 2 plugin, which takes it
 *       in the same place;
 *   <li>{@code tlsRootCert} or {@code tlsPin} for a CA the JVM does not know,
 *       {@code connectTimeout} and {@code timeout} in milliseconds.
 * </ul>
 */
final class RabbitSettings {

    final String host;
    final int port;
    final String virtualHost;
    final String user;
    final TrustChoice.Choice trust;
    final int connectTimeout;
    final int timeout;
    final SecretProvider secret;

    private RabbitSettings(String host, int port, String virtualHost, String user,
                           TrustChoice.Choice trust, int connectTimeout, int timeout,
                           SecretProvider secret) {
        this.host = host;
        this.port = port;
        this.virtualHost = virtualHost;
        this.user = user;
        this.trust = trust;
        this.connectTimeout = connectTimeout;
        this.timeout = timeout;
        this.secret = secret;
    }

    static RabbitSettings of(String url) {
        URI uri = URI.create(url);
        if (!"amqps".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("a RabbitMQ URL begins with amqps://, not "
                    + uri.getScheme() + "://: the login is never sent in the clear");
        }
        if (uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("a user or password in front of the host is not "
                    + "taken: the password would be a String for the life of the application. "
                    + "Name the user with user= and the secret with provider=");
        }
        if (uri.getHost() == null) {
            throw new IllegalArgumentException("no host in the RabbitMQ URL");
        }
        Map<String, String> options = new LinkedHashMap<>();
        if (uri.getRawQuery() != null) {
            for (String pair : uri.getRawQuery().split("&")) {
                int equals = pair.indexOf('=');
                if (equals > 0) {
                    options.put(decode(pair.substring(0, equals)),
                            decode(pair.substring(equals + 1)));
                }
            }
        }
        String user = options.remove("user");
        if (user == null || user.isEmpty()) {
            throw new IllegalArgumentException("a RabbitMQ URL needs user=");
        }
        if (user.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("the user name holds a NUL");
        }
        String rootCert = options.remove(TrustChoice.ROOT_CERT);
        String pin = options.remove(TrustChoice.PIN);
        int connectTimeout = number(options.remove("connectTimeout"), 10_000, "connectTimeout");
        int timeout = number(options.remove("timeout"), 60_000, "timeout");
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
        if (!options.containsKey("provider")) {
            throw new IllegalArgumentException("no secret named: add provider= and its options "
                    + "(provider=file&path=/run/secrets/rabbit, provider=vault&...)");
        }
        String path = uri.getRawPath();
        String virtualHost = path == null || path.length() <= 1 ? "/"
                : decode(path.substring(1));
        return new RabbitSettings(uri.getHost(), uri.getPort() >= 0 ? uri.getPort() : 5671,
                virtualHost, user, trust, connectTimeout, timeout, SecretProviders.of(options));
    }

    private static int number(String text, int otherwise, String name) {
        if (text == null) {
            return otherwise;
        }
        int value;
        try {
            value = Integer.parseInt(text);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(name + " is a number of milliseconds, not '"
                    + text + "'", e);
        }
        if (value < 0) {
            throw new IllegalArgumentException(name + " is 0 or more, not " + value);
        }
        return value;
    }

    private static String decode(String text) {
        return java.net.URLDecoder.decode(text.replace("+", "%2B"), StandardCharsets.UTF_8);
    }

    @Override
    public String toString() {
        return "amqps://" + host + ":" + port + " vhost " + virtualHost + " as " + user;
    }
}
