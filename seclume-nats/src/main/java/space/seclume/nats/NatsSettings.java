package space.seclume.nats;

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
 * Which NATS server and how to log in:
 *
 * <pre>
 * tls://nats.example.com:4222?auth=nkey&amp;provider=file&amp;path=/run/secrets/user.nk
 * tls://nats.example.com:4222?auth=creds&amp;provider=file&amp;path=/run/secrets/user.creds
 * tls://nats.example.com:4222?user=app&amp;provider=file&amp;path=/run/secrets/nats-password
 * tls://nats.example.com:4222?auth=token&amp;provider=file&amp;path=/run/secrets/nats-token
 * </pre>
 *
 * <ul>
 *   <li>{@code tls://} or {@code nats://} (4222 by default). A password or a
 *       token travels inside {@code CONNECT} and therefore requires
 *       {@code tls://}; {@code nats://} is permitted only for challenge-response
 *       logins ({@code auth=nkey} or {@code auth=creds}), where only the
 *       Ed25519 signature goes over the wire;
 *   <li>{@code auth=nkey} or {@code auth=creds} signs the server's challenge in
 *       native memory; {@code user=} (or {@code auth=password}) writes the
 *       password into {@code CONNECT} from native memory; {@code auth=token}
 *       writes the token into {@code CONNECT} from native memory;
 *   <li>{@code tlsRootCert} or {@code tlsPin} for a CA the JVM does not know,
 *       {@code connectTimeout} and {@code timeout} in milliseconds.
 * </ul>
 */
final class NatsSettings {

    enum AuthMode {
        PASSWORD,
        TOKEN,
        NKEY,
        CREDS
    }

    final String host;
    final int port;
    final boolean tls;
    final AuthMode mode;
    final String user;
    final TrustChoice.Choice trust;
    final int connectTimeout;
    final int timeout;
    final SecretProvider secret;

    private NatsSettings(String host, int port, boolean tls, AuthMode mode, String user,
                         TrustChoice.Choice trust, int connectTimeout, int timeout,
                         SecretProvider secret) {
        this.host = host;
        this.port = port;
        this.tls = tls;
        this.mode = mode;
        this.user = user;
        this.trust = trust;
        this.connectTimeout = connectTimeout;
        this.timeout = timeout;
        this.secret = secret;
    }

    static NatsSettings of(String spec) {
        URI uri = URI.create(spec);
        String scheme = uri.getScheme();
        boolean tls;
        if ("tls".equalsIgnoreCase(scheme) || "natss".equalsIgnoreCase(scheme)) {
            tls = true;
        } else if ("nats".equalsIgnoreCase(scheme)) {
            tls = false;
        } else {
            throw new IllegalArgumentException("a NATS URL begins with tls:// or nats://, not "
                    + scheme + "://");
        }
        if (uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("a user, password or token in front of the host is "
                    + "not taken: the secret would be a String for the life of the application. "
                    + "Name the user with user= and the secret with provider=");
        }
        if (uri.getHost() == null || uri.getHost().isEmpty()) {
            throw new IllegalArgumentException("no host in the NATS URL");
        }
        Map<String, String> options = parseQuery(uri.getRawQuery());
        String user = options.remove("user");
        String auth = options.remove("auth");
        AuthMode mode = resolveMode(auth, user);
        if (!tls && (mode == AuthMode.PASSWORD || mode == AuthMode.TOKEN)) {
            throw new IllegalArgumentException("a NATS password or token login requires tls:// "
                    + "(not nats://): the secret is sent inside CONNECT and is never sent in the "
                    + "clear");
        }
        if (mode == AuthMode.PASSWORD && (user == null || user.isEmpty())) {
            throw new IllegalArgumentException("a NATS password login needs user=");
        }
        if (mode != AuthMode.PASSWORD && user != null) {
            throw new IllegalArgumentException("user= is only for password logins, not auth="
                    + auth);
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
                    + "(provider=file&path=/run/secrets/nats, provider=vault&...)");
        }
        if (mode != AuthMode.PASSWORD) {
            defaultMaxLength(options);
        }
        int port = uri.getPort() >= 0 ? uri.getPort() : 4222;
        return new NatsSettings(uri.getHost(), port, tls, mode, user, trust, connectTimeout,
                timeout, SecretProviders.of(options));
    }

    static SecretProvider providerOf(String spec) {
        if (spec == null || spec.isBlank()) {
            throw new IllegalArgumentException("no secret named: add provider= and its options");
        }
        Map<String, String> options = parseQuery(spec);
        if (!options.containsKey("provider")) {
            throw new IllegalArgumentException("no secret named: add provider= and its options");
        }
        defaultMaxLength(options);
        return SecretProviders.of(options);
    }

    /**
     * A NATS {@code .creds} file or bearer JWT is typically 500–4096 bytes
     * (much longer than {@link SecretProviders#DEFAULT_MAX_LENGTH}'s 256-byte
     * database-password bound). Unless the caller set {@code max-length}
     * explicitly, allow up to 16 KiB.
     */
    private static void defaultMaxLength(Map<String, String> options) {
        if (!options.containsKey("max-length") && !options.containsKey("maxLength")) {
            options.put("max-length", "16384");
        }
    }

    static Map<String, String> parseQuery(String query) {
        Map<String, String> options = new LinkedHashMap<>();
        if (query != null) {
            for (String pair : query.split("&")) {
                int equals = pair.indexOf('=');
                if (equals > 0) {
                    options.put(decode(pair.substring(0, equals)),
                            decode(pair.substring(equals + 1)));
                }
            }
        }
        return options;
    }

    private static AuthMode resolveMode(String auth, String user) {
        if (auth == null || auth.isEmpty()) {
            if (user != null && !user.isEmpty()) {
                return AuthMode.PASSWORD;
            }
            throw new IllegalArgumentException("a NATS URL needs user= (for a password login) or "
                    + "auth=nkey, auth=creds, or auth=token");
        }
        return switch (auth.toLowerCase(java.util.Locale.ROOT)) {
            case "password" -> AuthMode.PASSWORD;
            case "token" -> AuthMode.TOKEN;
            case "nkey" -> AuthMode.NKEY;
            case "creds", "credentials", "jwt" -> AuthMode.CREDS;
            default -> throw new IllegalArgumentException("unknown NATS auth=" + auth
                    + " (expected password, token, nkey or creds)");
        };
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

    String serverUri() {
        return (tls ? "tls://" : "nats://") + host + ":" + port;
    }

    String target() {
        return host + ":" + port;
    }
}
