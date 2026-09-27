package space.seclume.http;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import space.seclume.internal.TrustChoice;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/**
 * Which API, and how to prove who is calling - read from one URL, the way a
 * seclume JDBC URL names its database:
 *
 * <pre>
 * https://api.example.com/v1?provider=file&amp;path=/run/secrets/api-token          (Bearer)
 * https://search.internal:9200?auth=header&amp;header=Authorization&amp;prefix=ApiKey%20
 *         &amp;provider=vault&amp;...                                               (Elasticsearch)
 * https://registry.internal?auth=basic&amp;user=deploy&amp;provider=file&amp;path=...     (Basic)
 * https://api.stripe.com?auth=header&amp;header=X-Api-Key&amp;provider=...
 * </pre>
 *
 * <ul>
 *   <li>Only {@code https://}: the credential is never sent in the clear. The
 *       path, if any, is the base every relative request is resolved against;
 *   <li>{@code auth} is {@code bearer} (the default: {@code Authorization:
 *       Bearer <secret>}), {@code basic} ({@code user=} and the secret as the
 *       password) or {@code header} ({@code header=} names it, {@code prefix=}
 *       goes in front of the secret);
 *   <li>{@code tlsRootCert} or {@code tlsPin} for a CA the JVM does not know,
 *       {@code connectTimeout} and {@code timeout} in milliseconds,
 *       {@code maxIdle} connections kept for reuse and {@code idleTimeout} after
 *       which one is not reused;
 *   <li>everything else is the secret provider's, as in a JDBC URL. A user or
 *       password in front of the host, and a key in the query meant for the
 *       API, are refused - both would be a {@code String} for good.
 * </ul>
 */
final class HttpSettings {

    /** How the secret goes into the request. */
    enum Auth { BEARER, BASIC, HEADER, OAUTH2 }

    /** A server to connect to: where, whose certificate, and how long to wait. */
    record Endpoint(String host, int port, TrustChoice.Choice trust, int connectTimeout,
                    int timeout) {
    }

    final String host;
    final int port;
    final String basePath;
    final Auth auth;
    final String user;
    final String headerName;
    final String prefix;
    final TrustChoice.Choice trust;
    final int connectTimeout;
    final int timeout;
    final int maxIdle;
    final long idleTimeoutMillis;
    final SecretProvider secret;
    final OAuthSettings oauth;

    private HttpSettings(String host, int port, String basePath, Auth auth, String user,
                         String headerName, String prefix, TrustChoice.Choice trust,
                         int connectTimeout, int timeout, int maxIdle, long idleTimeoutMillis,
                         SecretProvider secret, OAuthSettings oauth) {
        this.host = host;
        this.port = port;
        this.basePath = basePath;
        this.auth = auth;
        this.user = user;
        this.headerName = headerName;
        this.prefix = prefix;
        this.trust = trust;
        this.connectTimeout = connectTimeout;
        this.timeout = timeout;
        this.maxIdle = maxIdle;
        this.idleTimeoutMillis = idleTimeoutMillis;
        this.secret = secret;
        this.oauth = oauth;
    }

    /** The API's server. */
    Endpoint endpoint() {
        return new Endpoint(host, port, trust, connectTimeout, timeout);
    }

    static HttpSettings of(String url) {
        URI uri = URI.create(url);
        String scheme = String.valueOf(uri.getScheme()).toLowerCase(Locale.ROOT);
        if (!scheme.equals("https")) {
            throw new IllegalArgumentException("an API URL begins with https://, not "
                    + uri.getScheme() + "://: the credential is never sent in the clear");
        }
        if (uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("a user or password in front of the host is not "
                    + "taken: the password would be a String for the life of the application. "
                    + "Use auth=basic with user= and name the secret with provider=");
        }
        if (uri.getHost() == null) {
            throw new IllegalArgumentException("no host in the API URL");
        }
        Map<String, String> options = new LinkedHashMap<>();
        String query = uri.getRawQuery();
        if (query != null) {
            for (String pair : query.split("&")) {
                int equals = pair.indexOf('=');
                if (equals > 0) {
                    options.put(decode(pair.substring(0, equals)),
                            decode(pair.substring(equals + 1)));
                }
            }
        }
        String authName = remove(options, "auth", "bearer");
        String user = options.remove("user");
        String headerName = options.remove("header");
        String prefix = remove(options, "prefix", "");
        String rootCert = options.remove(TrustChoice.ROOT_CERT);
        String pin = options.remove(TrustChoice.PIN);
        int connectTimeout = number(remove(options, "connectTimeout", "10000"), "connectTimeout");
        int timeout = number(remove(options, "timeout", "60000"), "timeout");
        int maxIdle = number(remove(options, "maxIdle", "8"), "maxIdle");
        int idleTimeout = number(remove(options, "idleTimeout", "30000"), "idleTimeout");

        Auth auth = switch (authName.toLowerCase(Locale.ROOT)) {
            case "bearer" -> Auth.BEARER;
            case "basic" -> Auth.BASIC;
            case "header" -> Auth.HEADER;
            case "oauth2" -> Auth.OAUTH2;
            default -> throw new IllegalArgumentException(
                    "auth is bearer, basic, header or oauth2, not '" + authName + "'");
        };
        switch (auth) {
            case BASIC -> {
                if (user == null || user.isEmpty()) {
                    throw new IllegalArgumentException("auth=basic needs user=");
                }
                if (user.indexOf(':') >= 0 || !printable(user)) {
                    throw new IllegalArgumentException("a Basic user name cannot hold ':' or "
                            + "control characters");
                }
                headerName = "Authorization";
                prefix = "Basic ";
            }
            case BEARER, OAUTH2 -> {
                if (headerName != null) {
                    throw new IllegalArgumentException("header= belongs to auth=header; "
                            + "bearer is always Authorization");
                }
                headerName = "Authorization";
                prefix = "Bearer ";
            }
            case HEADER -> {
                if (headerName == null || !token(headerName)) {
                    throw new IllegalArgumentException("auth=header needs header= with the "
                            + "header's name, e.g. header=X-Api-Key");
                }
                if (!printable(prefix)) {
                    throw new IllegalArgumentException("prefix= cannot hold control "
                            + "characters");
                }
            }
            default -> throw new IllegalStateException(auth.name());
        }
        if (auth != Auth.BASIC && user != null) {
            throw new IllegalArgumentException("user= belongs to auth=basic");
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
        if (!options.containsKey("provider")) {
            throw new IllegalArgumentException("no secret named: add provider= and its "
                    + "options (provider=file&path=/run/secrets/api-token, provider=vault&..."
                    + ") - the same as in a seclume JDBC URL");
        }
        OAuthSettings oauth = auth == Auth.OAUTH2
                ? OAuthSettings.take(options, connectTimeout, timeout) : null;
        SecretProvider secret = SecretProviders.of(options);

        String path = uri.getRawPath() == null ? "" : uri.getRawPath();
        while (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return new HttpSettings(uri.getHost(), uri.getPort() >= 0 ? uri.getPort() : 443, path,
                auth, user, headerName, prefix, trust, connectTimeout, timeout, maxIdle,
                idleTimeout, secret, oauth);
    }

    /** {@code host} or {@code host:port} - what goes into the Host header. */
    String authority() {
        String name = host.indexOf(':') >= 0 ? "[" + host + "]" : host;
        return port == 443 ? name : name + ":" + port;
    }

    /** Whether {@code uri} is on the origin the credential belongs to. */
    boolean sameOrigin(URI uri) {
        String scheme = uri.getScheme();
        int otherPort = uri.getPort() >= 0 ? uri.getPort() : 443;
        return "https".equalsIgnoreCase(scheme) && host.equalsIgnoreCase(uri.getHost())
                && otherPort == port;
    }

    /** RFC 9110 token characters - a header name. */
    static boolean token(String text) {
        if (text.isEmpty()) {
            return false;
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            boolean ok = c > 32 && c < 127 && "()<>@,;:\\\"/[]?={}".indexOf(c) < 0;
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    /** No control characters - nothing that could end a header line early. */
    static boolean printable(String text) {
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < 32 && c != '\t' || c == 127) {
                return false;
            }
        }
        return true;
    }

    private static int number(String text, String name) {
        int value;
        try {
            value = Integer.parseInt(text);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(name + " is a number of 0 or more, not '"
                    + text + "'", e);
        }
        if (value < 0) {
            throw new IllegalArgumentException(name + " is a number of 0 or more, not '"
                    + text + "'");
        }
        return value;
    }

    private static String remove(Map<String, String> options, String key, String otherwise) {
        String value = options.remove(key);
        return value == null ? otherwise : value;
    }

    private static String decode(String text) {
        return java.net.URLDecoder.decode(text, StandardCharsets.UTF_8);
    }

    @Override
    public String toString() {
        return "https://" + authority() + basePath + " (" + auth.name().toLowerCase(Locale.ROOT)
                + (user == null ? "" : " as " + user) + ")";
    }
}
