package space.seclume.mongodb;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import space.seclume.internal.TrustChoice;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/**
 * A MongoDB connection URL as seclume takes it: host and port, {@code user},
 * {@code authSource}, {@code tlsRootCert} or {@code tlsPin},
 * {@code connectTimeout} and {@code timeout} in milliseconds - and the rest
 * the secret provider's settings.
 *
 * <p>A password in the URL is strictly refused, keeping the secret off the
 * heap from the outset.
 */
public record MongoUrl(String host, int port, String user, String authSource,
                TrustChoice.Choice trust, int connectTimeout, int timeout,
                SecretProvider secret, String driverConnectionString) {

    private static final int DEFAULT_PORT = 27017;
    private static final int DEFAULT_CONNECT_TIMEOUT = 10_000;
    private static final String DEFAULT_AUTH_SOURCE = "admin";

    private static final Set<String> SECLUME_KEYS = Set.of(
            "user", "authsource",
            "provider", "path", "key", "target", "entropy", "command",
            "max-length", "maxlength", "request", "aad", "address",
            "namespace", "verify", "timeout-millis", "credentials",
            "region", "secret-id", "field", "vault-uri", "name",
            "version", "project", "resource", "client-id", "scopes",
            "access-key-id", "db-user",
            "connecttimeout", "timeout", "sockettimeout"
    );

    static MongoUrl parse(String url) {
        if (url == null || url.isEmpty()) {
            throw new IllegalArgumentException("MongoDB URL must not be null or empty");
        }
        String scheme;
        String afterScheme;
        if (url.startsWith("mongodb://")) {
            scheme = "mongodb";
            afterScheme = url.substring("mongodb://".length());
        } else if (url.startsWith("mongodb+srv://")) {
            scheme = "mongodb+srv";
            afterScheme = url.substring("mongodb+srv://".length());
        } else {
            // Not the URL itself: one that was refused may carry a password
            // where the user should be, and an exception message ends up in
            // a log.
            throw new IllegalArgumentException(
                    "a MongoDB URL begins with mongodb:// or mongodb+srv://");
        }

        int question = afterScheme.indexOf('?');
        String authorityAndPath = question < 0 ? afterScheme : afterScheme.substring(0, question);
        String rawQuery = question < 0 ? "" : afterScheme.substring(question + 1);

        int firstSlash = authorityAndPath.indexOf('/');
        String authority = firstSlash < 0 ? authorityAndPath : authorityAndPath.substring(0, firstSlash);
        String dbPath = firstSlash < 0 ? "/" : authorityAndPath.substring(firstSlash);

        int at = authority.lastIndexOf('@');
        String rawUserInfo = at < 0 ? null : authority.substring(0, at);
        String hostsPart = at < 0 ? authority : authority.substring(at + 1);

        if (hostsPart.isEmpty()) {
            throw new IllegalArgumentException("a MongoDB URL names a host: mongodb://host:port?...");
        }

        if (rawUserInfo != null && rawUserInfo.contains(":")) {
            throw new IllegalArgumentException(
                    "a password in the URL is refused; use provider= and path= to keep the secret off the heap");
        }
        String userFromUri = rawUserInfo != null ? decode(rawUserInfo) : null;

        // Parse first host and port for record accessors
        String firstHostEntry = hostsPart.split(",")[0].trim();
        String firstHost;
        int firstPort = DEFAULT_PORT;
        if (firstHostEntry.startsWith("[")) {
            int closeBracket = firstHostEntry.indexOf(']');
            if (closeBracket > 0) {
                firstHost = firstHostEntry.substring(1, closeBracket);
                int colon = firstHostEntry.indexOf(':', closeBracket);
                if (colon > 0) {
                    firstPort = Integer.parseInt(firstHostEntry.substring(colon + 1));
                }
            } else {
                firstHost = firstHostEntry;
            }
        } else {
            int colon = firstHostEntry.lastIndexOf(':');
            if (colon > 0) {
                firstHost = firstHostEntry.substring(0, colon);
                firstPort = Integer.parseInt(firstHostEntry.substring(colon + 1));
            } else {
                firstHost = firstHostEntry;
            }
        }

        Map<String, String> allOptions = new LinkedHashMap<>();
        if (!rawQuery.isEmpty()) {
            for (String pair : rawQuery.split("&")) {
                if (pair.isEmpty()) {
                    continue;
                }
                int equals = pair.indexOf('=');
                if (equals > 0) {
                    allOptions.put(decode(pair.substring(0, equals)),
                            decode(pair.substring(equals + 1)));
                } else {
                    allOptions.put(decode(pair), "");
                }
            }
        }

        if (allOptions.containsKey("password") || allOptions.containsKey("secret")
                || allOptions.containsKey("value")) {
            throw new IllegalArgumentException(
                    "a password in the URL is refused; use provider= and path= to keep the secret off the heap");
        }

        String tlsVal = allOptions.get("tls");
        String sslVal = allOptions.get("ssl");
        if ("false".equalsIgnoreCase(tlsVal) || "false".equalsIgnoreCase(sslVal)) {
            throw new IllegalArgumentException(
                    "tls=false / ssl=false is refused; seclume-mongodb requires TLS");
        }

        String user = allOptions.get("user");
        if (user == null || user.isEmpty()) {
            user = userFromUri;
        }
        if (user == null || user.isEmpty()) {
            throw new IllegalArgumentException(
                    "a MongoDB URL requires a user name: mongodb://user@host/?... or ?user=...");
        }

        String authSource = allOptions.get("authSource");
        if (authSource == null || authSource.isEmpty()) {
            authSource = DEFAULT_AUTH_SOURCE;
        }

        String rootCert = allOptions.get(TrustChoice.ROOT_CERT);
        String pin = allOptions.get(TrustChoice.PIN);

        int connectTimeout = DEFAULT_CONNECT_TIMEOUT;
        if (allOptions.containsKey("connectTimeout")) {
            connectTimeout = Integer.parseInt(allOptions.get("connectTimeout"));
        } else if (allOptions.containsKey("connectTimeoutMS")) {
            connectTimeout = Integer.parseInt(allOptions.get("connectTimeoutMS"));
        }

        int timeout = 0;
        if (allOptions.containsKey("timeout")) {
            timeout = Integer.parseInt(allOptions.get("timeout"));
        } else if (allOptions.containsKey("socketTimeout")) {
            timeout = Integer.parseInt(allOptions.get("socketTimeout"));
        } else if (allOptions.containsKey("socketTimeoutMS")) {
            timeout = Integer.parseInt(allOptions.get("socketTimeoutMS"));
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

        // Separate seclume vs driver options
        Map<String, String> seclumeSettings = new LinkedHashMap<>();
        Map<String, String> driverOptions = new LinkedHashMap<>();

        for (Map.Entry<String, String> entry : allOptions.entrySet()) {
            String key = entry.getKey();
            String val = entry.getValue();
            String lower = key.toLowerCase(java.util.Locale.ROOT);

            boolean isSeclume = SECLUME_KEYS.contains(lower)
                    || lower.startsWith("key-")
                    || lower.startsWith("cipher-")
                    || lower.startsWith("token-")
                    || lower.startsWith("session-token-")
                    || key.equals(TrustChoice.ROOT_CERT)
                    || key.equals(TrustChoice.PIN);

            if (isSeclume) {
                seclumeSettings.put(key, val);
            } else {
                driverOptions.put(key, val);
            }
        }

        SecretProvider secret = SecretProviders.of(seclumeSettings);

        // Build clean connection string for driver
        StringBuilder sb = new StringBuilder(scheme).append("://").append(hostsPart).append(dbPath);
        if (!driverOptions.isEmpty()) {
            sb.append("?");
            boolean first = true;
            for (Map.Entry<String, String> entry : driverOptions.entrySet()) {
                if (!first) {
                    sb.append("&");
                }
                first = false;
                sb.append(encode(entry.getKey())).append("=").append(encode(entry.getValue()));
            }
        }
        String driverConnectionString = sb.toString();

        return new MongoUrl(firstHost, firstPort, user, authSource, trust, connectTimeout,
                timeout, secret, driverConnectionString);
    }

    private static String decode(String text) {
        return URLDecoder.decode(text, StandardCharsets.UTF_8);
    }

    private static String encode(String text) {
        return URLEncoder.encode(text, StandardCharsets.UTF_8);
    }
}
