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
 * {@code connectTimeout} and {@code timeout} in milliseconds, {@code transport}
 * (what carries the connection, as for the JDBC drivers), a client certificate
 * ({@code clientCert} and {@code clientKey-provider}, as for the JDBC drivers)
 * - and the rest
 * the secret provider's settings.
 *
 * <p>A password in the URL is strictly refused, keeping the secret off the
 * heap from the outset.
 */
public record MongoUrl(String host, int port, String user, String authSource,
                TrustChoice.Choice trust, int connectTimeout, int timeout,
                SecretProvider secret, String driverConnectionString, String transport,
                space.seclume.tls.ClientIdentity identity, String mechanism,
                space.seclume.mongodb.internal.MongoAws.Credentials aws) {

    /** The login seclume's own driver does by default; X.509 when authMechanism says so. */
    public static final String SCRAM_SHA_256 = "SCRAM-SHA-256";
    public static final String X509 = "MONGODB-X509";
    public static final String AWS = "MONGODB-AWS";
    public static final String OIDC = "MONGODB-OIDC";

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
            "connecttimeout", "timeout", "sockettimeout", "transport"
    );

    /**
     * Parses a URL; public for seclume's own MongoDB driver, which takes the
     * same URLs.
     */
    public static MongoUrl parse(String url) {
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

        String mechanism = allOptions.getOrDefault("authMechanism", SCRAM_SHA_256)
                .toUpperCase(java.util.Locale.ROOT);
        String user = allOptions.get("user");
        if (user == null || user.isEmpty()) {
            user = userFromUri;
        }
        if ((user == null || user.isEmpty()) && !mechanism.equals(X509)
                && !mechanism.equals(AWS) && !mechanism.equals(OIDC)) {
            throw new IllegalArgumentException(
                    "a MongoDB URL requires a user name: mongodb://user@host/?... or ?user=...");
        }

        String authSource = allOptions.get("authSource");
        if (authSource == null || authSource.isEmpty()) {
            // X.509 users live in $external; the others in admin unless said otherwise.
            authSource = mechanism.equals(X509) || mechanism.equals(AWS)
                    || mechanism.equals(OIDC) ? "$external" : DEFAULT_AUTH_SOURCE;
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
                    || lower.startsWith("clientcert") || lower.startsWith("clientkey-")
                    || lower.equals("authmechanism")
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

        space.seclume.tls.ClientIdentity identity = space.seclume.tls.ClientIdentities.of(
                identitySettings(seclumeSettings));
        if (mechanism.equals(X509) && identity == null) {
            throw new IllegalArgumentException("authMechanism=MONGODB-X509 needs a client "
                    + "certificate: clientCert and clientKey-provider (or a certificate store)");
        }
        space.seclume.mongodb.internal.MongoAws.Credentials aws = mechanism.equals(AWS)
                ? awsCredentials(seclumeSettings) : null;
        SecretProvider secret = mechanism.equals(X509) || mechanism.equals(AWS) ? null
                : mechanism.equals(OIDC) ? oidcToken(seclumeSettings,
                        allOptions.get("authMechanismProperties"), user)
                : SecretProviders.of(withoutIdentity(seclumeSettings));

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

        String transport = allOptions.get("transport");
        return new MongoUrl(firstHost, firstPort, user, authSource, trust, connectTimeout,
                timeout, secret, driverConnectionString, transport, identity, mechanism, aws);
    }

    /**
     * The AWS credentials of a MONGODB-AWS login, named as for rds-iam: the
     * workload's role ({@code credentials=instance|container|web-identity}),
     * or {@code access-key-id} with the secret key's provider under
     * {@code key-} and an optional session token's under {@code session-token-}.
     */
    private static space.seclume.mongodb.internal.MongoAws.Credentials awsCredentials(
            Map<String, String> settings) {
        space.seclume.secret.AwsInstanceRole role = space.seclume.secret.AwsInstanceRole.of(
                settings);
        if (role != null) {
            return new space.seclume.mongodb.internal.MongoAws.Credentials(role, null, null,
                    null);
        }
        String accessKeyId = settings.get("access-key-id");
        Map<String, String> key = prefixed(settings, "key-");
        if (accessKeyId == null || key.isEmpty()) {
            throw new IllegalArgumentException("authMechanism=MONGODB-AWS needs credentials: "
                    + "credentials=instance|container|web-identity, or access-key-id and "
                    + "key-provider (with session-token-provider for temporary ones)");
        }
        Map<String, String> token = prefixed(settings, "session-token-");
        return new space.seclume.mongodb.internal.MongoAws.Credentials(null, accessKeyId,
                SecretProviders.of(key), token.isEmpty() ? null : SecretProviders.of(token));
    }

    /**
     * Where a MONGODB-OIDC token comes from: any provider under {@code token-}
     * (a file, a socket, a vault), or the workload's own identity as the
     * driver specification names it - {@code ENVIRONMENT:k8s} for the service
     * account's token file, {@code ENVIRONMENT:azure} for the managed
     * identity's token from IMDS (the user, if any, is its client id),
     * {@code ENVIRONMENT:gcp} for the service account's identity token from the
     * metadata server; both of the last need {@code TOKEN_RESOURCE}. The
     * metadata answers are read from the socket into native memory
     * ({@code azure-managed-identity}, {@code gcp-metadata}), never a String.
     */
    private static SecretProvider oidcToken(Map<String, String> settings, String properties,
                                            String user) {
        Map<String, String> token = prefixed(settings, "token-");
        String environment = null;
        String resource = null;
        if (properties != null) {
            for (String pair : properties.split(",")) {
                // The first colon only: a TOKEN_RESOURCE is often api://... itself.
                int colon = pair.indexOf(':');
                if (colon <= 0) {
                    continue;
                }
                String key = pair.substring(0, colon).trim();
                String value = pair.substring(colon + 1).trim();
                if (key.equalsIgnoreCase("ENVIRONMENT")) {
                    environment = value.toLowerCase(java.util.Locale.ROOT);
                } else if (key.equalsIgnoreCase("TOKEN_RESOURCE")) {
                    resource = value;           // decoded with the URL's other options
                }
            }
        }
        // A JWT is often a kilobyte or more; the providers' default of 256 bytes is for
        // passwords.
        token.putIfAbsent("max-length", "16384");
        if (token.size() > 1) {
            return SecretProviders.of(token);
        }
        if ("k8s".equals(environment)) {
            String file = System.getenv("AZURE_FEDERATED_TOKEN_FILE"); // seclume-allow: a file path - the token is in the file
            if (file == null) {
                file = System.getenv("AWS_WEB_IDENTITY_TOKEN_FILE"); // seclume-allow: a file path - the token is in the file
            }
            if (file == null) {
                file = space.seclume.mongodb.internal.MongoOidc.KUBERNETES_TOKEN;
            }
            return SecretProviders.of(Map.of("provider", "file", "path", file,
                    "max-length", "16384"));
        }
        if ("azure".equals(environment) || "gcp".equals(environment)) {
            if (resource == null || resource.isEmpty()) {
                throw new IllegalArgumentException("ENVIRONMENT:" + environment + " needs "
                        + "TOKEN_RESOURCE in authMechanismProperties - the audience the token "
                        + "is issued for, as the cluster's OIDC configuration names it");
            }
            Map<String, String> metadata = new LinkedHashMap<>();
            if (environment.equals("azure")) {
                metadata.put("provider", "azure-managed-identity");
                metadata.put("resource", resource);
                if (user != null && !user.isEmpty()) {
                    metadata.put("client-id", user);
                }
            } else {
                if (user != null && !user.isEmpty()) {
                    throw new IllegalArgumentException("ENVIRONMENT:gcp takes no user: the "
                            + "metadata server's default service account is the identity");
                }
                metadata.put("provider", "gcp-metadata");
                metadata.put("audience", resource);
            }
            metadata.put("max-length", "16384");
            return SecretProviders.of(metadata);
        }
        if (environment != null) {
            throw new IllegalArgumentException("ENVIRONMENT:" + environment + " is not one "
                    + "seclume knows for MONGODB-OIDC: k8s, azure or gcp - or name the token's "
                    + "source with token-provider");
        }
        throw new IllegalArgumentException("authMechanism=MONGODB-OIDC needs a token: "
                + "token-provider (e.g. token-provider=file&token-path=...) or "
                + "authMechanismProperties=ENVIRONMENT:k8s, azure or gcp");
    }

    private static Map<String, String> prefixed(Map<String, String> settings, String prefix) {
        Map<String, String> nested = new LinkedHashMap<>();
        settings.forEach((name, value) -> {
            if (name.startsWith(prefix)) {
                nested.put(name.substring(prefix.length()), value);
            }
        });
        return nested;
    }

    /** The settings that describe a client certificate, for ClientIdentities. */
    private static Map<String, String> identitySettings(Map<String, String> settings) {
        Map<String, String> identity = new LinkedHashMap<>();
        settings.forEach((key, value) -> {
            if (key.startsWith("clientCert") || key.startsWith("clientKey-")) {
                identity.put(key, value);
            }
        });
        return identity;
    }

    /** The rest, for the password's provider. */
    private static Map<String, String> withoutIdentity(Map<String, String> settings) {
        Map<String, String> rest = new LinkedHashMap<>(settings);
        rest.keySet().removeIf(key -> key.startsWith("clientCert") || key.startsWith("clientKey-")
                || key.equalsIgnoreCase("authMechanism"));
        return rest;
    }

    private static String decode(String text) {
        return URLDecoder.decode(text, StandardCharsets.UTF_8);
    }

    private static String encode(String text) {
        return URLEncoder.encode(text, StandardCharsets.UTF_8);
    }
}
