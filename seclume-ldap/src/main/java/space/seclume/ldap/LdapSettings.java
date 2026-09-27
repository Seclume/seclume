package space.seclume.ldap;

import java.net.URI;
import java.net.URLDecoder;
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
 * {@code ldaps://host[:636][/base DN]?user=<bind DN>&provider=...}, and
 * optionally {@code tlsRootCert} or {@code tlsPin}, {@code connectTimeout}
 * and {@code timeout} in milliseconds.
 */
final class LdapSettings {

    final String host;
    final int port;
    final String base;
    final String user;
    final TrustChoice.Choice trust;
    final int connectTimeout;
    final int timeout;
    final SecretProvider secret;

    private LdapSettings(String host, int port, String base, String user,
                         TrustChoice.Choice trust, int connectTimeout, int timeout,
                         SecretProvider secret) {
        this.host = host;
        this.port = port;
        this.base = base;
        this.user = user;
        this.trust = trust;
        this.connectTimeout = connectTimeout;
        this.timeout = timeout;
        this.secret = secret;
    }

    static LdapSettings of(String url) {
        URI uri = URI.create(url);
        String scheme = String.valueOf(uri.getScheme()).toLowerCase(Locale.ROOT);
        if (!scheme.equals("ldaps")) {
            throw new IllegalArgumentException("an LDAP URL begins with ldaps://, not "
                    + uri.getScheme() + "://: the password is never sent in the clear (StartTLS "
                    + "on ldap:// is not supported)");
        }
        if (uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("a user or password in front of the host is not "
                    + "taken; name the bind DN with user= and the secret with provider=");
        }
        if (uri.getHost() == null) {
            throw new IllegalArgumentException("no host in the LDAP URL");
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
        if (user == null || user.isBlank()) {
            throw new IllegalArgumentException("an LDAP URL needs user= - the bind DN, e.g. "
                    + "user=cn=app,ou=services,dc=example,dc=com, or app@example.com for "
                    + "Active Directory");
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
                    + "(provider=file&path=/run/secrets/ldap, provider=vault&...)");
        }
        String path = uri.getRawPath();
        String base = path == null || path.length() <= 1 ? "" : decode(path.substring(1));
        return new LdapSettings(uri.getHost(), uri.getPort() >= 0 ? uri.getPort() : 636, base,
                user, trust, connectTimeout, timeout, SecretProviders.of(options));
    }

    /** Percent-decoding that leaves a {@code +} alone - DNs have them. */
    private static String decode(String text) {
        return URLDecoder.decode(text.replace("+", "%2B"), StandardCharsets.UTF_8);
    }

    private static int number(String text, int otherwise, String name) {
        if (text == null) {
            return otherwise;
        }
        try {
            int value = Integer.parseInt(text);
            if (value >= 0) {
                return value;
            }
        } catch (NumberFormatException e) {
            // said below
        }
        throw new IllegalArgumentException(name + " is a number of 0 or more, not '" + text
                + "'");
    }

    String authority() {
        return (host.indexOf(':') >= 0 ? "[" + host + "]" : host) + ":" + port;
    }
}
