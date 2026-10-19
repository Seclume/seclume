package space.seclume.ldap;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.function.Supplier;

import space.seclume.internal.Gssapi;
import space.seclume.internal.TrustChoice;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/**
 * {@code ldaps://host[:636][/base DN]?user=<bind DN>&provider=...} or
 * {@code ldap://host[:389][/base DN]?...} (upgraded with StartTLS before any
 * bind), with either a secret provider ({@code provider=...}) for a simple bind
 * or {@code authentication=kerberos} ({@code GSSAPI}) for an Active Directory /
 * Kerberos SASL bind, and optionally {@code tlsRootCert} or {@code tlsPin},
 * {@code connectTimeout} and {@code timeout} in milliseconds.
 */
final class LdapSettings {

    private static final Set<String> INLINE_SECRETS = Set.of(
            "password", "pass", "pwd", "secret", "token", "passphrase",
            "apikey", "api_key", "credential", "credentials");

    final String host;
    final int port;
    final boolean startTls;
    final boolean kerberos;
    final String serviceName;
    final String serverSpn;
    final String base;
    final String user;
    final String authorizationId;
    final TrustChoice.Choice trust;
    final int connectTimeout;
    final int timeout;
    final SecretProvider secret;
    final Supplier<Gssapi.Context> gssSupplier;

    private LdapSettings(String host, int port, boolean startTls, boolean kerberos,
                         String serviceName, String serverSpn, String base, String user,
                         String authorizationId, TrustChoice.Choice trust, int connectTimeout,
                         int timeout, SecretProvider secret,
                         Supplier<Gssapi.Context> gssSupplier) {
        this.host = host;
        this.port = port;
        this.startTls = startTls;
        this.kerberos = kerberos;
        this.serviceName = serviceName;
        this.serverSpn = serverSpn;
        this.base = base;
        this.user = user;
        this.authorizationId = authorizationId;
        this.trust = trust;
        this.connectTimeout = connectTimeout;
        this.timeout = timeout;
        this.secret = secret;
        this.gssSupplier = gssSupplier;
    }

    LdapSettings withGssSupplier(Supplier<Gssapi.Context> custom) {
        return new LdapSettings(host, port, startTls, kerberos, serviceName, serverSpn,
                base, user, authorizationId, trust, connectTimeout, timeout, secret, custom);
    }

    static LdapSettings of(String url) {
        URI uri = URI.create(url);
        String scheme = String.valueOf(uri.getScheme()).toLowerCase(Locale.ROOT);
        if (!scheme.equals("ldaps") && !scheme.equals("ldap")) {
            throw new IllegalArgumentException("an LDAP URL begins with ldaps:// or ldap:// "
                    + "(StartTLS), not " + uri.getScheme() + "://: the password is never sent in "
                    + "the clear");
        }
        boolean startTls = scheme.equals("ldap");
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
        String auth = options.remove("authentication");
        if (auth == null) {
            auth = options.remove("auth");
        } else {
            options.remove("auth");
        }
        boolean kerberos = false;
        if (auth != null) {
            String mode = auth.toLowerCase(Locale.ROOT);
            if (mode.equals("kerberos") || mode.equals("gssapi")) {
                kerberos = true;
            } else if (!mode.equals("simple")) {
                throw new IllegalArgumentException("authentication= is 'simple' or 'kerberos' "
                        + "(GSSAPI), not '" + auth + "'");
            }
        }
        String user = options.remove("user");
        String authzId = options.remove("authorizationId");
        if (user == null) {
            user = authzId;
        }
        if (!kerberos && (user == null || user.isBlank())) {
            throw new IllegalArgumentException("an LDAP URL needs user= - the bind DN, e.g. "
                    + "user=cn=app,ou=services,dc=example,dc=com, or app@example.com for "
                    + "Active Directory");
        }
        String authorizationId = user == null ? "" : user;
        if (kerberos && (user == null || user.isBlank())) {
            user = "GSSAPI";
        }
        String serviceName = options.remove("serviceName");
        if (serviceName == null) {
            serviceName = "ldap";
        } else if (serviceName.isBlank()) {
            throw new IllegalArgumentException("serviceName= cannot be blank: use e.g. "
                    + "serviceName=ldap");
        }
        String serverSpn = options.remove("serverSpn");
        if (serverSpn != null && serverSpn.isBlank()) {
            throw new IllegalArgumentException("serverSpn= cannot be blank: use e.g. "
                    + "serverSpn=ldap/ad.example.com");
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
        String host = uri.getHost();
        int defaultPort = startTls ? 389 : 636;
        int port = uri.getPort() >= 0 ? uri.getPort() : defaultPort;
        String path = uri.getRawPath();
        String base = path == null || path.length() <= 1 ? "" : decode(path.substring(1));
        if (kerberos) {
            if (options.containsKey("provider")) {
                throw new IllegalArgumentException("authentication=kerberos uses the operating "
                        + "system's Kerberos ticket and takes no provider=");
            }
            for (String key : options.keySet()) {
                if (INLINE_SECRETS.contains(key.toLowerCase(Locale.ROOT))) {
                    throw new IllegalArgumentException(key + "= in the URL is a secret on the "
                            + "heap; authentication=kerberos uses the operating system's ticket");
                }
                throw new IllegalArgumentException("unknown option '" + key
                        + "' for authentication=kerberos");
            }
            String spn = serverSpn;
            String svc = serviceName;
            Supplier<Gssapi.Context> gss = () -> spn != null
                    ? Gssapi.initiatePrincipal(spn)
                    : Gssapi.initiate(svc, host);
            return new LdapSettings(host, port, startTls, true, serviceName, serverSpn,
                    base, user, authorizationId, trust, connectTimeout, timeout, null, gss);
        }
        if (!options.containsKey("provider")) {
            throw new IllegalArgumentException("no secret named: add provider= and its options "
                    + "(provider=file&path=/run/secrets/ldap, provider=vault&...), or "
                    + "authentication=kerberos");
        }
        return new LdapSettings(host, port, startTls, false, serviceName, serverSpn,
                base, user, authorizationId, trust, connectTimeout, timeout,
                SecretProviders.of(options), null);
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
