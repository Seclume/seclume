package space.seclume.mail;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
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
 * Where to submit mail and how to log in - read from one URL, the way a
 * seclume JDBC URL names its database:
 *
 * <pre>
 * smtp://mail.example.com:587?user=reports&amp;provider=file&amp;path=/run/secrets/smtp
 * smtps://smtp.office365.com:465?user=reports@example.com&amp;auth=xoauth2
 *         &amp;provider=azure-managed-identity&amp;resource=https://outlook.office365.com
 * smtp://relay.internal:25?tls=none                      (a relay without login)
 * </pre>
 *
 * <ul>
 *   <li>{@code smtp://} upgrades with STARTTLS and refuses a server that does
 *       not offer it; {@code tls=none} sends in the clear, and then there is
 *       no login at all - a credential is never sent unencrypted;
 *   <li>{@code smtps://} is TLS from the first byte (port 465);
 *   <li>{@code user} is the login name, {@code auth} one of {@code plain},
 *       {@code login} or {@code xoauth2} - left out, it is PLAIN where the
 *       server offers it and LOGIN otherwise; XOAUTH2 is only ever chosen by
 *       name, because its secret is a token, not a password;
 *   <li>{@code tlsRootCert} or {@code tlsPin} for a CA the JVM does not know,
 *       {@code connectTimeout} and {@code timeout} in milliseconds,
 *       {@code ehlo} for the name this client gives in EHLO;
 *   <li>everything else is the secret provider's, as in a JDBC URL. A
 *       password in the URL is refused.
 * </ul>
 */
final class SmtpSettings {

    /** Which login, if any. */
    enum Auth { NONE, PLAIN, LOGIN, XOAUTH2, BEST }

    final String host;
    final int port;
    final boolean implicitTls;
    final boolean startTls;
    final String user;
    final Auth auth;
    final TrustChoice.Choice trust;
    final int connectTimeout;
    final int timeout;
    final String ehloName;
    final SecretProvider secret;

    private SmtpSettings(String host, int port, boolean implicitTls, boolean startTls, String user,
                         Auth auth, TrustChoice.Choice trust, int connectTimeout, int timeout,
                         String ehloName, SecretProvider secret) {
        this.host = host;
        this.port = port;
        this.implicitTls = implicitTls;
        this.startTls = startTls;
        this.user = user;
        this.auth = auth;
        this.trust = trust;
        this.connectTimeout = connectTimeout;
        this.timeout = timeout;
        this.ehloName = ehloName;
        this.secret = secret;
    }

    static SmtpSettings of(String url) {
        URI uri = URI.create(url);
        boolean implicitTls = switch (String.valueOf(uri.getScheme()).toLowerCase(Locale.ROOT)) {
            case "smtp" -> false;
            case "smtps" -> true;
            default -> throw new IllegalArgumentException(
                    "a mail URL begins with smtp:// or smtps://, not " + uri.getScheme() + "://");
        };
        if (uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("a user or password in front of the host is not "
                    + "taken: the password would be a String for the life of the application. "
                    + "Name the user with user= and the secret with provider= and path=");
        }
        if (uri.getHost() == null) {
            throw new IllegalArgumentException("no host in the mail URL");
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
        String user = options.remove("user");
        String authName = options.remove("auth");
        String tlsMode = options.remove("tls");
        String rootCert = options.remove(TrustChoice.ROOT_CERT);
        String pin = options.remove(TrustChoice.PIN);
        int connectTimeout = Integer.parseInt(remove(options, "connectTimeout", "10000"));
        int timeout = Integer.parseInt(remove(options, "timeout", "60000"));
        String ehlo = options.remove("ehlo");

        boolean startTls = !implicitTls;
        if (tlsMode != null) {
            switch (tlsMode.toLowerCase(Locale.ROOT)) {
                case "starttls" -> {
                    if (implicitTls) {
                        throw new IllegalArgumentException("smtps:// is TLS from the start; "
                                + "tls=starttls belongs to smtp://");
                    }
                }
                case "none" -> {
                    if (implicitTls) {
                        throw new IllegalArgumentException("smtps:// cannot be tls=none");
                    }
                    startTls = false;
                }
                default -> throw new IllegalArgumentException(
                        "tls is starttls or none, not '" + tlsMode + "'");
            }
        }
        boolean encrypted = implicitTls || startTls;

        Auth auth;
        if (authName == null) {
            auth = user == null ? Auth.NONE : Auth.BEST;
        } else {
            auth = switch (authName.toLowerCase(Locale.ROOT)) {
                case "none" -> Auth.NONE;
                case "plain" -> Auth.PLAIN;
                case "login" -> Auth.LOGIN;
                case "xoauth2" -> Auth.XOAUTH2;
                default -> throw new IllegalArgumentException(
                        "auth is plain, login, xoauth2 or none, not '" + authName + "'");
            };
        }
        if (auth != Auth.NONE && user == null) {
            throw new IllegalArgumentException("auth=" + authName + " needs user=");
        }
        if (auth != Auth.NONE && !encrypted) {
            throw new IllegalArgumentException("tls=none sends in the clear, and a credential "
                    + "is never sent that way - use STARTTLS or smtps://, or no login");
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
        SecretProvider secret = auth == Auth.NONE ? null : SecretProviders.of(options);
        int port = uri.getPort() >= 0 ? uri.getPort() : implicitTls ? 465 : 587;
        return new SmtpSettings(uri.getHost(), port, implicitTls, startTls, user, auth, trust,
                connectTimeout, timeout, ehlo != null ? ehlo : localName(), secret);
    }

    /** The name for EHLO: this host's, or its address literal when it has none. */
    private static String localName() {
        try {
            InetAddress local = InetAddress.getLocalHost();
            String name = local.getCanonicalHostName();
            if (name.contains(".") && !name.equals(local.getHostAddress())) {
                return name;
            }
            return local instanceof java.net.Inet6Address
                    ? "[IPv6:" + local.getHostAddress() + "]"
                    : "[" + local.getHostAddress() + "]";
        } catch (UnknownHostException e) {
            return "[127.0.0.1]";
        }
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
        return (implicitTls ? "smtps://" : "smtp://") + host + ":" + port
                + (user == null ? "" : " as " + user);
    }
}
