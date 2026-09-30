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
 * Which mail server, over which protocol, and how to log in - read from one
 * URL, the way a seclume JDBC URL names its database:
 *
 * <pre>
 * smtp://mail.example.com:587?user=reports&amp;provider=file&amp;path=/run/secrets/smtp
 * imaps://outlook.office365.com?user=inbox@example.com&amp;auth=xoauth2
 *         &amp;provider=azure-managed-identity&amp;resource=https://outlook.office365.com
 * pop3s://pop.example.com?user=bounces&amp;provider=vault&amp;...
 * smtp://relay.internal:25?tls=none                      (a relay without login)
 * </pre>
 *
 * <ul>
 *   <li>The scheme is the protocol: {@code smtp}, {@code imap} and
 *       {@code pop3} upgrade with STARTTLS (STLS for POP3) and refuse a
 *       server that does not offer it; {@code smtps}, {@code imaps} and
 *       {@code pop3s} are TLS from the first byte. {@code tls=none} sends in
 *       the clear, and then there is no login at all - a credential is never
 *       sent unencrypted. A mailbox cannot be read without a login, so for
 *       IMAP and POP3 that leaves nothing to do;
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
final class MailSettings {

    /** Which login, if any. LOGIN is the protocol's own password login. */
    enum Auth { NONE, PLAIN, LOGIN, XOAUTH2, BEST }

    /** The three protocols and their ports - with STARTTLS, and with TLS from the start. */
    enum Protocol {
        SMTP(587, 465), IMAP(143, 993), POP3(110, 995);

        final int plainPort;
        final int tlsPort;

        Protocol(int plainPort, int tlsPort) {
            this.plainPort = plainPort;
            this.tlsPort = tlsPort;
        }

        /** {@code smtp} or {@code smtps}, and so on - as the URL and Jakarta Mail name it. */
        String scheme(boolean implicitTls) {
            return name().toLowerCase(Locale.ROOT) + (implicitTls ? "s" : "");
        }
    }

    final Protocol protocol;
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

    private MailSettings(Protocol protocol, String host, int port, boolean implicitTls, boolean startTls, String user,
                         Auth auth, TrustChoice.Choice trust, int connectTimeout, int timeout,
                         String ehloName, SecretProvider secret) {
        this.protocol = protocol;
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

    static MailSettings of(String url) {
        URI uri = URI.create(url);
        String scheme = String.valueOf(uri.getScheme()).toLowerCase(Locale.ROOT);
        boolean implicitTls = scheme.endsWith("s");
        Protocol protocol = switch (implicitTls ? scheme.substring(0, scheme.length() - 1)
                : scheme) {
            case "smtp" -> Protocol.SMTP;
            case "imap" -> Protocol.IMAP;
            case "pop3" -> Protocol.POP3;
            default -> throw new IllegalArgumentException("a mail URL begins with smtp://, "
                    + "smtps://, imap://, imaps://, pop3:// or pop3s://, not "
                    + uri.getScheme() + "://");
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
        if (user != null && (user.indexOf('\r') >= 0 || user.indexOf('\n') >= 0
                || user.indexOf('\0') >= 0)) {
            // It goes into command lines (USER, LOGIN, EHLO's neighbours) as it is;
            // a line break in it would end the command and start another.
            throw new IllegalArgumentException("the user name holds a line break or NUL");
        }
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
                        throw new IllegalArgumentException(scheme + ":// is TLS from the "
                                + "start; tls=starttls belongs to " + protocol.scheme(false)
                                + "://");
                    }
                }
                case "none" -> {
                    if (implicitTls) {
                        throw new IllegalArgumentException(scheme + ":// cannot be tls=none");
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
        if (protocol != Protocol.SMTP && auth == Auth.NONE) {
            throw new IllegalArgumentException("a mailbox is read with a login: " + scheme
                    + ":// needs user= and a secret provider");
        }
        if (auth != Auth.NONE && !encrypted) {
            throw new IllegalArgumentException("tls=none sends in the clear, and a credential "
                    + "is never sent that way - use STARTTLS or " + protocol.scheme(true)
                    + "://, or no login");
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
        int port = uri.getPort() >= 0 ? uri.getPort()
                : implicitTls ? protocol.tlsPort : protocol.plainPort;
        return new MailSettings(protocol, uri.getHost(), port, implicitTls, startTls, user, auth, trust,
                connectTimeout, timeout, ehlo != null ? ehlo : localName(), secret);
    }

    /**
     * The name for EHLO: this host's, or its address literal when it has none.
     *
     * <p>Found once per JVM and kept. {@code getCanonicalHostName} is a reverse
     * DNS lookup, the JDK does not keep its answer, and where nothing answers
     * it waits for the resolver's timeout - 4.5 s on a Windows machine without
     * a PTR record, for every {@code SeclumeMail.of} that named no EHLO. The
     * host's name does not change while the process runs.
     */
    private static String localName() {
        return LocalName.EHLO;
    }

    /**
     * This host's canonical name as {@code InetAddress} gives it - what
     * Jakarta Mail would look up itself for a default sender and a
     * Message-ID, and does not keep either; null when there is none.
     */
    static String canonicalHostName() {
        return LocalName.CANONICAL;
    }

    private static final class LocalName {
        static final InetAddress LOCAL = local();
        static final String CANONICAL = LOCAL == null ? null : LOCAL.getCanonicalHostName();
        static final String EHLO = ehlo();

        private static InetAddress local() {
            try {
                return InetAddress.getLocalHost();
            } catch (UnknownHostException e) {
                return null;
            }
        }

        private static String ehlo() {
            if (LOCAL == null) {
                return "[127.0.0.1]";
            }
            if (CANONICAL.contains(".") && !CANONICAL.equals(LOCAL.getHostAddress())) {
                return CANONICAL;
            }
            return LOCAL instanceof java.net.Inet6Address
                    ? "[IPv6:" + LOCAL.getHostAddress() + "]"
                    : "[" + LOCAL.getHostAddress() + "]";
        }
    }

    /** {@code imaps} and so on - the scheme this was read from. */
    String scheme() {
        return protocol.scheme(implicitTls);
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
        return scheme() + "://" + host + ":" + port
                + (user == null ? "" : " as " + user);
    }
}
