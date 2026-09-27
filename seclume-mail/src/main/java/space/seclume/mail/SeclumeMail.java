package space.seclume.mail;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

import jakarta.mail.AuthenticationFailedException;
import jakarta.mail.MessagingException;
import jakarta.mail.NoSuchProviderException;
import jakarta.mail.Provider;
import jakarta.mail.Session;
import jakarta.mail.Store;

/**
 * Mail with the password or the OAuth token off the heap - sending over SMTP,
 * reading over IMAP and POP3.
 *
 * <p><b>With Jakarta Mail</b> - and so with Spring's {@code JavaMailSender},
 * Spring Integration's mail adapters and Camel - a session made here is all
 * there is to it. In it, {@code smtp}, {@code imap} and {@code pop3} (and
 * {@code smtps}, {@code imaps}, {@code pop3s}) are served by seclume, under
 * their usual names; outside it nothing changes.
 *
 * <pre>
 * Session session = SeclumeMail.session(
 *         "smtps://mail.example.com?user=reports&amp;provider=file&amp;path=/run/secrets/mail",
 *         "imaps://mail.example.com?user=reports&amp;provider=file&amp;path=/run/secrets/mail");
 *
 * Transport.send(message);                        // over smtps
 * Store inbox = session.getStore();               // imaps
 * inbox.connect();                                // no user, no password
 *
 * sender.setSession(session);                     // Spring's JavaMailSenderImpl
 * </pre>
 *
 * <p><b>On its own</b>, for sending without Jakarta Mail in between:
 *
 * <pre>
 * SeclumeMail smtp = SeclumeMail.of("smtp://mail.example.com:587?user=...&amp;provider=...");
 * smtp.send("reports@example.com", List.of("team@example.com"), out -&gt; out.write(mime));
 * </pre>
 *
 * <p><b>The URL.</b> The scheme is the protocol: {@code smtp://host:587},
 * {@code imap://host:143} and {@code pop3://host:110} upgrade with STARTTLS and
 * refuse a server without it; {@code smtps://} (465), {@code imaps://} (993) and
 * {@code pop3s://} (995) are TLS from the first byte. {@code user=} is the
 * login and {@code auth=plain|login|xoauth2} the mechanism - left out, PLAIN
 * where the server offers it and the protocol's own login otherwise; XOAUTH2
 * (Microsoft 365, Google) only by name. {@code tls=none} sends in the clear and
 * then never logs in, which only a relay for sending can use.
 * {@code tlsRootCert=} or {@code tlsPin=} for a CA the JVM does not know;
 * {@code connectTimeout=}, {@code timeout=} (ms) and, for SMTP, {@code ehlo=}.
 * Everything else is the secret provider's - the same options a seclume JDBC
 * URL takes. A password in the URL is refused.
 *
 * <p><b>What stays off the heap:</b> the credential, from the provider to the
 * encrypted record on the wire - for all three protocols, and for Jakarta
 * Mail, which is given a placeholder where it insists on a password and a
 * connection seclume has already logged in. <b>What does not:</b> the mail.
 * Subjects, addresses and bodies are the application's data, sent and read as
 * Jakarta Mail always has. This is the line the JDBC drivers draw too: the
 * password is not a {@code String}, the rows are.
 */
public final class SeclumeMail {

    /**
     * What Jakarta Mail is given where it will not connect without a password.
     * Not a secret, and never sent: IMAP skips its login after PREAUTH, and
     * POP3's USER and PASS are answered before they reach the server.
     */
    static final String PLACEHOLDER = "seclume-logs-in-itself";

    private static final String SETTINGS = "space.seclume.mail.settings.";

    private final MailSettings settings;

    private SeclumeMail(MailSettings settings) {
        this.settings = settings;
    }

    /** One server: {@code smtp(s)://}, {@code imap(s)://} or {@code pop3(s)://} - see the class comment. */
    public static SeclumeMail of(String url) {
        return new SeclumeMail(MailSettings.of(url));
    }

    /** An SMTP session - connected, encrypted and logged in - for as many messages as needed. */
    public SmtpConnection open() throws IOException {
        requireSmtp("open a sending session");
        return SmtpConnection.open(settings);
    }

    /** One message over SMTP, in a session of its own. */
    public SmtpConnection.Sent send(String from, List<String> recipients,
                                    SmtpConnection.MessageWriter message) throws IOException {
        requireSmtp("send");
        try (SmtpConnection session = open()) {
            return session.send(from, recipients, message);
        }
    }

    /**
     * An IMAP or POP3 store, connected and logged in - Jakarta Mail's, in a
     * session of its own. Close it when done.
     */
    public Store store() throws MessagingException {
        if (settings.protocol == MailSettings.Protocol.SMTP) {
            throw new IllegalStateException(settings.scheme() + ":// sends; a store reads "
                    + "over imap(s):// or pop3(s)://");
        }
        Store store = session(new Properties(), List.of(settings)).getStore(settings.scheme());
        store.connect();
        return store;
    }

    /**
     * A Jakarta Mail session in which the protocols of these URLs are served by
     * seclume - one URL per protocol, so one for sending and one or two for
     * reading. The first sending URL becomes the default transport and the
     * first reading one the default store.
     */
    public static Session session(String... urls) {
        return session(new Properties(), urls);
    }

    /** The same, on top of properties of the caller's - {@code mail.debug}, timeouts of its own. */
    public static Session session(Properties base, String... urls) {
        if (urls.length == 0) {
            throw new IllegalArgumentException("a mail session needs at least one URL");
        }
        return session(base, java.util.Arrays.stream(urls).map(MailSettings::of).toList());
    }

    private static Session session(Properties base, List<MailSettings> all) {
        Properties props = new Properties();
        props.putAll(base);
        boolean transport = false;
        boolean store = false;
        for (MailSettings settings : all) {
            String name = settings.scheme();
            if (props.get(SETTINGS + name) != null) {
                throw new IllegalArgumentException("two URLs for " + name + "://; a session "
                        + "has one server per protocol");
            }
            props.put(SETTINGS + name, settings);
            String prefix = "mail." + name;
            props.setProperty(prefix + ".host", settings.host);
            props.setProperty(prefix + ".port", Integer.toString(settings.port));
            if (settings.user != null) {
                props.setProperty(prefix + ".user", settings.user);
            }
            if (settings.protocol == MailSettings.Protocol.SMTP) {
                if (!transport) {
                    props.setProperty("mail.transport.protocol", name);
                    props.setProperty("mail.transport.protocol.rfc822", name);
                    transport = true;
                }
                continue;
            }
            if (!store) {
                props.setProperty("mail.store.protocol", name);
                store = true;
            }
            // The socket is seclume's and logs in before Angus reads from it;
            // Angus's own TLS, STARTTLS and SASL stay off.
            props.put(prefix + ".socketFactory", MailSocket.factory(settings));
            props.setProperty(prefix + ".socketFactory.fallback", "false");
            props.setProperty(prefix + ".ssl.enable", "false");
            props.setProperty(prefix + ".starttls.enable", "false");
            props.setProperty(prefix + ".starttls.required", "false");
            props.setProperty(prefix + ".sasl.enable", "false");
            if (settings.protocol == MailSettings.Protocol.POP3) {
                // USER and PASS, and nothing else before them: those two are
                // answered by the socket (see MailSocket).
                props.setProperty(prefix + ".disablecapa", "true");
                props.setProperty(prefix + ".apop.enable", "false");
                props.setProperty(prefix + ".auth.mechanisms", "LOGIN");
            }
        }
        Session session = Session.getInstance(props);
        try {
            for (MailSettings settings : all) {
                String name = settings.scheme();
                if (settings.protocol == MailSettings.Protocol.SMTP) {
                    session.setProvider(new Provider(Provider.Type.TRANSPORT, name,
                            SeclumeTransport.class.getName(), "seclume", null));
                } else {
                    session.setProvider(new Provider(Provider.Type.STORE, name,
                            (settings.protocol == MailSettings.Protocol.IMAP
                                    ? SeclumeImapStore.class : SeclumePop3Store.class).getName(),
                            "seclume", null));
                }
            }
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Jakarta Mail refused a provider: " + e.getMessage(), e);
        }
        return session;
    }

    /** The URL this session was made with for {@code protocol} - for the transport and the stores. */
    static MailSettings settings(Session session, String protocol) throws MessagingException {
        Object settings = session.getProperties().get(SETTINGS + protocol.toLowerCase(Locale.ROOT));
        if (!(settings instanceof MailSettings mail)) {
            throw new MessagingException("this session has no seclume URL for " + protocol
                    + "://; make it with SeclumeMail.session(...)");
        }
        return mail;
    }

    /** A password handed to Jakarta Mail is a String for good; it is not taken. */
    static void refusePassword(String password) throws AuthenticationFailedException {
        if (password != null && !password.isEmpty() && !password.equals(PLACEHOLDER)) {
            throw new AuthenticationFailedException("seclume-mail takes no password from "
                    + "Jakarta Mail: it is a String in the Session for as long as the "
                    + "application runs. Name the secret in the URL (provider=...)");
        }
    }

    private void requireSmtp(String what) {
        if (settings.protocol != MailSettings.Protocol.SMTP) {
            throw new IllegalStateException("cannot " + what + " over " + settings.scheme()
                    + "://; that takes smtp(s)://");
        }
    }

    @Override
    public String toString() {
        return "SeclumeMail[" + settings + "]";
    }
}
