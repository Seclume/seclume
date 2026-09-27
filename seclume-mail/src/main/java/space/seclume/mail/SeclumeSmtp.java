package space.seclume.mail;

import java.io.IOException;
import java.util.List;

/**
 * Mail submission with the password or the OAuth token off the heap.
 *
 * <pre>
 * SeclumeSmtp smtp = SeclumeSmtp.of(
 *         "smtp://mail.example.com:587?user=reports&amp;provider=file&amp;path=/run/secrets/smtp");
 * smtp.send("reports@example.com", List.of("team@example.com"), out -&gt; out.write(message));
 *
 * try (SmtpConnection session = smtp.open()) {      // several messages, one login
 *     for (Report report : reports) {
 *         session.send(from, report.recipients(), report::writeMime);
 *     }
 * }
 * </pre>
 *
 * <p><b>The URL.</b> {@code smtp://host:587} upgrades with STARTTLS and refuses
 * a server without it; {@code smtps://host:465} is TLS from the first byte.
 * {@code user=} is the login, {@code auth=plain|login|xoauth2} the mechanism
 * (left out: PLAIN, else LOGIN; XOAUTH2 only by name). {@code tls=none} sends
 * in the clear and then never logs in. {@code tlsRootCert=} or {@code tlsPin=}
 * for a CA the JVM does not know; {@code connectTimeout=}, {@code timeout=}
 * (ms) and {@code ehlo=}. Everything else is the secret provider's - the same
 * options a seclume JDBC URL takes. A password in the URL is refused.
 *
 * <p>With Jakarta Mail - and so with Spring's {@code JavaMailSenderImpl} - the
 * same URL goes into the session as {@code mail.seclume-smtp.url} and the
 * protocol is {@code seclume-smtp}; see {@link SeclumeSmtpTransport}.
 *
 * <p><b>What stays off the heap:</b> the credential, from the provider to the
 * encrypted record on the wire. <b>What does not:</b> the message. Its
 * subject, its recipients and its body are the application's data, made by the
 * application - usually from a template - long before they get here. This is
 * the same line the JDBC drivers draw: the password is not a {@code String},
 * the rows are.
 */
public final class SeclumeSmtp {

    private final SmtpSettings settings;

    private SeclumeSmtp(SmtpSettings settings) {
        this.settings = settings;
    }

    /** From an {@code smtp://} or {@code smtps://} URL - see the class comment. */
    public static SeclumeSmtp of(String url) {
        return new SeclumeSmtp(SmtpSettings.of(url));
    }

    /** A session - connected, encrypted and logged in - for as many messages as needed. */
    public SmtpConnection open() throws IOException {
        return SmtpConnection.open(settings);
    }

    /** One message in a session of its own. */
    public SmtpConnection.Sent send(String from, List<String> recipients,
                                    SmtpConnection.MessageWriter message) throws IOException {
        try (SmtpConnection session = open()) {
            return session.send(from, recipients, message);
        }
    }

    @Override
    public String toString() {
        return "SeclumeSmtp[" + settings + "]";
    }
}
