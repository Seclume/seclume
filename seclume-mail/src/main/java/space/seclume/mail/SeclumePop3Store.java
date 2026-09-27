package space.seclume.mail;

import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.URLName;

import org.eclipse.angus.mail.pop3.POP3Store;

/**
 * Reading over POP3, as Jakarta Mail sees it: Angus Mail's {@link POP3Store},
 * behind {@code pop3} and {@code pop3s} in a session made by
 * {@link SeclumeMail#session} - with the login taken out of its hands.
 *
 * <p>Its socket factory is {@link MailSocket}'s, which connects, encrypts and
 * logs in before Angus reads a byte. POP3 has no way to say "already logged
 * in", so the session is set for Angus to log in with USER and PASS alone, and
 * the socket answers those two itself; they never reach the server. What Angus
 * sends after them - STAT, LIST, RETR, DELE - goes through.
 *
 * <p>Angus insists on a password before it connects at all. It gets a
 * placeholder, which is not a secret and never leaves this JVM. A real
 * password handed to it is refused.
 */
public final class SeclumePop3Store extends POP3Store {

    private final String protocol;

    public SeclumePop3Store(Session session, URLName url) {
        // Never SSL as far as Angus is concerned: the TLS is seclume's own.
        super(session, url, protocolOf(url), false);
        this.protocol = protocolOf(url);
    }

    private static String protocolOf(URLName url) {
        return url == null || url.getProtocol() == null ? "pop3" : url.getProtocol();
    }

    @Override
    protected synchronized boolean protocolConnect(String host, int port, String user,
            String password) throws MessagingException {
        SeclumeMail.refusePassword(password);
        MailSettings settings = SeclumeMail.settings(session, protocol);
        return super.protocolConnect(settings.host, settings.port, settings.user,
                SeclumeMail.PLACEHOLDER);
    }
}
