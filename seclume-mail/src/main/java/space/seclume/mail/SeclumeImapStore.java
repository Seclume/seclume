package space.seclume.mail;

import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.URLName;

import org.eclipse.angus.mail.imap.IMAPStore;

/**
 * Reading over IMAP, as Jakarta Mail sees it: Angus Mail's {@link IMAPStore},
 * behind {@code imap} and {@code imaps} in a session made by
 * {@link SeclumeMail#session} - with the login taken out of its hands.
 *
 * <p>Its socket factory is {@link MailSocket}'s, which connects, encrypts and
 * logs in before Angus reads a byte, and greets it with {@code PREAUTH}; Angus
 * then skips its own login. Folders, search, fetching and flags are
 * Angus's own, unchanged - and so are its pooled connections, each of which is
 * logged in the same way when it is opened.
 *
 * <p>Angus insists on a password before it connects at all. It gets a
 * placeholder, which is not a secret and never leaves this JVM: Angus does not
 * send it after PREAUTH. A real password handed to it is refused.
 */
public final class SeclumeImapStore extends IMAPStore {

    public SeclumeImapStore(Session session, URLName url) {
        // Never SSL as far as Angus is concerned: the TLS is seclume's own, inside
        // the socket. Angus doing TLS as well would be TLS over TLS - and JSSE.
        super(session, url, url == null || url.getProtocol() == null ? "imap"
                : url.getProtocol(), false);
    }

    @Override
    protected synchronized boolean protocolConnect(String host, int port, String user,
            String password) throws MessagingException {
        SeclumeMail.refusePassword(password);
        MailSettings settings = SeclumeMail.settings(session, name);
        return super.protocolConnect(settings.host, settings.port, settings.user,
                SeclumeMail.PLACEHOLDER);
    }
}
