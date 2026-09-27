package space.seclume.mail;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import jakarta.mail.Address;
import jakarta.mail.AuthenticationFailedException;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.SendFailedException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.URLName;
import jakarta.mail.event.TransportEvent;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

/**
 * seclume's SMTP as a Jakarta Mail transport: protocol {@code seclume-smtp}.
 *
 * <pre>
 * Properties props = new Properties();
 * props.put("mail.seclume-smtp.url",
 *         "smtp://mail.example.com:587?user=reports&amp;provider=file&amp;path=/run/secrets/smtp");
 * props.put("mail.transport.protocol.rfc822", "seclume-smtp");   // for Transport.send(message)
 * Session session = Session.getInstance(props);
 * Transport.send(message);
 * </pre>
 *
 * <p>Spring, with {@code JavaMailSenderImpl}:
 *
 * <pre>
 * sender.setProtocol("seclume-smtp");
 * sender.getJavaMailProperties().put("mail.seclume-smtp.url", url);
 * // no setHost, no setUsername, and above all no setPassword
 * </pre>
 *
 * <p><b>Jakarta Mail is given no password, and a password given to it is
 * refused.</b> Everything Jakarta Mail knows it keeps as a {@code String} - in
 * its {@code Session}, its {@code PasswordAuthentication}, the {@code URLName}
 * of this very transport - so the only credential that never reaches the heap
 * is the one it never gets. The URL names a secret provider; the transport
 * logs in itself, the way {@link SmtpConnection} describes.
 *
 * <p>The envelope sender is {@code mail.seclume-smtp.from} when set, the
 * message's first From address otherwise; the recipients are the addresses
 * Jakarta Mail hands over. A partial delivery - some recipients refused -
 * ends as the {@link SendFailedException} Jakarta Mail users expect, with the
 * refused ones among its invalid addresses, after the message went to the
 * rest.
 */
public final class SeclumeSmtpTransport extends Transport {

    /** The protocol name, in {@code mail.transport.protocol} or {@code getTransport(...)}. */
    public static final String PROTOCOL = "seclume-smtp";
    /** The session property that holds the URL. */
    public static final String URL_PROPERTY = "mail.seclume-smtp.url";
    /** The session property that sets the envelope sender. */
    public static final String FROM_PROPERTY = "mail.seclume-smtp.from";

    private SmtpConnection connection;

    public SeclumeSmtpTransport(Session session, URLName url) {
        super(session, url);
    }

    @Override
    protected boolean protocolConnect(String host, int port, String user, String password)
            throws MessagingException {
        if (password != null && !password.isEmpty()) {
            throw new AuthenticationFailedException("seclume-smtp takes no password from Jakarta "
                    + "Mail: it is a String in the Session for as long as the application runs. "
                    + "Name the secret in " + URL_PROPERTY + " (provider=...)");
        }
        String url = session.getProperty(URL_PROPERTY);
        if (url == null) {
            throw new MessagingException("seclume-smtp needs " + URL_PROPERTY);
        }
        try {
            connection = SeclumeSmtp.of(url).open();
            return true;
        } catch (SmtpException e) {
            if (e.replyCode() == 535 || e.replyCode() == 534) {
                throw new AuthenticationFailedException(e.getMessage());
            }
            throw new MessagingException(e.getMessage(), e);
        } catch (IOException | RuntimeException e) {
            throw new MessagingException("could not connect with " + URL_PROPERTY + ": "
                    + e.getMessage(), e);
        }
    }

    @Override
    public void sendMessage(Message message, Address[] addresses) throws MessagingException {
        if (!(message instanceof MimeMessage mime)) {
            throw new MessagingException("seclume-smtp sends MimeMessages, not "
                    + message.getClass().getName());
        }
        if (connection == null || !isConnected()) {
            throw new IllegalStateException(
                    "the seclume-smtp transport is not connected - call connect() first");
        }
        if (addresses == null || addresses.length == 0) {
            throw new SendFailedException("the message has no recipient to send to");
        }
        List<String> recipients = new ArrayList<>();
        for (Address address : addresses) {
            if (!(address instanceof InternetAddress internet)) {
                throw new SendFailedException("not an internet address: " + address);
            }
            recipients.add(internet.getAddress());
        }
        String from = envelopeSender(mime);

        SmtpConnection.Sent sent;
        try {
            sent = connection.send(from, recipients, out -> {
                try {
                    mime.writeTo(out);
                } catch (MessagingException e) {
                    throw new IOException(e.getMessage(), e);
                }
            });
        } catch (SmtpException e) {
            notifyTransportListeners(TransportEvent.MESSAGE_NOT_DELIVERED, new Address[0],
                    addresses, new Address[0], message);
            throw new SendFailedException(e.getMessage(), e, new Address[0], addresses,
                    new Address[0]);
        } catch (IOException e) {
            if (e.getCause() instanceof MessagingException writing) {
                throw writing;
            }
            throw new MessagingException(e.getMessage(), e);
        }

        if (sent.refused().isEmpty()) {
            notifyTransportListeners(TransportEvent.MESSAGE_DELIVERED, addresses,
                    new Address[0], new Address[0], message);
            return;
        }
        List<Address> delivered = new ArrayList<>();
        List<Address> invalid = new ArrayList<>();
        for (Address address : addresses) {
            String plain = ((InternetAddress) address).getAddress();
            (sent.refused().containsKey(plain) ? invalid : delivered).add(address);
        }
        Address[] ok = delivered.toArray(new Address[0]);
        Address[] bad = invalid.toArray(new Address[0]);
        notifyTransportListeners(TransportEvent.MESSAGE_PARTIALLY_DELIVERED, ok, new Address[0],
                bad, message);
        throw new SendFailedException("the server refused " + sent.refused(), null, ok,
                new Address[0], bad);
    }

    @Override
    public synchronized void close() throws MessagingException {
        if (connection != null) {
            connection.close();
            connection = null;
        }
        super.close();
    }

    private String envelopeSender(MimeMessage message) throws MessagingException {
        String configured = session.getProperty(FROM_PROPERTY);
        if (configured != null) {
            return configured;
        }
        Address[] from = message.getFrom();
        if (from != null && from.length > 0 && from[0] instanceof InternetAddress internet) {
            return internet.getAddress();
        }
        InternetAddress local = InternetAddress.getLocalAddress(session);
        if (local == null) {
            throw new SendFailedException("no sender: the message has no From and "
                    + FROM_PROPERTY + " is not set");
        }
        return local.getAddress();
    }
}
