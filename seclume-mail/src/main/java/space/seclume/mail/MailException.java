package space.seclume.mail;

import java.io.IOException;

/**
 * The mail server answered with something other than what the step needed -
 * over SMTP, IMAP or POP3.
 *
 * <p>The message carries the server's reply as it came. A mail server never
 * echoes a credential, so there is nothing to hide in it - and hiding it
 * would take away the one line that says why a login or a recipient was
 * refused.
 */
public class MailException extends IOException {

    private static final long serialVersionUID = 1L;

    private final int replyCode;

    public MailException(int replyCode, String message) {
        super(message);
        this.replyCode = replyCode;
    }

    /** SMTP's three-digit reply code; -1 for IMAP and POP3, and when it was not a reply. */
    public int replyCode() {
        return replyCode;
    }
}
