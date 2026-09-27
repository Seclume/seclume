package space.seclume.mail;

import java.io.IOException;

/**
 * The server answered with something other than what the step needed.
 *
 * <p>The message carries the server's reply as it came. An SMTP server never
 * echoes a credential, so there is nothing to hide in it - and hiding it
 * would take away the one line that says why a login or a recipient was
 * refused.
 */
public class SmtpException extends IOException {

    private static final long serialVersionUID = 1L;

    private final int replyCode;

    public SmtpException(int replyCode, String message) {
        super(message);
        this.replyCode = replyCode;
    }

    /** The three-digit reply code, or -1 when the failure was not a reply. */
    public int replyCode() {
        return replyCode;
    }
}
