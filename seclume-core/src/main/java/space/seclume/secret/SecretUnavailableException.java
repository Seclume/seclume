package space.seclume.secret;

/**
 * The secret source delivered nothing usable.
 *
 * <p>The message names the source (path, service, key name) and the reason,
 * never the content that was read - an exception message ends up in logs, in
 * traces and in bug reports.
 */
public class SecretUnavailableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public SecretUnavailableException(String message) {
        super(message);
    }

    public SecretUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
