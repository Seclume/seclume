package space.seclume.field;

/**
 * A value that cannot be encrypted or decrypted: not seclume's format, a key
 * the ring does not hold, a column of the other mode, or a tag that does not
 * match.
 *
 * <p>The last one says nothing about which of the inputs was wrong. A tag
 * covers the key, the column, the context and the ciphertext at once, and a
 * message that narrowed it down would be an oracle.
 */
public class FieldEncryptionException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public FieldEncryptionException(String message) {
        super(message);
    }

    public FieldEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
