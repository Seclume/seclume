package space.seclume.field;

import java.util.Arrays;

/**
 * An encrypted value as an object of the application: the ciphertext an
 * {@link EncryptedColumn} made, to be stored as it is and opened when needed.
 *
 * <p>The type for a secret in an entity - an API token, a TOTP seed, a refresh
 * token. The entity holds the sealed value from the moment it is loaded to the
 * moment it is saved; nothing on the heap is ever the plaintext. Opening it
 * writes the plaintext into native memory the caller owns
 * ({@link EncryptedColumn#open}), and only for as long as the caller keeps it.
 *
 * <pre>
 * &#64;Entity
 * class Tenant {
 *     &#64;Convert(converter = SealedConverter.class)   // seclume-jpa
 *     &#64;Column(length = 300) Sealed apiToken;
 * }
 *
 * tenant.apiToken = token.seal(issued.secret());
 * ...
 * try (SecretScope value = SecretScope.allocate(tenant.apiToken.plaintextLength())) {
 *     value.length(token.open(tenant.apiToken, value.segment()));
 * }
 * </pre>
 *
 * <p>Two sealed values are equal when their ciphertexts are: for a
 * deterministic column, when their plaintexts are - which is what a query
 * parameter needs. Immutable; the bytes are copied in and out.
 */
public final class Sealed {

    private final byte[] ciphertext; // seclume-allow: ciphertext, which is what the database holds

    private Sealed(byte[] ciphertext) {
        this.ciphertext = ciphertext;
    }

    /**
     * The value as the database holds it; checked to be field encryption's
     * format version 1 and long enough, not yet authenticated - that is done
     * when it is opened, by the column it belongs to.
     *
     * @return {@code null} for {@code null}: SQL NULL stays NULL
     */
    public static Sealed of(byte[] ciphertext) {
        if (ciphertext == null) {
            return null;
        }
        if (ciphertext.length < EncryptedColumn.OVERHEAD || ciphertext[0] != EncryptedColumn.VERSION) {
            throw new FieldEncryptionException("a sealed value is field encryption's format, "
                    + "version 1, at least " + EncryptedColumn.OVERHEAD + " bytes - this is "
                    + ciphertext.length + " bytes" + (ciphertext.length > 0
                            ? " starting with " + (ciphertext[0] & 0xff) : ""));
        }
        return new Sealed(ciphertext.clone());
    }

    /** A copy of the ciphertext, for storing. */
    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    /** The plaintext's length: the ciphertext's less the format's overhead. */
    public int plaintextLength() {
        return ciphertext.length - EncryptedColumn.OVERHEAD;
    }

    /** The number of the key it was sealed under. */
    public int keyId() {
        return ((ciphertext[2] & 0xff) << 24) | ((ciphertext[3] & 0xff) << 16)
                | ((ciphertext[4] & 0xff) << 8) | (ciphertext[5] & 0xff);
    }

    /** Whether it was sealed by a deterministic column. */
    public boolean deterministic() {
        return (ciphertext[1] & 1) != 0;
    }

    byte[] bytes() {
        return ciphertext;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof Sealed sealed && Arrays.equals(ciphertext, sealed.ciphertext);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(ciphertext);
    }

    /** Says what it is, never what it holds. */
    @Override
    public String toString() {
        return "Sealed[" + plaintextLength() + " bytes, key " + keyId()
                + (deterministic() ? ", deterministic" : "") + "]";
    }
}
