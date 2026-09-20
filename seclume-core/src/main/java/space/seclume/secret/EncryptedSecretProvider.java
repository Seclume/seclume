package space.seclume.secret;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

import space.seclume.crypto.AesGcm;
import space.seclume.crypto.AesKey;
import space.seclume.internal.Base64Off;

/**
 * A secret that is stored encrypted, decrypted straight into the target.
 *
 * <p>The case this exists for: the password may not sit in the configuration in
 * the clear, but there is nowhere better to put it either - no Vault, no
 * Credential Manager, no secrets mount. So it sits there encrypted, and the key
 * that opens it comes from somewhere the ciphertext is not.
 *
 * <p><b>That is a smaller gain than it looks, and it should be said plainly:</b>
 * whoever can read the ciphertext can usually read the key file next to it.
 * What this buys is that the secret does not stand in a configuration file, a
 * repository or a container image in readable form - a real gain against
 * copying, screenshots, backups and accidental commits, and no gain at all
 * against somebody who already has the machine. A proper secret store is
 * better. This is for when there is none.
 *
 * <h2>What is kept off the heap, and what need not be</h2>
 *
 * <p>Only two things are secret: the <b>key</b> and the <b>plaintext</b>. Both
 * live in native memory from beginning to end - the key is read into a segment
 * by another provider, the plaintext is written by {@link AesGcm} directly into
 * the caller's target, and neither is ever a Java object. The <b>ciphertext is
 * not secret</b> and would do no harm on the heap; it is kept off it anyway,
 * because it arrives through an ordinary {@link SecretProvider} and those
 * already work that way.
 *
 * <p>The cryptography is {@code space.seclume.crypto}, not the JCA. That is not
 * an accident and not a preference: {@code javax.crypto.Cipher} takes its key
 * as a {@code SecretKeySpec}, which holds a {@code byte[]} that shows up in a
 * heap dump and that nothing can wipe. Using the JCA here would mean giving up
 * the one property this library exists for, in the very class whose job is to
 * protect it.
 *
 * <h2>The format</h2>
 *
 * <p>Both the ciphertext and the key are <b>Base64</b>, because a file, an
 * environment entry and a property all have to be able to carry them. Decoded,
 * the ciphertext is:
 *
 * <pre>
 *   [ 12 bytes nonce ][ ciphertext ][ 16 bytes tag ]
 * </pre>
 *
 * <p>AES-GCM with a twelve-byte nonce and a sixteen-byte tag; the key is 16, 24
 * or 32 bytes, which selects AES-128, -192 or -256.
 *
 * <p><b>A nonce is used once.</b> Encrypting two different secrets with the
 * same key and the same nonce hands an attacker the difference of the two
 * plaintexts and destroys the authentication for that key. Whatever produces
 * these files has to draw a fresh random nonce every time. This class cannot
 * check that and does not pretend to.
 *
 * <h2>Binding it to its purpose</h2>
 *
 * <p>The optional {@code aad} is authenticated but not encrypted, and it
 * answers an attack the encryption alone does not: without it the ciphertext of
 * the reporting database can be pasted over the one for the production
 * database, and it decrypts perfectly - it is a valid secret, just the wrong
 * one. Bind each ciphertext to where it belongs and the swap fails as a tag
 * mismatch instead of succeeding quietly.
 */
public final class EncryptedSecretProvider implements SecretProvider {

    private static final int NONCE = AesGcm.NONCE;
    private static final int TAG = AesGcm.TAG;
    /** Nonce plus tag: what a ciphertext costs before it carries anything. */
    private static final int OVERHEAD = NONCE + TAG;

    private final SecretProvider ciphertext;
    private final SecretProvider key;
    private final byte[] aad; // seclume-allow: associated data is authenticated, not secret

    /**
     * @param ciphertext where the Base64 ciphertext comes from - a file, an
     *                   environment entry, a socket, anything
     * @param key        where the Base64 key comes from; a different place than
     *                   the ciphertext, or the exercise is pointless
     * @param aad        additional authenticated data, or {@code null} - see the
     *                   class comment on why this is worth setting
     */
    public EncryptedSecretProvider(SecretProvider ciphertext, SecretProvider key, String aad) {
        this.ciphertext = ciphertext;
        this.key = key;
        this.aad = aad == null || aad.isEmpty() ? new byte[0] : utf8(aad);
    }

    /**
     * The plaintext is shorter than the ciphertext by the nonce and the tag, and
     * shorter again by a quarter because Base64 grows what it encodes. Reporting
     * the encoded length is therefore generous, which is all this has to be.
     */
    @Override
    public int maxSecretLength() {
        return ciphertext.maxSecretLength();
    }

    @Override
    public int writeSecret(MemorySegment target) {
        try (Arena arena = Arena.ofConfined();
             SecretScope encoded = SecretScope.fromProvider(ciphertext);
             SecretScope raw = SecretScope.in(arena, rawCapacity(encoded.length()))) {

            int rawLength = decode(encoded, raw, "ciphertext");
            if (rawLength < OVERHEAD + 1) {
                throw new SecretUnavailableException(
                        "the encrypted secret is " + rawLength + " bytes, which cannot hold a "
                        + NONCE + "-byte nonce, a " + TAG + "-byte tag and any content");
            }
            int contentLength = rawLength - OVERHEAD;
            if (contentLength > target.byteSize()) {
                throw new SecretUnavailableException(
                        "the decrypted secret is " + contentLength + " bytes and does not fit "
                        + "into the " + target.byteSize() + " bytes provided - raise max-length");
            }

            MemorySegment associated = arena.allocate(Math.max(aad.length, 1));
            MemorySegment.copy(aad, 0, associated, java.lang.foreign.ValueLayout.JAVA_BYTE,
                    0, aad.length);

            boolean authentic;
            try (SecretScope keyBytes = SecretScope.fromProvider(key);
                 SecretScope keyRaw = SecretScope.in(arena, rawCapacity(keyBytes.length()))) {

                int keyLength = decode(keyBytes, keyRaw, "key");
                if (keyLength != 16 && keyLength != 24 && keyLength != 32) {
                    throw new SecretUnavailableException(
                            "the key decodes to " + keyLength + " bytes; AES needs 16, 24 or 32");
                }
                try (AesKey aesKey = new AesKey(keyRaw.segment(), 0, keyLength)) {
                    authentic = AesGcm.decrypt(aesKey,
                            raw.segment(), 0,
                            associated, 0, aad.length,
                            raw.segment(), NONCE, contentLength,
                            target, 0);
                }
            }

            if (!authentic) {
                // Deliberately says nothing about what was wrong. A tag covers
                // the key, the nonce, the ciphertext and the associated data at
                // once, and an error message that narrowed it down would be an
                // oracle.
                throw new SecretUnavailableException(
                        "the encrypted secret did not authenticate - wrong key, wrong "
                        + "associated data, or the ciphertext has been altered");
            }
            return contentLength;
        }
    }

    /** Both inner sources are closed with this one; it owns neither exclusively. */
    @Override
    public void close() {
        try {
            ciphertext.close();
        } catch (Exception first) {
            try {
                key.close();
            } catch (Exception ignored) {
                // The first failure is the one worth reporting.
            }
            throw new SecretUnavailableException("closing the ciphertext source failed", first);
        }
        try {
            key.close();
        } catch (Exception e) {
            throw new SecretUnavailableException("closing the key source failed", e);
        }
    }

    /**
     * The associated data as bytes.
     *
     * <p>Associated data is <b>not a secret</b>. It is authenticated but not
     * encrypted, it is a label such as {@code main} or {@code reporting} taken
     * from the configuration, and it travels beside the ciphertext in the
     * clear - its whole purpose is to be public. It also arrives here as a
     * {@code String} parameter, so no choice made in this class could keep it
     * off the heap.
     *
     * <p>The secret takes a different route entirely and touches no Java
     * object on it: the key is read into native memory by another provider,
     * and {@link AesGcm} writes the plaintext straight into the caller's
     * segment. The rule against {@code getBytes} is about that route, and that
     * route is unaffected. Same case as the entropy in
     * {@link DpapiSecretProvider} and the target name in
     * {@link CredentialManagerSecretProvider}.
     */
    private static byte[] utf8(String text) {
        // seclume-allow: associated data is not a secret - see the javadoc above
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static int rawCapacity(int encodedLength) {
        return Math.max(Base64Off.decodedUpperBound(encodedLength), 1);
    }

    private static int decode(SecretScope encoded, SecretScope into, String what) {
        try {
            int length = Base64Off.decode(encoded.segment(), 0, encoded.length(),
                    into.segment(), 0);
            into.length(length);
            return length;
        } catch (RuntimeException notBase64) {
            throw new SecretUnavailableException(
                    "the " + what + " is not valid Base64", notBase64);
        }
    }
}
