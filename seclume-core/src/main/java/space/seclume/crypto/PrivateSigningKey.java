package space.seclume.crypto;

import java.lang.foreign.MemorySegment;

import space.seclume.internal.Platform;

/**
 * A private key that signs where it lives - in OpenSSL 3 on Linux
 * ({@link OpenSslSigningKey}), in CNG on Windows ({@link CngSigningKey}) - and
 * never becomes a Java object. What seclume-keys, seclume-jwt and SigV4a sign
 * with.
 *
 * <p>Both backends take the same input - PEM or DER, PKCS#8, SEC 1 or PKCS#1,
 * unencrypted - and give the same output: the public half as a DER
 * {@code SubjectPublicKeyInfo}, signatures as OpenSSL writes them (DER for
 * ECDSA).
 */
public interface PrivateSigningKey extends AutoCloseable {

    /** The longest signature either backend writes. */
    int MAX_SIGNATURE = OpenSslSigningKey.MAX_SIGNATURE;

    /** Whether one of the backends can be used here. */
    static boolean available() {
        return OpenSslSigningKey.available() || CngSigningKey.available();
    }

    /**
     * Decodes a private key from {@code length} bytes of PEM or DER at the
     * start of {@code encoded}, which stays the caller's to wipe - with
     * OpenSSL where it is, else with CNG.
     */
    static PrivateSigningKey decode(MemorySegment encoded, int length) {
        if (OpenSslSigningKey.available()) {
            return OpenSslSigningKey.decode(encoded, length);
        }
        if (CngSigningKey.available()) {
            return CngSigningKey.decode(encoded, length);
        }
        throw new IllegalStateException("signing with a private key needs OpenSSL 3 on 64-bit "
                + "Linux or CNG on Windows, and this is " + (Platform.isMac() ? "macOS"
                        : System.getProperty("os.name")));
    }

    /** {@code RSA}, {@code EC}, {@code ED25519}, {@code RSA-PSS} - whether this key is of that type. */
    boolean is(String type);

    /** The public half, as a DER {@code SubjectPublicKeyInfo}. Public, and so a {@code byte[]}. */
    byte[] publicKey();

    /**
     * Signs {@code length} bytes of {@code message}, hashing them with
     * {@code digest} ({@code SHA256}, {@code SHA384}, {@code SHA512}); with
     * {@code pss}, RSA-PSS with a salt as long as the digest. ECDSA comes out
     * in DER.
     *
     * @return how many bytes of {@code signature} were written
     */
    int sign(String digest, boolean pss, MemorySegment message, long length,
             MemorySegment signature);

    @Override
    void close();
}
