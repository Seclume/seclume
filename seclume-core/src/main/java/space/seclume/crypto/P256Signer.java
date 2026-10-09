package space.seclume.crypto;

import java.lang.foreign.MemorySegment;

/**
 * Signs with a P-256 private key that never becomes a Java object.
 *
 * <p>{@link NativeP256} is the other half of the same idea and deliberately a
 * different class: that one is an <b>ephemeral</b> key generated for one
 * handshake and thrown away, and it only ever agrees on a shared secret. This
 * one is a <b>long-lived</b> key that was issued to this client, loaded from
 * somewhere, and used to prove who we are. The two have almost nothing in
 * common but the curve, and merging them would produce a class whose
 * documentation had to start with "depending on how it was constructed".
 *
 * <p>The reason it exists at all is the gap the library used to have: the
 * password was held off the heap with some care, and the private key that
 * authenticates the very same connection was handed to the JCA, where a
 * {@code PrivateKey} keeps its material in objects nothing can wipe. Either
 * both are protected or neither is worth protecting - an attacker with the key
 * does not need the password.
 *
 * <p>The key material goes straight from a {@code MemorySegment} into CNG
 * (Windows) or OpenSSL 3 (64-bit Linux), and the signing happens there. There
 * is no heap fallback, for the same reason there is none in {@link NativeP256}:
 * a fallback that quietly gives up the guarantee is worse than a platform that
 * says no.
 *
 * <h2>Why the public point is a parameter</h2>
 *
 * <p>Neither provider can import a private scalar on its own - both want the
 * public point beside it, because deriving one from the other is a scalar
 * multiplication they will not do during an import. That is no hardship: the
 * point is in the certificate this key belongs to, which the caller has to
 * have anyway. It also buys a check for free - a key that does not belong to
 * the certificate is refused at import rather than producing signatures nobody
 * can verify.
 *
 * <h2>The output</h2>
 *
 * <p>Always <b>DER</b>, which is what TLS 1.3 wants in {@code CertificateVerify}
 * (RFC 8446, section 4.2.3): {@code SEQUENCE { INTEGER r, INTEGER s }}, at most
 * {@value #MAX_SIGNATURE} bytes. OpenSSL produces that shape itself; CNG
 * produces the raw pair and it is encoded here.
 *
 * <p>Thread-confined and explicitly closed, like everything else that holds
 * key material.
 */
public final class P256Signer implements AutoCloseable {

    /** Field size: r and s are 32 bytes each before encoding. */
    public static final int FIELD = 32;

    /**
     * The longest a DER-encoded P-256 signature can be.
     *
     * <p>Two integers of 32 bytes, each of which may need a leading zero when
     * its top bit is set, plus two bytes of tag and length each, plus the
     * two-byte SEQUENCE header: 2 + 2 * (2 + 33).
     */
    public static final int MAX_SIGNATURE = 72;

    // The work is EcdsaSigner's, which does P-384 as well; this class keeps
    // the P-256 API it always had.
    private final EcdsaSigner signer;

    private P256Signer(EcdsaSigner signer) {
        this.signer = signer;
    }

    /**
     * Takes the key into the provider and keeps it there.
     *
     * <p>Neither segment is retained: the provider copies what it needs and
     * the caller stays free to wipe both the moment this returns. That is the
     * point of loading a key this way rather than keeping it around - the
     * window in which it exists outside the provider is as short as the call.
     *
     * @param publicPoint 65 bytes, {@code 0x04 || x || y}, from the certificate
     * @param scalar      32 bytes, big-endian, in native memory - normally a
     *                    {@code SecretScope}
     */
    public static P256Signer of(MemorySegment publicPoint, MemorySegment scalar) {
        return new P256Signer(EcdsaSigner.of(EcdsaSigner.Curve.P256, publicPoint, scalar));
    }

    /** Whether this platform can sign at all - for a caller that wants to say why not. */
    public static boolean available() {
        return EcdsaSigner.available();
    }

    /**
     * Signs a digest that has already been computed.
     *
     * <p>Pre-hashed on purpose: in TLS the thing being signed is built from the
     * transcript by {@link space.seclume.tls.HandshakeSignature}, and handing
     * the provider a message to hash itself would mean two places that have to
     * agree on which hash it was.
     *
     * @param digest the hash to sign - 32 bytes for SHA-256
     * @param der    where the DER signature goes; at least
     *               {@value #MAX_SIGNATURE} bytes
     * @return how many bytes of {@code der} were written
     */
    public int sign(MemorySegment digest, MemorySegment der) {
        return signer.sign(digest, der);
    }

    @Override
    public void close() {
        signer.close();
    }

    /** The raw pair {@code r || s} as DER - see {@link EcdsaSigner}. */
    static int der(MemorySegment raw, MemorySegment out) {
        return EcdsaSigner.der(raw, FIELD, out);
    }
}
