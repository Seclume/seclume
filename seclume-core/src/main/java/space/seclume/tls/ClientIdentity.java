package space.seclume.tls;

import java.util.List;

/**
 * Who the client is, when the server asks.
 *
 * <p>Mutual TLS closes the gap the library used to leave open. A password
 * handed to seclume never reaches the heap; a client certificate's private
 * key, in every other driver, is an {@code ECPrivateKey} or an
 * {@code RSAPrivateKey} whose material sits in objects nothing can wipe. An
 * attacker with that key does not need the password - it authenticates the
 * very same connection. Protecting one and not the other protects nothing.
 *
 * <p>So the private key never crosses this interface. What crosses it is a
 * <b>signature</b>, which is public, over <b>content</b>, which is public
 * too - the key stays inside the implementation, in native memory, and the
 * handshake only ever asks it to prove something.
 *
 * <p>The certificate chain is equally public: it is sent in the clear in every
 * handshake, and there is nothing to gain by keeping it off the heap.
 *
 * <p>An identity is closed when the connection that used it is done with it,
 * and closing it releases the key.
 */
public interface ClientIdentity extends AutoCloseable {

    /**
     * The certificate chain, DER-encoded, <b>leaf first</b>.
     *
     * <p>The order is the one TLS 1.3 requires (RFC 8446, section 4.4.2) and
     * not the one a PEM bundle is usually written in, so an implementation
     * reading a bundle has to say which end it is taking.
     */
    List<byte[]> chain();

    /**
     * The {@code SignatureScheme} this identity signs with - the two-byte code
     * that goes into {@code CertificateVerify}, e.g.
     * {@link HandshakeSignature#ECDSA_SECP256R1_SHA256}.
     */
    int signatureScheme();

    /**
     * Signs what {@link HandshakeSignature#content} built.
     *
     * <p>Nothing here is secret: the content is derived from a transcript both
     * sides have, and a signature is meant to be shown. Which is why this is
     * the only shape the interface needs - the secret is the key, and the key
     * does not appear.
     *
     * @return the signature, encoded as the scheme requires
     */
    byte[] sign(byte[] content);

    @Override
    void close();
}
