package space.seclume.tls;

import java.io.IOException;
import java.io.InputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
// seclume-allow: only the certificate's public coordinates - see publicPoint below
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
// seclume-allow: hashes the public transcript, never the key - see sign below
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.ArrayList;
import java.util.List;

import space.seclume.crypto.EcPrivateKeyFile;
import space.seclume.crypto.P256Signer;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;
import space.seclume.secret.SecretUnavailableException;

/**
 * A client identity whose P-256 private key lives in the provider, not in Java.
 *
 * <p>The division of labour is the whole design. The <b>certificate</b> is
 * public, so it is read with {@code CertificateFactory} like anyone else's -
 * there is nothing to protect and a great deal of parsing not worth repeating.
 * The <b>private key</b> never becomes an object: its bytes come out of a
 * {@link SecretProvider} into a {@link SecretScope}, the scalar is picked out
 * of the DER in place by {@link EcPrivateKeyFile}, and it goes straight into
 * CNG or OpenSSL, which keeps it. Between the file and the provider it exists
 * only in native memory that is wiped on the way out, including on failure.
 *
 * <p>The key is loaded <b>once</b>, at construction, and the provider holds it
 * from then on. The alternative - reading it again for every connection, the
 * way a password is read - would mean the file, the mount or the HSM is
 * touched on every physical connect, for a key that does not rotate on that
 * timescale. What it costs is that the key is resident for the life of the
 * data source; what it buys is that it is resident in <b>one</b> place that
 * can be closed, rather than in a fresh set of unwipeable objects per
 * connection.
 *
 * <p>P-256 only, and that is a statement rather than a limitation: it is what
 * {@link ClientHandshake} negotiates for key exchange, what the signer
 * supports off the heap, and what a certificate issued for a database client
 * in the last ten years almost always is. An RSA client certificate is refused
 * with a message that says so, instead of quietly falling back to the JCA and
 * giving up the guarantee this class exists for.
 */
public final class P256ClientIdentity implements ClientIdentity {

    private final List<byte[]> chain;
    private final P256Signer signer;
    private boolean closed;

    /**
     * @param certificateChain the client certificate and any intermediates,
     *                         PEM or DER, leaf first
     * @param key              where the private key file comes from - any
     *                         seclume secret provider, so the key can equally
     *                         well arrive from a mount, an agent or encrypted
     */
    public P256ClientIdentity(Path certificateChain, SecretProvider key) {
        this(readChain(certificateChain), key);
    }

    /** The same with the chain already in hand - for tests and for callers that have it. */
    public P256ClientIdentity(List<byte[]> certificateChain, SecretProvider key) {
        if (certificateChain.isEmpty()) {
            throw new IllegalArgumentException("a client identity needs at least its own "
                    + "certificate");
        }
        this.chain = List.copyOf(certificateChain);
        this.signer = load(publicPoint(this.chain.get(0)), key);
    }

    /**
     * Key file to provider, through native memory and nothing else.
     *
     * <p>Everything in here is inside a try-with-resources for the reason
     * {@code WipeOnFailureTest} spells out: a malformed key file, a wrong
     * curve or a mismatched pair all leave through an exception, and that is
     * exactly where a wipe gets skipped if it is not attached to the exit.
     */
    private static P256Signer load(byte[] point, SecretProvider key) {
        try (Arena arena = Arena.ofConfined();
             SecretScope file = SecretScope.fromProvider(key);
             SecretScope scalar = SecretScope.in(arena, EcPrivateKeyFile.SCALAR)) {

            EcPrivateKeyFile.scalar(file.segment(), file.length(), scalar.segment());
            scalar.length(EcPrivateKeyFile.SCALAR);

            MemorySegment publicPoint = arena.allocate(65);
            MemorySegment.copy(point, 0, publicPoint, ValueLayout.JAVA_BYTE, 0, 65);
            return P256Signer.of(publicPoint, scalar.segment());
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw new SecretUnavailableException("the client certificate's private key could "
                    + "not be loaded: " + e.getMessage(), e);
        }
    }

    @Override
    public List<byte[]> chain() {
        return chain;
    }

    @Override
    public int signatureScheme() {
        return HandshakeSignature.ECDSA_SECP256R1_SHA256;
    }

    @Override
    public byte[] sign(byte[] content) {
        if (closed) {
            throw new IllegalStateException("this client identity is closed");
        }
        try (Arena arena = Arena.ofConfined()) {
            // Public data on both sides: the content comes from a transcript
            // the server has as well, and a signature is meant to be seen.
            byte[] digest = sha256(content);
            MemorySegment hash = arena.allocate(digest.length);
            MemorySegment.copy(digest, 0, hash, ValueLayout.JAVA_BYTE, 0, digest.length);

            MemorySegment der = arena.allocate(P256Signer.MAX_SIGNATURE);
            int length = signer.sign(hash, der);
            byte[] signature = new byte[length];
            MemorySegment.copy(der, ValueLayout.JAVA_BYTE, 0, signature, 0, length);
            return signature;
        }
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        signer.close();
    }

    // ------------------------------------------------------ the public half --

    /**
     * SHA-256 over the CertificateVerify content.
     *
     * <p>Also public, and for a reason worth stating: the content is built
     * from the handshake transcript, which the server has in full as well -
     * it has to, or it could not check the signature. Nothing secret is
     * hashed here, and the JCA is used because there is nothing to protect.
     * The key stays where it was put.
     */
    private static byte[] sha256(byte[] content) {
        try {
            // seclume-allow: public transcript data, see the javadoc above
            return MessageDigest.getInstance("SHA-256").digest(content);
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("a JVM without SHA-256", impossible);
        }
    }

    /** {@code 0x04 || x || y} out of the leaf certificate. */
    private static byte[] publicPoint(byte[] leaf) {
        X509Certificate certificate = parse(leaf);
        if (!(certificate.getPublicKey() instanceof ECPublicKey ec)) {
            throw new IllegalArgumentException("the client certificate holds a "
                    + certificate.getPublicKey().getAlgorithm() + " key. seclume signs client "
                    + "certificates with P-256 only, because that is what it can do without "
                    + "putting the private key on the heap - see P256ClientIdentity");
        }
        ECPoint w = ec.getW();
        byte[] point = new byte[65];
        point[0] = 4;
        fixed(w.getAffineX(), point, 1);
        fixed(w.getAffineY(), point, 33);
        return point;
    }

    /**
     * A coordinate into exactly 32 bytes.
     *
     * <p>{@code BigInteger.toByteArray} gives neither: it adds a leading zero
     * when the top bit is set and drops leading zeroes otherwise, so a naive
     * copy is off by one byte roughly half the time and produces a point the
     * provider rejects - or worse, does not.
     *
     * <p><b>On the BigInteger.</b> The rule against it stands and is not being
     * bent here. What passes through this method is the <b>public</b> key out
     * of the certificate - the x and y coordinates that seclume sends to the
     * server in the clear in every handshake and that anybody holding the
     * certificate already has. It is not a secret and there is nothing about
     * it to wipe. The private scalar takes a route that touches no Java
     * object at all: {@link SecretProvider} into a {@link SecretScope},
     * {@link space.seclume.crypto.EcPrivateKeyFile} picking it out of the DER
     * in place, and straight into the provider - see {@code load} above, which
     * is the method the rule is actually about.
     */
    private static void fixed(BigInteger value, byte[] into, int at) {   // seclume-allow: public coordinates
        byte[] bytes = value.toByteArray();
        int from = Math.max(0, bytes.length - 32);
        int length = bytes.length - from;
        if (length > 32) {
            throw new IllegalArgumentException("this is not a P-256 certificate");
        }
        System.arraycopy(bytes, from, into, at + 32 - length, length);
    }

    private static X509Certificate parse(byte[] der) {
        try (InputStream in = new java.io.ByteArrayInputStream(der)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(in);
        } catch (CertificateException | IOException e) {
            throw new IllegalArgumentException("the client certificate cannot be read", e);
        }
    }

    /**
     * The chain out of a PEM bundle or a DER file, leaf first.
     *
     * <p>{@code CertificateFactory.generateCertificates} reads both and keeps
     * the file's order, which by convention is leaf first - the same order TLS
     * wants. A bundle written the other way round produces a handshake the
     * server refuses, which is the right outcome: silently reordering it would
     * hide a mistake in the deployment.
     */
    private static List<byte[]> readChain(Path file) {
        try {
            return parseChain(Files.readAllBytes(file), file); // seclume-allow: the certificate chain, which is public
        } catch (IOException e) {
            throw new IllegalArgumentException("the client certificate chain in " + file
                    + " cannot be read", e);
        }
    }

    /**
     * The same from bytes already read.
     *
     * <p>For {@link ReloadingClientIdentity}, which has to parse exactly the
     * bytes it compared: reading the file a second time to build the identity
     * would leave a window in which a rotation lands between the comparison
     * and the load, and the identity would then carry a chain that does not
     * match what was recorded as loaded.
     */
    static List<byte[]> parseChain(byte[] content, Path file) {
        try (InputStream in = new java.io.ByteArrayInputStream(content)) {
            List<byte[]> chain = new ArrayList<>();
            for (java.security.cert.Certificate certificate
                    : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                chain.add(certificate.getEncoded());
            }
            if (chain.isEmpty()) {
                throw new IllegalArgumentException(
                        "no certificate in " + file);
            }
            return chain;
        } catch (CertificateException | IOException e) {
            throw new IllegalArgumentException("the client certificate chain in " + file
                    + " cannot be read", e);
        }
    }
}
