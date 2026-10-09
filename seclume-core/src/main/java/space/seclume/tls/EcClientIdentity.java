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
import space.seclume.crypto.EcdsaSigner;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;
import space.seclume.secret.SecretUnavailableException;

/**
 * A client identity whose P-256 or P-384 private key lives in the provider,
 * not in Java.
 *
 * <p>The design of {@link P256ClientIdentity}, for both curves: the
 * certificate is public and read with {@code CertificateFactory}; the private
 * key comes out of a {@link SecretProvider} into a {@link SecretScope}, its
 * scalar is picked out of the DER in place by {@link EcPrivateKeyFile}, and it
 * goes straight into CNG or OpenSSL, which keeps it. The curve is the
 * certificate's: P-256 signs with SHA-256 ({@code ecdsa_secp256r1_sha256}),
 * P-384 with SHA-384 ({@code ecdsa_secp384r1_sha384}) - the pairing TLS 1.3
 * requires and FIPS and CNSA configurations ask for.
 *
 * <p>Still refused: RSA, which would mean the JCA and the key on the heap,
 * and P-521, which no database client certificate uses.
 */
public final class EcClientIdentity implements ClientIdentity {

    private final List<byte[]> chain;
    private final EcdsaSigner signer;
    private boolean closed;

    /**
     * @param certificateChain the client certificate and any intermediates,
     *                         PEM or DER, leaf first
     * @param key              where the private key file comes from - any
     *                         seclume secret provider
     */
    public EcClientIdentity(Path certificateChain, SecretProvider key) {
        this(readChain(certificateChain), key);
    }

    /** The same with the chain already in hand. */
    public EcClientIdentity(List<byte[]> certificateChain, SecretProvider key) {
        if (certificateChain.isEmpty()) {
            throw new IllegalArgumentException("a client identity needs at least its own "
                    + "certificate");
        }
        this.chain = List.copyOf(certificateChain);
        this.signer = load(publicKey(this.chain.get(0)), key);
    }

    /** The curve of the certificate's key. */
    public EcdsaSigner.Curve curve() {
        return signer.curve();
    }

    /** Key file to provider, through native memory and nothing else - see P256ClientIdentity. */
    private static EcdsaSigner load(ECPublicKey certificateKey, SecretProvider key) {
        EcdsaSigner.Curve curve = curveOf(certificateKey);
        int field = curve.field();
        try (Arena arena = Arena.ofConfined();
             SecretScope file = SecretScope.fromProvider(key);
             SecretScope scalar = SecretScope.in(arena, field)) {

            EcPrivateKeyFile.scalar(file.segment(), file.length(), scalar.segment(), field);
            scalar.length(field);

            byte[] point = publicPoint(certificateKey, field);
            MemorySegment publicPoint = arena.allocate(point.length);
            MemorySegment.copy(point, 0, publicPoint, ValueLayout.JAVA_BYTE, 0, point.length);
            return EcdsaSigner.of(curve, publicPoint, scalar.segment());
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
        return signer.curve() == EcdsaSigner.Curve.P384
                ? HandshakeSignature.ECDSA_SECP384R1_SHA384
                : HandshakeSignature.ECDSA_SECP256R1_SHA256;
    }

    @Override
    public byte[] sign(byte[] content) {
        if (closed) {
            throw new IllegalStateException("this client identity is closed");
        }
        try (Arena arena = Arena.ofConfined()) {
            // Public data on both sides: the content comes from a transcript
            // the server has as well, and a signature is meant to be seen.
            byte[] digest = digest(content, signer.curve());
            MemorySegment hash = arena.allocate(digest.length);
            MemorySegment.copy(digest, 0, hash, ValueLayout.JAVA_BYTE, 0, digest.length);

            MemorySegment der = arena.allocate(signer.curve().maxSignature());
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

    /** SHA-256 or SHA-384 over the CertificateVerify content - public transcript data. */
    private static byte[] digest(byte[] content, EcdsaSigner.Curve curve) {
        try {
            // seclume-allow: public transcript data, see P256ClientIdentity
            return MessageDigest.getInstance(curve == EcdsaSigner.Curve.P384 ? "SHA-384"
                    : "SHA-256").digest(content);
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("a JVM without SHA-2", impossible);
        }
    }

    private static ECPublicKey publicKey(byte[] leaf) {
        X509Certificate certificate = parse(leaf);
        if (!(certificate.getPublicKey() instanceof ECPublicKey ec)) {
            throw new IllegalArgumentException("the client certificate holds a "
                    + certificate.getPublicKey().getAlgorithm() + " key. seclume signs client "
                    + "certificates with P-256 or P-384 only, because that is what it can do "
                    + "without putting the private key on the heap - see EcClientIdentity");
        }
        return ec;
    }

    private static EcdsaSigner.Curve curveOf(ECPublicKey key) {
        int bits = key.getParams().getCurve().getField().getFieldSize();
        if (bits != 256 && bits != 384) {
            throw new IllegalArgumentException("the client certificate's key is on a "
                    + bits + "-bit curve; seclume signs with P-256 or P-384 only");
        }
        return EcdsaSigner.Curve.ofField(bits / 8);
    }

    /**
     * {@code 0x04 || x || y} out of the certificate's key - the public
     * coordinates, which every handshake sends in the clear. See
     * P256ClientIdentity on why a BigInteger is acceptable here and nowhere
     * near the scalar.
     */
    private static byte[] publicPoint(ECPublicKey key, int field) {
        ECPoint w = key.getW();
        byte[] point = new byte[1 + 2 * field];
        point[0] = 4;
        fixed(w.getAffineX(), point, 1, field);
        fixed(w.getAffineY(), point, 1 + field, field);
        return point;
    }

    /** A coordinate into exactly {@code field} bytes. */
    private static void fixed(BigInteger value, byte[] into, int at, int field) {   // seclume-allow: public coordinates
        byte[] bytes = value.toByteArray();
        int from = Math.max(0, bytes.length - field);
        int length = bytes.length - from;
        if (length > field) {
            throw new IllegalArgumentException("a coordinate longer than the curve");
        }
        System.arraycopy(bytes, from, into, at + field - length, length);
    }

    private static X509Certificate parse(byte[] der) {
        try (InputStream in = new java.io.ByteArrayInputStream(der)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(in);
        } catch (CertificateException | IOException e) {
            throw new IllegalArgumentException("the client certificate cannot be read", e);
        }
    }

    private static List<byte[]> readChain(Path file) {
        try {
            return parseChain(Files.readAllBytes(file), file); // seclume-allow: the certificate chain, which is public
        } catch (IOException e) {
            throw new IllegalArgumentException("the client certificate chain in " + file
                    + " cannot be read", e);
        }
    }

    /** The chain out of a PEM bundle or a DER file, leaf first - see P256ClientIdentity. */
    static List<byte[]> parseChain(byte[] content, Path file) {
        try (InputStream in = new java.io.ByteArrayInputStream(content)) {
            List<byte[]> chain = new ArrayList<>();
            for (java.security.cert.Certificate certificate
                    : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                chain.add(certificate.getEncoded());
            }
            if (chain.isEmpty()) {
                throw new IllegalArgumentException("no certificate in " + file);
            }
            return chain;
        } catch (CertificateException | IOException e) {
            throw new IllegalArgumentException("the client certificate chain in " + file
                    + " cannot be read", e);
        }
    }
}
