package space.seclume.crypto;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.internal.Platform;

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

    /** What a provider has to be able to do; see the two implementations. */
    interface Backend extends AutoCloseable {
        /** @return the length written into {@code der} */
        int sign(MemorySegment digest, MemorySegment der);

        @Override void close();
    }

    private final Thread owner = Thread.currentThread();
    private final Backend backend;
    private boolean closed;

    private P256Signer(Backend backend) {
        this.backend = backend;
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
        if (publicPoint.byteSize() < 65 || publicPoint.get(ValueLayout.JAVA_BYTE, 0) != 4) {
            throw new IllegalArgumentException(
                    "P-256 requires an uncompressed public point of 65 bytes");
        }
        if (scalar.byteSize() < FIELD) {
            throw new IllegalArgumentException("a P-256 private scalar is 32 bytes");
        }
        if (Platform.isWindows()) {
            return new P256Signer(new CngP256Signer(publicPoint, scalar));
        }
        if (Platform.isLinux() && ValueLayout.ADDRESS.byteSize() == 8) {
            return new P256Signer(new OpenSslP256Signer(publicPoint, scalar));
        }
        throw new UnsupportedOperationException("signing with a P-256 key off the heap requires "
                + "Windows or 64-bit Linux with libcrypto.so.3");
    }

    /** Whether this platform can sign at all - for a caller that wants to say why not. */
    public static boolean available() {
        return Platform.isWindows()
                || (Platform.isLinux() && ValueLayout.ADDRESS.byteSize() == 8);
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
        checkOpen();
        if (digest.byteSize() != FIELD) {
            throw new IllegalArgumentException(
                    "ECDSA with P-256 signs a 32-byte digest, not " + digest.byteSize());
        }
        if (der.byteSize() < MAX_SIGNATURE) {
            throw new IllegalArgumentException(
                    "the signature needs room for " + MAX_SIGNATURE + " bytes");
        }
        return backend.sign(digest, der);
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        backend.close();
    }

    private void checkOpen() {
        if (closed) {
            throw new IllegalStateException("the signer is closed");
        }
        if (Thread.currentThread() != owner) {
            throw new IllegalStateException("a signer belongs to the thread that made it");
        }
    }

    /**
     * The raw pair {@code r || s} as DER, for a provider that hands out the
     * coordinates rather than the encoding.
     *
     * <p>Each half becomes an {@code INTEGER}, which in DER is signed and
     * minimal: leading zero bytes go, and one zero comes back if the top bit
     * would otherwise read as a negative number. Getting this wrong produces a
     * signature that this code verifies happily and every other implementation
     * rejects, which is the worst kind of bug to find later.
     */
    static int der(MemorySegment raw, MemorySegment out) {
        int rLength = integer(raw, 0, out, 4);
        int sLength = integer(raw, FIELD, out, 4 + rLength + 2);
        int content = 2 + rLength + 2 + sLength;

        // Written back to front: the header lengths are only known now.
        out.set(ValueLayout.JAVA_BYTE, 0, (byte) 0x30);
        out.set(ValueLayout.JAVA_BYTE, 1, (byte) content);
        out.set(ValueLayout.JAVA_BYTE, 2, (byte) 0x02);
        out.set(ValueLayout.JAVA_BYTE, 3, (byte) rLength);
        out.set(ValueLayout.JAVA_BYTE, 4L + rLength, (byte) 0x02);
        out.set(ValueLayout.JAVA_BYTE, 5L + rLength, (byte) sLength);
        return 2 + content;
    }

    /** One 32-byte half as the body of a DER INTEGER. @return its length */
    private static int integer(MemorySegment raw, int from, MemorySegment out, long to) {
        int start = 0;
        while (start < FIELD - 1 && raw.get(ValueLayout.JAVA_BYTE, from + start) == 0) {
            start++;
        }
        boolean pad = (raw.get(ValueLayout.JAVA_BYTE, from + start) & 0x80) != 0;
        int length = FIELD - start + (pad ? 1 : 0);
        long at = to;
        if (pad) {
            out.set(ValueLayout.JAVA_BYTE, at++, (byte) 0);
        }
        MemorySegment.copy(raw, from + start, out, at, FIELD - start);
        return length;
    }
}
