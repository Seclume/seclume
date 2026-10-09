package space.seclume.crypto;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.internal.Platform;

/**
 * Signs with a P-256 or P-384 private key that never becomes a Java object.
 *
 * <p>The design of {@link P256Signer}, for both curves a client certificate
 * has in practice: P-256, and P-384 where FIPS or CNSA configurations ask for
 * it. The key material goes straight from a {@code MemorySegment} into CNG
 * (Windows) or OpenSSL 3 (64-bit Linux), and the signing happens there; there
 * is no heap fallback.
 *
 * <p>The public point is a parameter for the reasons {@link P256Signer} gives:
 * neither provider imports a scalar alone, and importing both lets the pair be
 * checked at once. The output is DER, at most {@link Curve#maxSignature()} bytes.
 *
 * <p>Thread-confined and explicitly closed, like everything else that holds
 * key material.
 */
public final class EcdsaSigner implements AutoCloseable {

    /** The two curves, with what each provider calls them. */
    public enum Curve {
        /** secp256r1, signed with SHA-256: TLS scheme {@code ecdsa_secp256r1_sha256}. */
        P256(32, "ECDSA_P256", 0x31534345, 0x32534345, "prime256v1", "P-256"),
        /** secp384r1, signed with SHA-384: TLS scheme {@code ecdsa_secp384r1_sha384}. */
        P384(48, "ECDSA_P384", 0x33534345, 0x34534345, "secp384r1", "P-384");

        private final int field;
        private final String cngAlgorithm;
        private final int cngPublicMagic;
        private final int cngPrivateMagic;
        private final String openSslGroup;
        private final String label;

        Curve(int field, String cngAlgorithm, int cngPublicMagic, int cngPrivateMagic,
              String openSslGroup, String label) {
            this.field = field;
            this.cngAlgorithm = cngAlgorithm;
            this.cngPublicMagic = cngPublicMagic;
            this.cngPrivateMagic = cngPrivateMagic;
            this.openSslGroup = openSslGroup;
            this.label = label;
        }

        /** Bytes per coordinate, per half of a signature, and of the scalar - and of the digest. */
        public int field() {
            return field;
        }

        /** {@code 0x04 || x || y}. */
        public int pointSize() {
            return 1 + 2 * field;
        }

        /**
         * The longest DER signature: two INTEGERs of {@code field} bytes, each
         * with a possible leading zero and two bytes of tag and length, in a
         * SEQUENCE - short-form lengths for both curves.
         */
        public int maxSignature() {
            return 2 + 2 * (2 + field + 1);
        }

        /** The curve whose coordinates are {@code field} bytes. */
        public static Curve ofField(int field) {
            for (Curve curve : values()) {
                if (curve.field == field) {
                    return curve;
                }
            }
            throw new IllegalArgumentException("no P-256 or P-384 curve has " + field
                    + "-byte coordinates");
        }

        String cngAlgorithm() {
            return cngAlgorithm;
        }

        /** BCRYPT_ECDSA_PUBLIC_P256_MAGIC 'ECS1' / _P384 'ECS3'. */
        int cngPublicMagic() {
            return cngPublicMagic;
        }

        /** BCRYPT_ECDSA_PRIVATE_P256_MAGIC 'ECS2' / _P384 'ECS4'. */
        int cngPrivateMagic() {
            return cngPrivateMagic;
        }

        String openSslGroup() {
            return openSslGroup;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    /** What a provider has to be able to do; see the two implementations. */
    interface Backend extends AutoCloseable {
        /** @return the length written into {@code der} */
        int sign(MemorySegment digest, MemorySegment der);

        @Override void close();
    }

    private final Thread owner = Thread.currentThread();
    private final Curve curve;
    private final Backend backend;
    private boolean closed;

    private EcdsaSigner(Curve curve, Backend backend) {
        this.curve = curve;
        this.backend = backend;
    }

    /**
     * Takes the key into the provider and keeps it there. Neither segment is
     * retained: the caller stays free to wipe both the moment this returns.
     *
     * @param publicPoint {@code 0x04 || x || y} from the certificate
     * @param scalar      the private scalar, big-endian, {@code field} bytes,
     *                    in native memory - normally a {@code SecretScope}
     */
    public static EcdsaSigner of(Curve curve, MemorySegment publicPoint, MemorySegment scalar) {
        if (publicPoint.byteSize() < curve.pointSize()
                || publicPoint.get(ValueLayout.JAVA_BYTE, 0) != 4) {
            throw new IllegalArgumentException(curve + " requires an uncompressed public point of "
                    + curve.pointSize() + " bytes");
        }
        if (scalar.byteSize() < curve.field()) {
            throw new IllegalArgumentException("a " + curve + " private scalar is "
                    + curve.field() + " bytes");
        }
        if (Platform.isWindows()) {
            return new EcdsaSigner(curve, new CngEcdsaSigner(curve, publicPoint, scalar));
        }
        if (Platform.isLinux() && ValueLayout.ADDRESS.byteSize() == 8) {
            return new EcdsaSigner(curve, new OpenSslEcdsaSigner(curve, publicPoint, scalar));
        }
        throw new UnsupportedOperationException("signing with an EC key off the heap requires "
                + "Windows or 64-bit Linux with libcrypto.so.3");
    }

    /** Whether this platform can sign at all - for a caller that wants to say why not. */
    public static boolean available() {
        return Platform.isWindows()
                || (Platform.isLinux() && ValueLayout.ADDRESS.byteSize() == 8);
    }

    public Curve curve() {
        return curve;
    }

    /**
     * Signs a digest that has already been computed - SHA-256 for P-256,
     * SHA-384 for P-384, as TLS pairs them.
     *
     * @param digest {@code field} bytes
     * @param der    where the DER signature goes; at least
     *               {@link Curve#maxSignature()} bytes
     * @return how many bytes of {@code der} were written
     */
    public int sign(MemorySegment digest, MemorySegment der) {
        checkOpen();
        if (digest.byteSize() != curve.field()) {
            throw new IllegalArgumentException("ECDSA with " + curve + " signs a "
                    + curve.field() + "-byte digest, not " + digest.byteSize());
        }
        if (der.byteSize() < curve.maxSignature()) {
            throw new IllegalArgumentException(
                    "the signature needs room for " + curve.maxSignature() + " bytes");
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
     * The raw pair {@code r || s}, each {@code field} bytes, as DER - for a
     * provider that hands out the coordinates rather than the encoding.
     *
     * <p>Each half becomes an {@code INTEGER}, which in DER is signed and
     * minimal: leading zero bytes go, and one zero comes back if the top bit
     * would otherwise read as a negative number. Getting this wrong produces a
     * signature that this code verifies happily and every other implementation
     * rejects, which is the worst kind of bug to find later.
     */
    static int der(MemorySegment raw, int field, MemorySegment out) {
        int rLength = integer(raw, 0, field, out, 4);
        int sLength = integer(raw, field, field, out, 4 + rLength + 2);
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

    /** One half as the body of a DER INTEGER. @return its length */
    private static int integer(MemorySegment raw, int from, int field, MemorySegment out,
                               long to) {
        int start = 0;
        while (start < field - 1 && raw.get(ValueLayout.JAVA_BYTE, from + start) == 0) {
            start++;
        }
        boolean pad = (raw.get(ValueLayout.JAVA_BYTE, from + start) & 0x80) != 0;
        int length = field - start + (pad ? 1 : 0);
        long at = to;
        if (pad) {
            out.set(ValueLayout.JAVA_BYTE, at++, (byte) 0);
        }
        MemorySegment.copy(raw, from + start, out, at, field - start);
        return length;
    }
}
