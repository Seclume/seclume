package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.internal.Base64Off;
import space.seclume.secret.SecretScope;

/**
 * The private scalar out of a key file, without the key ever being an object.
 *
 * <p>This is the piece that would otherwise force the whole exercise back onto
 * the heap. The obvious way to load a P-256 key is
 * {@code KeyFactory.generatePrivate(new PKCS8EncodedKeySpec(bytes))}, and that
 * single line puts the key into a {@code byte[]} that is copied into an
 * {@code ECPrivateKey} whose {@code BigInteger} keeps further copies, none of
 * which can be wiped and all of which a heap dump shows. So the file is parsed
 * here instead - a few dozen lines of DER, working on positions inside a
 * segment and copying only the 32 bytes that are the answer.
 *
 * <h2>What it reads</h2>
 *
 * <p>Both shapes that occur in practice, in PEM or raw DER:
 *
 * <ul>
 *   <li><b>PKCS#8</b>, {@code -----BEGIN PRIVATE KEY-----} - what
 *       {@code openssl genpkey}, Kubernetes cert-manager and most tooling
 *       writes today.
 *   <li><b>SEC1</b>, {@code -----BEGIN EC PRIVATE KEY-----} - what
 *       {@code openssl ecparam -genkey} still writes.
 * </ul>
 *
 * <p>An <b>encrypted</b> private key is refused with a message saying so. It
 * would be the wrong place to solve that anyway: a passphrase-protected key
 * file is an encrypted secret, and seclume already has a provider for those -
 * the file goes through {@code encrypted} and arrives here decrypted.
 */
public final class EcPrivateKeyFile {

    /** A P-256 private key is 32 bytes. */
    public static final int SCALAR = 32;

    /** {@code -----BEGIN} - enough to tell PEM from DER. */
    private static final byte[] BEGIN = {'-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N'};
    private static final byte[] END = {'-', '-', '-', '-', '-', 'E', 'N', 'D'};

    private EcPrivateKeyFile() {
    }

    /**
     * Reads the scalar out of a key file.
     *
     * @param source the file's bytes - PEM or DER, in native memory
     * @param length how many of them there are
     * @param out    where the 32 bytes go; the caller wipes it
     * @return {@value #SCALAR}, always - anything else has thrown by now
     */
    public static int scalar(MemorySegment source, int length, MemorySegment out) {
        if (out.byteSize() < SCALAR) {
            throw new IllegalArgumentException("a P-256 private key needs 32 bytes");
        }
        if (length > 0 && source.get(ValueLayout.JAVA_BYTE, 0) == 0x30) {
            return fromDer(source, 0, length, out);
        }
        try (Arena arena = Arena.ofConfined()) {
            long bodyAt = afterFirstLine(source, length);
            int bodyLength = (int) (beforeEnd(source, length) - bodyAt);
            if (bodyLength <= 0) {
                throw new IllegalArgumentException("this does not look like a PEM private key - "
                        + "no -----BEGIN/-----END pair, and it does not start with a DER SEQUENCE");
            }
            try (SecretScope der = SecretScope.in(arena,
                    Math.max(Base64Off.decodedUpperBound(bodyLength), 1))) {
                int decoded = Base64Off.decode(source, bodyAt, bodyLength, der.segment(), 0);
                der.length(decoded);
                return fromDer(der.segment(), 0, decoded, out);
            }
        }
    }

    /**
     * The DER walk, for both shapes.
     *
     * <p>They are told apart by the version number, which is the first element
     * of each and is 0 in PKCS#8 and 1 in SEC1. That is more robust than going
     * by the PEM label, which is only a comment and is wrong often enough to
     * matter.
     */
    private static int fromDer(MemorySegment der, long offset, int length, MemorySegment out) {
        Der.Reader outer = new Der.Reader(der, offset, length).readSequence();
        int version = outer.readSmallInteger();

        Der.Reader key;
        if (version == 0) {
            // PKCS#8: AlgorithmIdentifier, then the SEC1 structure inside an
            // OCTET STRING. The algorithm is skipped rather than checked here
            // - a key of the wrong curve is caught when the provider imports
            // it, and with a better message than this code could give.
            outer.skipElement();
            Der.Reader inner = outer.readOctetStringAsDer().readSequence();
            if (inner.readSmallInteger() != 1) {
                throw new IllegalArgumentException(
                        "the PKCS#8 file does not contain an EC private key");
            }
            key = inner;
        } else if (version == 1) {
            key = outer;                                   // SEC1, already here
        } else {
            throw new IllegalArgumentException(
                    "unsupported private key structure, version " + version
                    + " - an encrypted key (-----BEGIN ENCRYPTED PRIVATE KEY-----) has to be "
                    + "decrypted first; the 'encrypted' secret provider does that");
        }

        Der.Range scalar = key.readOctetStringRange();
        if (scalar.length() > SCALAR) {
            throw new IllegalArgumentException(
                    "this is not a P-256 key: its private scalar is " + scalar.length()
                    + " bytes, not " + SCALAR);
        }
        // Shorter is legal and happens roughly once in 256 keys: a scalar with
        // a leading zero byte. It is left-padded rather than rejected.
        out.asSlice(0, SCALAR).fill((byte) 0);
        MemorySegment.copy(der, scalar.offset(), out, SCALAR - scalar.length(), scalar.length());
        return SCALAR;
    }

    /** The position just after the {@code -----BEGIN ...-----} line. */
    private static long afterFirstLine(MemorySegment source, int length) {
        long begin = indexOf(source, length, BEGIN, 0);
        if (begin < 0) {
            return 0;
        }
        for (long i = begin; i < length; i++) {
            if (source.get(ValueLayout.JAVA_BYTE, i) == '\n') {
                return i + 1;
            }
        }
        return length;
    }

    /** The position where the {@code -----END ...-----} line starts. */
    private static long beforeEnd(MemorySegment source, int length) {
        long end = indexOf(source, length, END, 0);
        return end < 0 ? length : end;
    }

    private static long indexOf(MemorySegment source, int length, byte[] needle, long from) {
        outer:
        for (long i = from; i + needle.length <= length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (source.get(ValueLayout.JAVA_BYTE, i + j) != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
