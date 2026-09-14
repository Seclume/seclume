package space.seclume.crypto;

import java.lang.foreign.MemorySegment;

/**
 * The hash algorithms the four handshakes need.
 *
 * <p>MD5 and SHA-1 are not here out of carelessness: PostgreSQL's {@code md5}
 * authentication, MySQL's {@code mysql_native_password} and Oracle's O5LOGON
 * for 11g all require them. Without them you cannot log in to existing servers.
 */
public enum HashAlgorithm {

    MD5(16, 64),
    SHA_1(20, 64),
    SHA_256(32, 64),
    SHA_384(48, 128),
    SHA_512(64, 128);

    private final int digestLength;
    private final int blockLength;

    HashAlgorithm(int digestLength, int blockLength) {
        this.digestLength = digestLength;
        this.blockLength = blockLength;
    }

    public int digestLength() {
        return digestLength;
    }

    public int blockLength() {
        return blockLength;
    }

    /** A fresh digest. The caller closes it. */
    public Digest newDigest() {
        return switch (this) {
            case MD5 -> new Md5Digest();
            case SHA_1 -> new Sha1Digest();
            case SHA_256 -> new Sha256Digest();
            case SHA_384 -> new Sha384Digest();
            case SHA_512 -> new Sha512Digest();
        };
    }

    /**
     * A one-shot hash over a segment - for the many places where a handshake
     * needs exactly one hash.
     */
    public void hash(MemorySegment data, long offset, long length,
                     MemorySegment out, long outOffset) {
        try (Digest digest = newDigest()) {
            digest.update(data, offset, length);
            digest.digest(out, outOffset);
        }
    }
}
