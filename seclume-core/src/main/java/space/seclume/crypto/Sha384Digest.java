package space.seclume.crypto;

/**
 * SHA-384: SHA-512 with different starting values, cut to 48 bytes.
 *
 * <p>FIPS 180-4 section 5.3.4. Nothing else about the function changes - same
 * block size, same constants, same rounds - so everything is inherited and
 * only the two things that differ are here.
 */
final class Sha384Digest extends Sha512Digest {

    @Override
    public int digestLength() {
        return 48;
    }

    @Override
    long[] initialHash() {
        return new long[] {
            0xcbbb9d5dc1059ed8L, 0x629a292a367cd507L, 0x9159015a3070dd17L, 0x152fecd8f70e5939L,
            0x67332667ffc00b31L, 0x8eb44a8768581511L, 0xdb0c2e0d64f98fa7L, 0x47b5481dbefa4fa4L,
        };
    }
}
