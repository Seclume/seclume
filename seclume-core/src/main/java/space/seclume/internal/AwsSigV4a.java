package space.seclume.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Hmac;
import space.seclume.crypto.OpenSslSigningKey;

/**
 * AWS Signature Version 4a: the same canonical request as SigV4, signed with
 * ECDSA P-256 instead of an HMAC chain, so that one signature is valid in
 * several regions - S3 multi-region access points need it.
 *
 * <p>The ECDSA key is not a key anyone holds: it is derived from the secret
 * key, as AWS's own libraries derive it (NIST SP 800-108 in counter mode with
 * HMAC-SHA256, the key {@code AWS4A + secret}, the label
 * {@code AWS4-ECDSA-P256-SHA256}, the access key id and a counter that moves
 * on while the candidate is not below the curve order less one). The secret,
 * the HMAC's input key, the candidate and the scalar are native memory, wiped
 * before this returns; the scalar goes to OpenSSL as a SEC 1 key without its
 * public point, which OpenSSL computes as it reads it, and signs there.
 *
 * <p>So, like seclume's other signing with a private key, OpenSSL 3 on
 * 64-bit Linux - {@link #available()}. The signature is public.
 */
public final class AwsSigV4a {

    public static final String ALGORITHM = "AWS4-ECDSA-P256-SHA256";

    private static final int MAX_KEY_BYTES = 256;
    /** P-256's order less two, big-endian: a candidate above it is skipped. */
    private static final byte[] ORDER_MINUS_TWO = java.util.HexFormat.of().parseHex( // seclume-allow: the curve's public order
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f");
    /** {@code ECPrivateKey} of SEC 1 up to the scalar, and the P-256 parameters after it. */
    private static final byte[] SEC1_HEAD = {0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20}; // seclume-allow: DER framing, public
    private static final byte[] SEC1_TAIL = {(byte) 0xa0, 0x0a, 0x06, 0x08, 0x2a, (byte) 0x86, // seclume-allow: the P-256 OID, public
            0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07};

    private AwsSigV4a() {
    }

    /** Whether SigV4a can be signed here: OpenSSL 3 on 64-bit Linux. */
    public static boolean available() {
        return OpenSslSigningKey.available();
    }

    /** The scope of a SigV4a signature: no region in it - the region set is a header. */
    public static String scope(String day, String service) {
        return day + "/" + service + "/" + AwsSigV4.TERMINATOR;
    }

    /**
     * Signs {@code toSign} with the key derived from the secret key and the
     * access key id; @return the DER signature in hex, as the
     * {@code Authorization} header carries it.
     */
    public static String sign(AwsSigV4.SecretKey secretKey, String accessKeyId, String toSign) {
        try (Arena arena = Arena.ofConfined();
             OpenSslSigningKey key = derive(arena, secretKey, accessKeyId)) {
            MemorySegment message = arena.allocate(toSign.length() * 3L + 1);
            int length = AwsSigV4.writeAscii(message, toSign);
            MemorySegment signature = arena.allocate(OpenSslSigningKey.MAX_SIGNATURE);
            int written = key.sign("SHA256", false, message, length, signature);
            return AwsSigV4.hex(signature.asSlice(0, written));
        }
    }

    /**
     * The derived key's public half, a DER {@code SubjectPublicKeyInfo} -
     * what AWS's test vectors give, and so what a test compares.
     */
    public static byte[] publicKey(AwsSigV4.SecretKey secretKey, String accessKeyId) {
        try (Arena arena = Arena.ofConfined();
             OpenSslSigningKey key = derive(arena, secretKey, accessKeyId)) {
            return key.publicKey();
        }
    }

    private static OpenSslSigningKey derive(Arena arena, AwsSigV4.SecretKey secretKey,
            String accessKeyId) {
        if (!available()) {
            throw new UnsupportedOperationException("SigV4a signs with ECDSA through OpenSSL 3, "
                    + "on 64-bit Linux only - as seclume's other signing with a private key");
        }
        MemorySegment secret = arena.allocate(MAX_KEY_BYTES);
        MemorySegment input = arena.allocate(5 + MAX_KEY_BYTES);
        MemorySegment candidate = arena.allocate(32);
        MemorySegment der = arena.allocate(SEC1_HEAD.length + 32 + SEC1_TAIL.length);
        try {
            int length = secretKey.write(secret);
            if (length <= 0) {
                throw new IllegalStateException("the AWS secret key source gave nothing - "
                        + "nothing can be signed without it");
            }
            AwsSigV4.writeAscii(input, "AWS4A");
            MemorySegment.copy(secret, 0, input, 5, length);
            MemorySegment fixed = arena.allocate(4 + 64 + accessKeyId.length() * 3L + 6);
            for (int counter = 1; counter <= 254; counter++) {
                // 1 (the KDF's own counter, one block) || label || 0 || id || counter || 256
                int at = 0;
                fixed.set(ValueLayout.JAVA_INT_UNALIGNED.withOrder(java.nio.ByteOrder.BIG_ENDIAN),
                        at, 1);
                at += 4;
                at += AwsSigV4.writeAscii(fixed.asSlice(at), ALGORITHM);
                fixed.set(ValueLayout.JAVA_BYTE, at++, (byte) 0);
                at += AwsSigV4.writeAscii(fixed.asSlice(at), accessKeyId);
                fixed.set(ValueLayout.JAVA_BYTE, at++, (byte) counter);
                fixed.set(ValueLayout.JAVA_INT_UNALIGNED.withOrder(java.nio.ByteOrder.BIG_ENDIAN),
                        at, 256);
                at += 4;
                try (Hmac mac = new Hmac(HashAlgorithm.SHA_256, input, 0, 5 + length)) {
                    mac.update(fixed, 0, at);
                    mac.doFinal(candidate, 0);
                }
                if (!above(candidate)) {
                    break;
                }
                if (counter == 254) {
                    throw new IllegalStateException("no SigV4a key could be derived");
                }
            }
            addOne(candidate);
            MemorySegment.copy(SEC1_HEAD, 0, der, ValueLayout.JAVA_BYTE, 0, SEC1_HEAD.length);
            MemorySegment.copy(candidate, 0, der, SEC1_HEAD.length, 32);
            MemorySegment.copy(SEC1_TAIL, 0, der, ValueLayout.JAVA_BYTE, SEC1_HEAD.length + 32,
                    SEC1_TAIL.length);
            return OpenSslSigningKey.decode(der, (int) der.byteSize());
        } finally {
            secret.fill((byte) 0);
            input.fill((byte) 0);
            candidate.fill((byte) 0);
            der.fill((byte) 0);
        }
    }

    /**
     * Whether the candidate is above the order less two - every byte looked
     * at, whatever the first difference: the comparison is on key material.
     */
    private static boolean above(MemorySegment candidate) {
        int borrow = 0;
        for (int i = 31; i >= 0; i--) {
            int difference = (ORDER_MINUS_TWO[i] & 0xff)
                    - (candidate.get(ValueLayout.JAVA_BYTE, i) & 0xff) - borrow;
            borrow = (difference >> 31) & 1;
        }
        return borrow == 1;                    // order - 2 - candidate went below zero
    }

    /** {@code candidate + 1}, which cannot carry out: the candidate is below the order. */
    private static void addOne(MemorySegment candidate) {
        int carry = 1;
        for (int i = 31; i >= 0; i--) {
            int sum = (candidate.get(ValueLayout.JAVA_BYTE, i) & 0xff) + carry;
            candidate.set(ValueLayout.JAVA_BYTE, i, (byte) sum);
            carry = sum >> 8;
        }
    }
}
