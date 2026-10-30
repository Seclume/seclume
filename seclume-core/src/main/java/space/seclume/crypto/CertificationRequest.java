package space.seclume.crypto;

import java.io.ByteArrayOutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Base64; // seclume-allow: a public request in PEM

/**
 * A PKCS#10 certification request for a {@link PrivateSigningKey}, signed by
 * it where it lives.
 *
 * <p>Everything in a request is public - the subject, the public key, the
 * signature - so it is built here, in Java, as DER; only the signature is made
 * where the key is. What it asks for is a common name; the alternative names
 * and the lifetime go to the CA beside it (Vault's {@code alt_names},
 * {@code ttl}), where the CA's role decides what it grants.
 */
public final class CertificationRequest {

    /** ecdsa-with-SHA256, 1.2.840.10045.4.3.2. */
    private static final byte[] ECDSA_SHA256 = {0x06, 0x08, 0x2a, (byte) 0x86, 0x48,
        (byte) 0xce, 0x3d, 0x04, 0x03, 0x02};
    /** ecdsa-with-SHA384, 1.2.840.10045.4.3.3. */
    private static final byte[] ECDSA_SHA384 = {0x06, 0x08, 0x2a, (byte) 0x86, 0x48,
        (byte) 0xce, 0x3d, 0x04, 0x03, 0x03};
    /** sha256WithRSAEncryption, 1.2.840.113549.1.1.11, and its NULL parameters. */
    private static final byte[] RSA_SHA256 = {0x06, 0x09, 0x2a, (byte) 0x86, 0x48,
        (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00};
    /** commonName, 2.5.4.3. */
    private static final byte[] COMMON_NAME = {0x06, 0x03, 0x55, 0x04, 0x03};

    private CertificationRequest() {
    }

    /**
     * The request in DER, for {@code commonName}, signed by {@code key}: an EC
     * key with SHA-256 - with SHA-384 on P-384, which is the only hash a cloud
     * KMS lets such a key sign - and an RSA key with SHA-256, PKCS#1 v1.5.
     */
    public static byte[] der(PrivateSigningKey key, String commonName) {
        boolean rsa = key.is("RSA");
        if (!rsa && !key.is("EC")) {
            throw new IllegalArgumentException("a request is signed here with an EC or RSA "
                    + "key only");
        }
        boolean p384 = !rsa && fieldSize(key.publicKey()) == 384;
        if (commonName == null || commonName.isBlank()) {
            throw new IllegalArgumentException("a certificate needs a common name");
        }
        // seclume-allow: a common name, which the certificate publishes
        byte[] name = commonName.getBytes(StandardCharsets.UTF_8);
        byte[] subject = sequence(set(sequence(COMMON_NAME, tlv(0x0c, name))));
        byte[] info = sequence(tlv(0x02, new byte[] {0}), subject, key.publicKey(),
                tlv(0xa0, new byte[0]));
        byte[] bits;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment message = arena.allocate(info.length);
            MemorySegment.copy(info, 0, message, ValueLayout.JAVA_BYTE, 0, info.length);
            MemorySegment out = arena.allocate(PrivateSigningKey.MAX_SIGNATURE);
            int written = key.sign(p384 ? "SHA384" : "SHA256", false, message, info.length,
                    out);
            bits = new byte[written + 1];
            MemorySegment.copy(out, ValueLayout.JAVA_BYTE, 0, bits, 1, written);
        }
        return sequence(info, sequence(rsa ? RSA_SHA256 : p384 ? ECDSA_SHA384 : ECDSA_SHA256),
                tlv(0x03, bits));
    }

    private static int fieldSize(byte[] spki) {
        try {
            java.security.PublicKey parsed = java.security.KeyFactory.getInstance("EC")
                    .generatePublic(new java.security.spec.X509EncodedKeySpec(spki));
            return ((java.security.interfaces.ECPublicKey) parsed).getParams().getCurve()
                    .getField().getFieldSize();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalArgumentException("the key's public half is no EC key the JDK "
                    + "reads", e);
        }
    }

    /** The same as PEM, as Vault's {@code csr} parameter takes it. */
    public static String pem(PrivateSigningKey key, String commonName) {
        return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}) // seclume-allow: a public request
                        .encodeToString(der(key, commonName))
                + "\n-----END CERTIFICATE REQUEST-----\n";
    }

    private static byte[] sequence(byte[]... parts) {
        return tlv(0x30, concat(parts));
    }

    private static byte[] set(byte[]... parts) {
        return tlv(0x31, concat(parts));
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.write(part, 0, part.length);
        }
        return out.toByteArray();
    }

    static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        int length = value.length;
        if (length < 0x80) {
            out.write(length);
        } else if (length < 0x100) {
            out.write(0x81);
            out.write(length);
        } else if (length < 0x10000) {
            out.write(0x82);
            out.write(length >>> 8);
            out.write(length & 0xff);
        } else {
            throw new IllegalArgumentException("longer than a request ever is");
        }
        out.write(value, 0, value.length);
        return out.toByteArray();
    }
}
