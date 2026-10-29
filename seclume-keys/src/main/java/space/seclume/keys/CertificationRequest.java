package space.seclume.keys;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64; // seclume-allow: a public request in PEM

/**
 * A PKCS#10 certification request for a key in OpenSSL, signed by it there.
 *
 * <p>Everything in a request is public - the subject, the public key, the
 * signature - so it is built here, in Java, as DER; only the signature is made
 * where the key is. What it asks for is a common name; the alternative names
 * and the lifetime go to the CA beside it (Vault's {@code alt_names},
 * {@code ttl}), where the CA's role decides what it grants.
 */
final class CertificationRequest {

    /** ecdsa-with-SHA256, 1.2.840.10045.4.3.2. */
    private static final byte[] ECDSA_SHA256 = {0x06, 0x08, 0x2a, (byte) 0x86, 0x48,
        (byte) 0xce, 0x3d, 0x04, 0x03, 0x02};
    /** commonName, 2.5.4.3. */
    private static final byte[] COMMON_NAME = {0x06, 0x03, 0x55, 0x04, 0x03};

    private CertificationRequest() {
    }

    /** The request in DER, for {@code commonName}, signed by {@code key} (EC) with SHA-256. */
    static byte[] der(NativeKey key, String commonName) {
        if (!"EC".equals(key.type)) {
            throw new IllegalArgumentException("a request is signed here with an EC key only");
        }
        if (commonName == null || commonName.isBlank()) {
            throw new IllegalArgumentException("a certificate needs a common name");
        }
        // seclume-allow: a common name, which the certificate publishes
        byte[] name = commonName.getBytes(StandardCharsets.UTF_8);
        byte[] subject = sequence(set(sequence(COMMON_NAME, tlv(0x0c, name))));
        byte[] info = sequence(tlv(0x02, new byte[] {0}), subject,
                key.publicKey.getEncoded(), tlv(0xa0, new byte[0]));
        byte[] signature = key.sign("SHA256", false, info, info.length);
        byte[] bits = new byte[signature.length + 1];
        System.arraycopy(signature, 0, bits, 1, signature.length);
        return sequence(info, sequence(ECDSA_SHA256), tlv(0x03, bits));
    }

    /** The same as PEM, as Vault's {@code csr} parameter takes it. */
    static String pem(NativeKey key, String commonName) {
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
