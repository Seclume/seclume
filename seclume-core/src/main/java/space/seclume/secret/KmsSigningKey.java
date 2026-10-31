package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;
import java.util.Map;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.PrivateSigningKey;

/**
 * A private key that lives in a key management service and signs there -
 * Vault's transit engine ({@code kms=vault-transit}), AWS KMS ({@code aws-kms}),
 * Google Cloud KMS ({@code gcp-kms}), Azure Key Vault or Managed HSM
 * ({@code azure-key-vault}). What the process holds is
 * the public half and a credential to ask with; the key itself is never in it,
 * not in native memory either, and a dump of the whole process finds nothing
 * to steal but a token that expires.
 *
 * <p>It is a {@link PrivateSigningKey} like OpenSSL's and CNG's, so whatever
 * takes one takes this: seclume's own TLS as a database connection's client
 * certificate ({@code clientKey-kms=}), seclume-keys' JSSE key managers and
 * Spring SSL bundles ({@code kms=} in place of {@code provider=}), a
 * certification request ({@link space.seclume.crypto.CertificationRequest}).
 *
 * <p>The message is hashed here and only the hash is sent: the service never
 * sees what is signed, and a TLS transcript of any length is one small
 * request. Each signature is one round trip - and a
 * {@code space.seclume.RemoteSignature} event - so a handshake waits for the
 * service; that suits connections that live long, as pooled ones do, and
 * costs a server that makes many short ones.
 *
 * <p>When it is opened it reads the public half and signs once, checking that
 * signature here: a key name that points elsewhere, a version that is not the
 * certificate's or a token that may not sign fails where it is configured, not
 * in the first handshake. EC keys on P-256 and P-384 and RSA keys are taken.
 */
public final class KmsSigningKey implements PrivateSigningKey {

    /** What a key management service has to do for a key in it. */
    interface Service extends AutoCloseable {

        /** The key as the configuration names it, for messages and recordings. */
        String describe();

        /** The public half, as a DER {@code SubjectPublicKeyInfo}. */
        byte[] publicKey() throws IOException;

        /**
         * Signs {@code hash}, made with {@code digest}: ECDSA in DER, RSA
         * PKCS#1 v1.5 or - with {@code pss} - PSS with a salt as long as the
         * hash.
         */
        byte[] sign(HashAlgorithm digest, boolean pss, byte[] hash) throws IOException;

        /** Whether an RSA key signs with PSS - one bound to PKCS#1 v1.5 does not. */
        default boolean signsPss() {
            return true;
        }

        @Override
        void close();
    }

    /** The settings that name the service. */
    public static final String KMS = "kms";

    private static final int MAX_SIGNATURE = 1024;

    private final Service service;
    private final String name;
    private final byte[] publicKey;
    private final String type;
    private final int bits;
    private volatile boolean closed;

    private KmsSigningKey(Service service, byte[] publicKey) {
        this.service = service;
        this.name = service.describe();
        this.publicKey = publicKey.clone();
        PublicKey parsed = parse(publicKey);
        if (parsed instanceof ECPublicKey ec) {
            this.type = "EC";
            this.bits = ec.getParams().getCurve().getField().getFieldSize();
            if (bits != 256 && bits != 384) {
                throw new IllegalArgumentException(name + " is an EC key on a " + bits
                        + "-bit curve; P-256 and P-384 are what TLS client and server "
                        + "certificates use and what is taken here");
            }
        } else if (parsed instanceof RSAPublicKey rsa) {
            this.type = "RSA";
            this.bits = rsa.getModulus().bitLength();
            if (bits < 2048) {
                throw new IllegalArgumentException(name + " is an RSA key of " + bits
                        + " bits; 2048 is the least that is taken");
            }
        } else {
            throw new IllegalArgumentException(name + " is a " + parsed.getAlgorithm()
                    + " key - EC (P-256, P-384) and RSA keys are taken");
        }
    }

    /**
     * The key {@code settings} name: {@code kms} says which service
     * ({@code vault-transit}), the rest are that service's settings. Reads the
     * public half and checks a signature before it returns.
     */
    public static KmsSigningKey of(Map<String, String> settings) {
        String kms = settings.get(KMS);
        if (kms == null || kms.isBlank()) {
            throw new IllegalArgumentException("no key management service named: kms="
                    + "vault-transit, aws-kms, gcp-kms or azure-key-vault, with the key's "
                    + "settings beside it");
        }
        Service service = switch (kms.trim().toLowerCase(Locale.ROOT)) {
            case "vault-transit", "vaulttransit", "transit", "vault", "openbao" ->
                    new VaultTransitKey(settings);
            case "aws-kms", "awskms", "aws" -> new AwsKmsKey(settings);
            case "gcp-kms", "gcpkms", "gcp", "google" -> new GcpKmsKey(settings);
            case "azure-key-vault", "azurekeyvault", "azure" -> new AzureKeyVaultKey(settings);
            default -> throw new IllegalArgumentException("kms is vault-transit, aws-kms, "
                    + "gcp-kms or azure-key-vault, not '" + kms + "'");
        };
        return open(service);
    }

    /** Reads the public half of {@code service}'s key and proves that it signs as that key. */
    static KmsSigningKey open(Service service) {
        try {
            KmsSigningKey key = new KmsSigningKey(service, service.publicKey());
            key.selfTest();
            space.seclume.inventory.CryptoInventory.privateKey(key, key.publicKey,
                    service.describe());
            return key;
        } catch (IOException e) {
            service.close();
            throw new IllegalArgumentException(service.describe() + " cannot be used: "
                    + e.getMessage(), e);
        } catch (RuntimeException e) {
            service.close();
            throw e;
        }
    }

    /**
     * Signs a fixed message the way a handshake will and checks the result
     * against the public half - the one thing that would otherwise first go
     * wrong in front of a peer.
     */
    private void selfTest() throws IOException {
        byte[] message = "seclume: does this key sign as its public half says?"
                .getBytes(StandardCharsets.US_ASCII); // seclume-allow: a constant text, no secret
        HashAlgorithm digest = bits == 384 ? HashAlgorithm.SHA_384 : HashAlgorithm.SHA_256;
        boolean pss = type.equals("RSA") && service.signsPss();
        byte[] signature = service.sign(digest, pss, hash(digest, message));
        // The verification TLS itself uses, on public data.
        int scheme = type.equals("EC")
                ? (bits == 384 ? space.seclume.tls.HandshakeSignature.ECDSA_SECP384R1_SHA384
                        : space.seclume.tls.HandshakeSignature.ECDSA_SECP256R1_SHA256)
                : pss ? space.seclume.tls.HandshakeSignature.RSA_PSS_RSAE_SHA256
                        : space.seclume.tls.HandshakeSignature.RSA_PKCS1_SHA256;
        if (!space.seclume.tls.HandshakeSignature.verifyTls12(parse(publicKey), scheme, message,
                signature)) {
            throw new IOException("its signature does not verify with the public key it "
                    + "gave - a different key or version answered");
        }
    }

    private static PublicKey parse(byte[] spki) {
        for (String algorithm : new String[] {"EC", "RSA", "Ed25519"}) {
            try {
                return KeyFactory.getInstance(algorithm)
                        .generatePublic(new X509EncodedKeySpec(spki));
            } catch (GeneralSecurityException notThisOne) {
                // the next one
            }
        }
        throw new IllegalArgumentException("the public key the service gave is neither EC, "
                + "RSA nor Ed25519");
    }

    private static byte[] hash(HashAlgorithm digest, byte[] message) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment in = arena.allocate(Math.max(1, message.length));
            MemorySegment.copy(message, 0, in, ValueLayout.JAVA_BYTE, 0, message.length);
            MemorySegment out = arena.allocate(digest.digestLength());
            digest.hash(in, 0, message.length, out, 0);
            return out.toArray(ValueLayout.JAVA_BYTE);
        }
    }

    /**
     * An ECDSA signature as IEEE P1363 - r and s, each as long as the curve -
     * in DER, which TLS and the JDK take: what Azure Key Vault answers.
     */
    static byte[] derFromRaw(byte[] raw) throws IOException {
        if (raw.length == 0 || raw.length % 2 != 0 || raw.length > 132) {
            throw new IOException("an ECDSA signature of " + raw.length + " bytes is not r "
                    + "and s of one length");
        }
        int half = raw.length / 2;
        byte[] r = integer(raw, 0, half);
        byte[] s = integer(raw, half, half);
        java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
        body.write(r, 0, r.length);
        body.write(s, 0, s.length);
        return tlv(0x30, body.toByteArray());
    }

    private static byte[] integer(byte[] raw, int from, int length) {
        int start = from;
        while (start < from + length - 1 && raw[start] == 0) {
            start++;
        }
        boolean pad = (raw[start] & 0x80) != 0;
        byte[] value = new byte[from + length - start + (pad ? 1 : 0)];
        System.arraycopy(raw, start, value, pad ? 1 : 0, from + length - start);
        return tlv(0x02, value);
    }

    private static byte[] tlv(int tag, byte[] value) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write(tag);
        if (value.length < 0x80) {
            out.write(value.length);
        } else {
            out.write(0x81);
            out.write(value.length);
        }
        out.write(value, 0, value.length);
        return out.toByteArray();
    }

    /** {@code host} or {@code host:port} of an https endpoint setting - 443 by default. */
    static String[] endpoint(String value, String fallbackHost) {
        String endpoint = value == null || value.isBlank() ? fallbackHost : value.trim();
        if (endpoint.startsWith("https://")) {
            endpoint = endpoint.substring("https://".length());
        } else if (endpoint.contains("://")) {
            throw new IllegalArgumentException("a key service is reached over https, not "
                    + endpoint);
        }
        while (endpoint.endsWith("/")) {
            endpoint = endpoint.substring(0, endpoint.length() - 1);
        }
        int colon = endpoint.lastIndexOf(':');
        return colon > 0 ? new String[] {endpoint.substring(0, colon),
            endpoint.substring(colon + 1)} : new String[] {endpoint, "443"};
    }

    /** A positive whole-number setting, {@code fallback} when it is left out. */
    static int positive(Map<String, String> settings, String name, int fallback) {
        String value = settings.get(name);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed > 0) {
                return parsed;
            }
        } catch (NumberFormatException e) {
            // said below
        }
        throw new IllegalArgumentException(name + " is a positive whole number, not " + value);
    }

    /** A setting the key cannot do without. */
    static String required(Map<String, String> settings, String name, String service) {
        String value = settings.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("a key in " + service + " needs " + name);
        }
        return value.trim();
    }

    /** The key as configured: service, name, version. */
    public String name() {
        return name;
    }

    @Override
    public boolean is(String type) {
        return this.type.equalsIgnoreCase(type);
    }

    @Override
    public byte[] publicKey() {
        return publicKey.clone();
    }

    @Override
    public int sign(String digest, boolean pss, MemorySegment message, long length,
            MemorySegment signature) {
        if (closed) {
            throw new IllegalStateException(name + " is closed and signs nothing more");
        }
        HashAlgorithm algorithm = switch (digest.toUpperCase(Locale.ROOT).replace("-", "")) {
            case "SHA256" -> HashAlgorithm.SHA_256;
            case "SHA384" -> HashAlgorithm.SHA_384;
            case "SHA512" -> HashAlgorithm.SHA_512;
            default -> throw new IllegalArgumentException("a key in a key management service "
                    + "signs SHA256, SHA384 or SHA512, not " + digest);
        };
        if (pss && !type.equals("RSA")) {
            throw new IllegalArgumentException("PSS is an RSA padding, and " + name
                    + " is an EC key");
        }
        byte[] hash;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(algorithm.digestLength());
            algorithm.hash(message, 0, length, out, 0);
            hash = out.toArray(ValueLayout.JAVA_BYTE);
        }
        space.seclume.jfr.SeclumeEvents.RemoteSignature event =
                space.seclume.jfr.Observed.beginRemoteSignature();
        try {
            byte[] made = service.sign(algorithm, pss, hash);
            if (made.length > signature.byteSize() || made.length > MAX_SIGNATURE) {
                throw new IOException("its signature is " + made.length + " bytes, more than "
                        + "the " + signature.byteSize() + " there is room for");
            }
            MemorySegment.copy(made, 0, signature, ValueLayout.JAVA_BYTE, 0, made.length);
            space.seclume.jfr.Observed.endRemoteSignature(event, name, digest, true, null);
            return made.length;
        } catch (IOException | RuntimeException e) {
            space.seclume.jfr.Observed.endRemoteSignature(event, name, digest, false,
                    e.getMessage());
            throw new IllegalStateException(name + " did not sign: " + e.getMessage(), e);
        }
    }

    /** Lets go of the credential; the key stays where it is. */
    @Override
    public void close() {
        if (!closed) {
            closed = true;
            service.close();
        }
    }

    @Override
    public String toString() {
        return name;
    }
}
