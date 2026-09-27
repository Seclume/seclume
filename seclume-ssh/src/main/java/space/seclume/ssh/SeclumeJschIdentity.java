package space.seclume.ssh;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger; // seclume-allow: an RSA public key's exponent and modulus - public
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import com.jcraft.jsch.Identity;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;

/**
 * A JSch identity whose private key stays in OpenSSL - Ed25519, ECDSA or RSA.
 *
 * <pre>
 * JSch jsch = new JSch();
 * SeclumeJschIdentity.add(jsch, "provider=file&amp;path=/run/secrets/id_ed25519");
 * </pre>
 *
 * <p>JSch reads a key file itself and keeps the key's bytes; with this identity
 * it asks for signatures instead, which are made through seclume's JCA
 * provider. The key file may be in OpenSSH's own format, PEM or DER. RSA signs
 * {@code rsa-sha2-256} and {@code rsa-sha2-512}; SHA-1 {@code ssh-rsa} is not
 * offered.
 */
public final class SeclumeJschIdentity implements Identity {

    private final KeyPair pair;
    private final String algorithm;
    private final byte[] publicKeyBlob;
    private final String name;

    private SeclumeJschIdentity(KeyPair pair, String name) {
        this.pair = pair;
        this.name = name;
        PublicKey key = pair.getPublic();
        if (key instanceof EdECPublicKey) {
            algorithm = "ssh-ed25519";
            byte[] encoded = key.getEncoded();
            publicKeyBlob = blob(text(algorithm), string(Arrays.copyOfRange(encoded,
                    encoded.length - 32, encoded.length)));
        } else if (key instanceof ECPublicKey ec) {
            int field = (ec.getParams().getCurve().getField().getFieldSize() + 7) / 8;
            String curve = switch (field) {
                case 32 -> "nistp256";
                case 48 -> "nistp384";
                case 66 -> "nistp521";
                default -> throw new IllegalArgumentException("an EC key on a curve SSH does "
                        + "not name");
            };
            algorithm = "ecdsa-sha2-" + curve;
            byte[] encoded = key.getEncoded();
            byte[] point = Arrays.copyOfRange(encoded, encoded.length - (1 + 2 * field),
                    encoded.length);
            publicKeyBlob = blob(text(algorithm), text(curve), string(point));
        } else if (key instanceof RSAPublicKey rsa) {
            algorithm = "ssh-rsa";
            publicKeyBlob = blob(text(algorithm), mpint(rsa.getPublicExponent()),
                    mpint(rsa.getModulus()));
        } else {
            throw new IllegalArgumentException("a " + key.getAlgorithm() + " key is not an SSH "
                    + "key here - Ed25519, ECDSA and RSA are");
        }
    }

    /** The key named by {@code keySpec}, the secret provider's options. */
    public static SeclumeJschIdentity of(String keySpec) {
        return new SeclumeJschIdentity(SeclumeSsh.keyPair(keySpec), "seclume");
    }

    /** Adds the key to {@code jsch}, for all its sessions. */
    public static SeclumeJschIdentity add(JSch jsch, String keySpec) throws JSchException {
        SeclumeJschIdentity identity = of(keySpec);
        jsch.addIdentity(identity, null);
        return identity;
    }

    @Override
    public byte[] getPublicKeyBlob() {
        return publicKeyBlob.clone();
    }

    @Override
    public byte[] getSignature(byte[] data) {
        return getSignature(data, algorithm.equals("ssh-rsa") ? "rsa-sha2-512" : algorithm);
    }

    @Override
    public byte[] getSignature(byte[] data, String alg) {
        try {
            String jca = switch (alg) {
                case "ssh-ed25519" -> "Ed25519";
                case "ecdsa-sha2-nistp256" -> "SHA256withECDSA";
                case "ecdsa-sha2-nistp384" -> "SHA384withECDSA";
                case "ecdsa-sha2-nistp521" -> "SHA512withECDSA";
                case "rsa-sha2-256" -> "SHA256withRSA";
                case "rsa-sha2-512" -> "SHA512withRSA";
                default -> null;                     // ssh-rsa (SHA-1) and anything unknown
            };
            if (jca == null) {
                return null;
            }
            Signature signer = Signature.getInstance(jca);
            signer.initSign(pair.getPrivate());
            signer.update(data);
            byte[] signature = signer.sign();
            if (alg.startsWith("ecdsa-")) {
                signature = ecdsa(signature);
            }
            return blob(text(alg), string(signature));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("the SSH signature could not be made", e);
        }
    }

    @Override
    public boolean setPassphrase(byte[] passphrase) {
        return true;                                 // nothing is encrypted here
    }

    @Override
    public String getAlgName() {
        return algorithm;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public boolean isEncrypted() {
        return false;
    }

    @Override
    public void clear() {
        // the key lives in OpenSSL until the application ends
    }

    /** DER {@code SEQUENCE { r, s }} to SSH's {@code mpint r, mpint s}. */
    private static byte[] ecdsa(byte[] der) {
        int at = 2;
        if ((der[1] & 0x80) != 0) {
            at = 2 + (der[1] & 0x7f);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int part = 0; part < 2; part++) {
            int length = der[at + 1] & 0xff;
            byte[] integer = Arrays.copyOfRange(der, at + 2, at + 2 + length);
            out.writeBytes(string(integer));
            at += 2 + length;
        }
        return out.toByteArray();
    }

    private static byte[] text(String value) {
        return string(value.getBytes(StandardCharsets.US_ASCII)); // seclume-allow: an algorithm name
    }

    private static byte[] string(byte[] value) {
        byte[] out = new byte[4 + value.length];
        out[0] = (byte) (value.length >>> 24);
        out[1] = (byte) (value.length >>> 16);
        out[2] = (byte) (value.length >>> 8);
        out[3] = (byte) value.length;
        System.arraycopy(value, 0, out, 4, value.length);
        return out;
    }

    private static byte[] mpint(BigInteger value) { // seclume-allow: a public exponent or modulus
        return string(value.toByteArray());
    }

    private static byte[] blob(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }
}
