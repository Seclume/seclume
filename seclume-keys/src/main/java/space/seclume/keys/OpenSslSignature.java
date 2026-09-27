package space.seclume.keys;

import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Locale;

/**
 * Signing with an {@link OpenSslPrivateKey}: the message is collected here -
 * it is public, a TLS transcript hash or what an SSH server asks to have
 * signed - and signed in OpenSSL, where the key is.
 *
 * <p>Only signing. Verifying needs no secret and stays with the JDK's
 * providers; this one refuses public keys, and JCA moves on to them.
 */
final class OpenSslSignature extends SignatureSpi {

    private final String keyType;
    private final boolean pss;
    private String digest;                 // for RSASSA-PSS, from the parameters
    private int saltLength;
    private NativeKey key;
    private final ByteArrayOutputStream data = new ByteArrayOutputStream();

    /**
     * @param keyType {@code RSA}, {@code EC} or {@code Ed25519}
     * @param digest  {@code SHA256}, {@code SHA384}, {@code SHA512}; {@code null}
     *                for RSASSA-PSS, which takes it from its parameters, and
     *                for Ed25519, which has none
     */
    OpenSslSignature(String keyType, String digest) {
        this.keyType = keyType;
        this.pss = digest == null && keyType.equals("RSA");
        this.digest = digest;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof OpenSslPrivateKey opaque)) {
            throw new InvalidKeyException("this provider signs only with keys it holds in "
                    + "OpenSSL, not with a " + (privateKey == null ? "null key"
                    : privateKey.getClass().getName()));
        }
        if (!opaque.nativeKey().type.equals(keyType)) {
            throw new InvalidKeyException("this signature needs an " + keyType + " key, not "
                    + "an " + opaque.getAlgorithm() + " key");
        }
        this.key = opaque.nativeKey();
        data.reset();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        throw new InvalidKeyException("this provider only signs; verifying is the JDK's");
    }

    @Override
    protected void engineUpdate(byte b) {
        data.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
        data.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (key == null) {
            throw new SignatureException("not initialized for signing");
        }
        if (digest == null && pss) {
            throw new SignatureException("RSASSA-PSS needs its parameters (PSSParameterSpec) "
                    + "before signing");
        }
        byte[] message = data.toByteArray();
        data.reset();
        try {
            return key.sign(digest, pss, message, message.length);
        } catch (RuntimeException e) {
            throw new SignatureException(e.getMessage(), e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        throw new SignatureException("this provider only signs; verifying is the JDK's");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (!pss) {
            if (params != null) {
                throw new InvalidAlgorithmParameterException("this signature takes no "
                        + "parameters");
            }
            return;
        }
        if (!(params instanceof PSSParameterSpec spec)) {
            throw new InvalidAlgorithmParameterException("RSASSA-PSS takes a "
                    + "PSSParameterSpec");
        }
        String name = spec.getDigestAlgorithm().toUpperCase(Locale.ROOT).replace("-", "");
        int length = switch (name) {
            case "SHA256" -> 32;
            case "SHA384" -> 48;
            case "SHA512" -> 64;
            default -> throw new InvalidAlgorithmParameterException("RSASSA-PSS with "
                    + spec.getDigestAlgorithm() + " is not made here - SHA-256, SHA-384 or "
                    + "SHA-512");
        };
        boolean sameMgf = "MGF1".equalsIgnoreCase(spec.getMGFAlgorithm())
                && spec.getMGFParameters() instanceof MGF1ParameterSpec mgf
                && mgf.getDigestAlgorithm().toUpperCase(Locale.ROOT).replace("-", "")
                        .equals(name);
        if (!sameMgf || spec.getSaltLength() != length
                || spec.getTrailerField() != PSSParameterSpec.TRAILER_FIELD_BC) {
            throw new InvalidAlgorithmParameterException("RSASSA-PSS is made here with MGF1 "
                    + "of the same digest and a salt as long as the digest - as TLS 1.3 and "
                    + "JWS use it");
        }
        this.digest = name;
        this.saltLength = length;
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) {
        throw new InvalidParameterException("no parameters by name");
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String param) {
        throw new InvalidParameterException("no parameters by name");
    }

    @Override
    public String toString() {
        return "OpenSSL " + keyType + (pss ? " PSS/" + digest + "/salt " + saltLength
                : "/" + digest);
    }
}
