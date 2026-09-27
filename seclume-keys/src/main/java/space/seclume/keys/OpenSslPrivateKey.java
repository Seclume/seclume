package space.seclume.keys;

import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.math.BigInteger; // seclume-allow: the public modulus, which a certificate carries anyway
import java.security.PrivateKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;

import javax.security.auth.Destroyable;

/**
 * A private key whose secret parts are not in this object: they are in
 * OpenSSL's memory, and signing goes there through {@link SeclumeKeyProvider}.
 *
 * <p>What Java code can ask of it is only what is public anyway - the
 * algorithm, the modulus of an RSA key, the curve of an EC key (JSSE picks its
 * signature scheme and checks key sizes with them). {@link #getEncoded()} is
 * {@code null}, as for a key in a hardware module: whoever needs the bytes
 * cannot have them, and says so instead of quietly copying the key.
 *
 * <p>RSA keys are {@link RSAKey}, EC keys {@link ECKey} - never
 * {@code RSAPrivateKey} or {@code ECPrivateKey}, whose getters are the secret.
 * That is also what keeps the JDK's own providers from taking this key: they
 * declare those interfaces as what they support, and JCA moves on to this one.
 */
public abstract sealed class OpenSslPrivateKey implements PrivateKey, Destroyable
        permits OpenSslPrivateKey.Rsa, OpenSslPrivateKey.Ec, OpenSslPrivateKey.Ed {

    @Serial
    private static final long serialVersionUID = 1L;

    private final transient NativeKey key;

    OpenSslPrivateKey(NativeKey key) {
        this.key = key;
    }

    static OpenSslPrivateKey of(NativeKey key) {
        return switch (key.type) {
            case "RSA" -> new Rsa(key);
            case "EC" -> new Ec(key);
            default -> new Ed(key);
        };
    }

    NativeKey nativeKey() {
        return key;
    }

    @Override
    public String getAlgorithm() {
        return key.type;
    }

    /** {@code null}: the encoding is the secret, and it is not here. */
    @Override
    public String getFormat() {
        return null;
    }

    /** {@code null}: the encoding is the secret, and it is not here. */
    @Override
    public byte[] getEncoded() {
        return null;
    }

    /** Frees the key in OpenSSL; signing with it afterwards fails. */
    @Override
    public void destroy() {
        key.destroy();
    }

    @Override
    public boolean isDestroyed() {
        return key.isDestroyed();
    }

    @Serial
    private void writeObject(ObjectOutputStream out) throws NotSerializableException {
        throw new NotSerializableException("a key in OpenSSL's memory is not serialized - "
                + "that would be the one way to get it onto the heap");
    }

    @Override
    public String toString() {
        return getAlgorithm() + " private key in OpenSSL's memory";
    }

    /** An RSA key: its modulus, which is public, and nothing else. */
    static final class Rsa extends OpenSslPrivateKey implements RSAKey {

        @Serial
        private static final long serialVersionUID = 1L;

        Rsa(NativeKey key) {
            super(key);
        }

        @Override
        public BigInteger getModulus() { // seclume-allow: the public modulus
            return ((RSAPublicKey) nativeKey().publicKey).getModulus();
        }

        @Override
        public AlgorithmParameterSpec getParams() {
            return ((RSAPublicKey) nativeKey().publicKey).getParams();
        }
    }

    /** An Ed25519 key: its curve's name, and nothing else. */
    static final class Ed extends OpenSslPrivateKey implements java.security.interfaces.EdECKey {

        @Serial
        private static final long serialVersionUID = 1L;

        Ed(NativeKey key) {
            super(key);
        }

        /** {@code EdDSA}, as the JDK names Ed25519 keys - JSSE asks by that name. */
        @Override
        public String getAlgorithm() {
            return "EdDSA";
        }

        @Override
        public java.security.spec.NamedParameterSpec getParams() {
            return java.security.spec.NamedParameterSpec.ED25519;
        }
    }

    /** An EC key: its curve, which is public, and nothing else. */
    static final class Ec extends OpenSslPrivateKey implements ECKey {

        @Serial
        private static final long serialVersionUID = 1L;

        Ec(NativeKey key) {
            super(key);
        }

        @Override
        public ECParameterSpec getParams() {
            return ((ECPublicKey) nativeKey().publicKey).getParams();
        }
    }
}
