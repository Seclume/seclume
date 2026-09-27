package space.seclume.keys;

import java.io.Serial;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.List;
import java.util.Map;

/**
 * The JCA provider that signs with {@link OpenSslPrivateKey}s - and with
 * nothing else.
 *
 * <p>It is added <b>last</b>. JCA picks a provider when the signature is
 * initialized with a key ("delayed provider selection"); the JDK's own
 * providers declare that they take {@code RSAPrivateKey} and
 * {@code ECPrivateKey}, which these keys are not, so they step aside and this
 * one is used. Every other key goes on to the JDK as before: installing it
 * changes nothing for anyone else.
 */
public final class SeclumeKeyProvider extends Provider {

    @Serial
    private static final long serialVersionUID = 1L;

    public static final String NAME = "Seclume";

    private static final SeclumeKeyProvider INSTANCE = new SeclumeKeyProvider();

    private SeclumeKeyProvider() {
        super(NAME, "1.0", "Signatures with private keys held by OpenSSL, off the heap");
        Map<String, String> attributes = Map.of("SupportedKeyClasses",
                OpenSslPrivateKey.class.getName());
        for (String digest : List.of("SHA256", "SHA384", "SHA512")) {
            putService(new Signing(this, digest + "withRSA", "RSA", digest, attributes));
            putService(new Signing(this, digest + "withECDSA", "EC", digest, attributes));
        }
        putService(new Signing(this, "RSASSA-PSS", "RSA", null, attributes));
    }

    /** Adds the provider, last, once; later calls do nothing. */
    public static synchronized SeclumeKeyProvider install() {
        if (Security.getProvider(NAME) == null) {
            Security.addProvider(INSTANCE);
        }
        return INSTANCE;
    }

    /** Built directly rather than by reflection - also in a native image. */
    private static final class Signing extends Service {

        private final String keyType;
        private final String digest;

        Signing(Provider provider, String algorithm, String keyType, String digest,
                Map<String, String> attributes) {
            super(provider, "Signature", algorithm, OpenSslSignature.class.getName(),
                    List.of(), attributes);
            this.keyType = keyType;
            this.digest = digest;
        }

        @Override
        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
            return new OpenSslSignature(keyType, digest);
        }
    }
}
