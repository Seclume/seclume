package space.seclume.keys;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

/**
 * One certificate chain and its key in OpenSSL: what a TLS server presents,
 * or a client asked for its certificate.
 *
 * <p>JSSE asks for the key by type - {@code RSA}, {@code RSASSA-PSS} (an RSA
 * key signing with PSS, which TLS 1.3 always does), {@code EC} - and gets the
 * one alias when the type fits.
 */
final class SeclumeKeyManager extends X509ExtendedKeyManager {

    static final String ALIAS = "seclume";

    private final X509Certificate[] chain;
    private final OpenSslPrivateKey key;

    SeclumeKeyManager(X509Certificate[] chain, OpenSslPrivateKey key) {
        this.chain = chain.clone();
        this.key = key;
    }

    private boolean fits(String keyType) {
        if (keyType == null) {
            return false;
        }
        return switch (key.getAlgorithm()) {
            case "RSA" -> keyType.equals("RSA") || keyType.equals("RSASSA-PSS");
            case "EC" -> keyType.equals("EC");
            case "EdDSA" -> keyType.equals("EdDSA") || keyType.equals("Ed25519");
            default -> false;
        };
    }

    private String choose(String[] keyTypes) {
        if (keyTypes != null) {
            for (String keyType : keyTypes) {
                if (fits(keyType)) {
                    return ALIAS;
                }
            }
        }
        return null;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return fits(keyType) ? new String[] {ALIAS} : null;
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return choose(keyType);
    }

    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers,
                                          SSLEngine engine) {
        return choose(keyType);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return fits(keyType) ? new String[] {ALIAS} : null;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return fits(keyType) ? ALIAS : null;
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers,
                                          SSLEngine engine) {
        return fits(keyType) ? ALIAS : null;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return ALIAS.equals(alias) ? chain.clone() : null;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return ALIAS.equals(alias) ? key : null;
    }
}
