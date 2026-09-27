package space.seclume.keys;

import java.net.Socket;
import java.nio.file.Path;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;
import space.seclume.secret.SecretWatch;

/**
 * A server key and certificate that are renewed on disk - cert-manager,
 * certbot, a Vault PKI agent - and taken up without a restart.
 *
 * <p>Two {@link SecretWatch}es look at the key (through its secret provider,
 * so the key is compared by a keyed fingerprint in native memory, never read
 * to the heap) and at the chain file. When either changed, both are loaded
 * again, and the new pair is used from the next handshake on - only if the
 * certificate is the key's. A half-written renewal (the key there, the
 * certificate not yet) is refused and the pair that works stays; the second
 * half arriving is a change of its own and completes it.
 *
 * <p>Each generation has an alias of its own, so a handshake that chose the
 * old one gets the old key and chain even if the renewal lands in between -
 * and so does a TLS library that caches key material by alias. The old key is
 * freed a minute later, when no handshake still has it.
 */
final class ReloadingKeyManager extends X509ExtendedKeyManager implements AutoCloseable {

    private static final System.Logger LOG =
            System.getLogger(ReloadingKeyManager.class.getName());
    private static final long GRACE_SECONDS = 60;

    private record Generation(String alias, SeclumeKeyManager manager) {
    }

    private final Path chain;
    private final String keySpec;
    private final SecretProvider key;
    private final SecretWatch keyWatch;
    private final SecretWatch chainWatch;
    private volatile Generation current;
    private volatile Generation previous;
    private int generations;

    ReloadingKeyManager(Path chain, String keySpec, SecretProvider key, Duration interval) {
        this.chain = chain;
        this.keySpec = keySpec;
        this.key = key;
        this.current = load();
        this.keyWatch = SecretWatch.start("TLS key for " + chain, key, interval, this::reload);
        SecretProvider chainFile = SecretProviders.of(Map.of("provider", "file",
                "path", chain.toString(), "max-length", String.valueOf(1 << 20)));
        this.chainWatch = SecretWatch.start("TLS certificate " + chain, chainFile, interval,
                this::reload);
    }

    private synchronized Generation load() {
        X509ExtendedKeyManager loaded = SeclumeKeys.keyManager(chain, keySpec);
        return new Generation("seclume-" + (++generations), (SeclumeKeyManager) loaded);
    }

    /** Loads the pair again; throws - and keeps the old pair - if they do not belong together. */
    private synchronized void reload() {
        Generation next = load();
        Generation retired = previous;
        previous = current;
        current = next;
        LOG.log(System.Logger.Level.INFO, "the TLS key and certificate " + chain
                + " were renewed and are used from the next handshake on");
        if (retired != null) {
            destroyLater(retired);
        }
    }

    private static void destroyLater(Generation generation) {
        CompletableFuture.delayedExecutor(GRACE_SECONDS, TimeUnit.SECONDS)
                .execute(() -> ((OpenSslPrivateKey) generation.manager()
                        .getPrivateKey(SeclumeKeyManager.ALIAS)).destroy());
    }

    private SeclumeKeyManager of(String alias) {
        Generation now = current;
        // the plain alias is whatever is current - for callers outside a handshake
        if (now.alias().equals(alias) || SeclumeKeyManager.ALIAS.equals(alias)) {
            return now.manager();
        }
        Generation before = previous;
        return before != null && before.alias().equals(alias) ? before.manager() : null;
    }

    private String alias(String chosen) {
        return chosen == null ? null : current.alias();
    }

    private String[] aliases(String[] chosen) {
        return chosen == null ? null : new String[] {current.alias()};
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return aliases(current.manager().getClientAliases(keyType, issuers));
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return alias(current.manager().chooseClientAlias(keyType, issuers, socket));
    }

    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers,
                                          SSLEngine engine) {
        return alias(current.manager().chooseEngineClientAlias(keyType, issuers, engine));
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return aliases(current.manager().getServerAliases(keyType, issuers));
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return alias(current.manager().chooseServerAlias(keyType, issuers, socket));
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers,
                                          SSLEngine engine) {
        return alias(current.manager().chooseEngineServerAlias(keyType, issuers, engine));
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        SeclumeKeyManager manager = of(alias);
        return manager == null ? null : manager.getCertificateChain(SeclumeKeyManager.ALIAS);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        SeclumeKeyManager manager = of(alias);
        return manager == null ? null : manager.getPrivateKey(SeclumeKeyManager.ALIAS);
    }

    /** How many times the pair was loaded, the first time included - for tests and metrics. */
    synchronized int generations() {
        return generations;
    }

    /** For tests: look now. */
    boolean checkNow() {
        boolean key = keyWatch.checkNow();             // both look, whatever the first found
        boolean chain = chainWatch.checkNow();
        return key || chain;
    }

    /** Stops watching; the keys in use stay until the manager is gone. */
    @Override
    public void close() {
        keyWatch.close();
        chainWatch.close();
        key.close();
    }
}
