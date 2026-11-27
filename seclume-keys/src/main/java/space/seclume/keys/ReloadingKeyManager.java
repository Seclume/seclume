package space.seclume.keys;

import java.nio.file.Path;
import java.time.Duration;

import space.seclume.secret.SecretProvider;
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
 * half arriving is a change of its own and completes it. Generations and
 * their aliases are {@link RotatingKeyManager}'s.
 */
final class ReloadingKeyManager extends RotatingKeyManager {

    private static final System.Logger LOG =
            System.getLogger(ReloadingKeyManager.class.getName());
    private final Path chain;
    private final java.util.function.Supplier<SeclumeKeyManager> loading;
    private final SecretProvider key;
    private final SecretWatch keyWatch;
    private final SecretWatch chainWatch;

    ReloadingKeyManager(Path chain, SecretProvider key,
                        java.util.function.Supplier<SeclumeKeyManager> loading, Duration interval) {
        this.chain = chain;
        this.loading = loading;
        this.key = key;
        install(load());
        this.keyWatch = SecretWatch.start("TLS key for " + chain, key, interval, this::reload);
        // Built here, not from settings: the chain's path is the caller's, not a URL's.
        SecretProvider chainFile = new space.seclume.secret.FileSecretProvider(chain, 1 << 20);
        this.chainWatch = SecretWatch.start("TLS certificate " + chain, chainFile, interval,
                this::reload);
        register();
    }

    @Override
    String name() {
        return chain.toString();
    }

    @Override
    String kind() {
        return "file";
    }

    @Override
    java.time.Instant nextRenewal() {
        return null;                              // whoever writes the files decides
    }

    private SeclumeKeyManager load() {
        return loading.get();
    }

    /** Loads the pair again; throws - and keeps the old pair - if they do not belong together. */
    private synchronized void reload() {
        try {
            install(load());
        } catch (RuntimeException e) {
            failed(e.getMessage());
            throw e;
        }
        succeeded();
        LOG.log(System.Logger.Level.INFO, "the TLS key and certificate " + chain
                + " were renewed and are used from the next handshake on");
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
        unregister();
        keyWatch.close();
        chainWatch.close();
        key.close();
        destroyKeys();
    }
}
