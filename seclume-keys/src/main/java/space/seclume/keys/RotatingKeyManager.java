package space.seclume.keys;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

/**
 * A key and chain that are replaced while the application runs - by a renewal
 * on disk ({@link ReloadingKeyManager}) or a new certificate from a CA
 * ({@link VaultPkiKeyManager}).
 *
 * <p>Each generation has an alias of its own, so a handshake that chose the
 * old one gets the old key and chain even if the replacement lands in
 * between - and so does a TLS library that caches key material by alias. The
 * old key is freed a minute later, when no handshake still has it.
 */
abstract class RotatingKeyManager extends X509ExtendedKeyManager implements AutoCloseable {

    private static final long GRACE_SECONDS = 60;

    /** Every manager that is open, for {@link SeclumeKeys#managedCertificates()}. */
    private static final java.util.Set<RotatingKeyManager> OPEN =
            java.util.concurrent.ConcurrentHashMap.newKeySet();

    private volatile String lastFailure;
    private volatile java.time.Instant failedAt;

    private record Generation(String alias, SeclumeKeyManager manager) {
    }

    private volatile Generation current;
    private volatile Generation previous;
    private int generations;
    /** The pairs freed before a checkpoint; the next use gets a new one. */
    private volatile boolean dropped;
    /**
     * Pairs replaced by a renewal and freed after the grace a handshake that
     * chose them has to finish. Kept here so that a checkpoint or a close in
     * that minute frees them too: a timer that has not fired yet left the key
     * in OpenSSL's memory - in the CRaC or SnapStart image, and after close.
     */
    private final java.util.Set<Generation> retiring =
            java.util.concurrent.ConcurrentHashMap.newKeySet();
    /** Closed: the keys are freed, and nothing is issued again. */
    private volatile boolean keysDestroyed;

    /** Inside {@link #afterRestore()}: the pair {@link #restore()} installs is the one wanted. */
    private boolean restoring;

    /**
     * Makes {@code manager} the one handshakes get from now on; the one before
     * the last is freed.
     *
     * <p>Not between a checkpoint that dropped the pairs and the first use
     * after the restore: a pair that comes then - pushed by an agent, from a
     * renewal on its timer - would be in the image, and the first use asks
     * for a new one anyway; its key is freed at once. Nor after close.
     */
    protected final synchronized void install(SeclumeKeyManager manager) {
        if (keysDestroyed || (dropped && !restoring)) {
            ((OpenSslPrivateKey) manager.getPrivateKey(SeclumeKeyManager.ALIAS)).destroy();
            return;
        }
        Generation next = new Generation("seclume-" + (++generations), manager);
        Generation retired = previous;
        previous = current;
        current = next;
        if (retired != null) {
            retiring.add(retired);
            destroyLater(retired);
        }
    }

    private void destroyLater(Generation generation) {
        CompletableFuture.delayedExecutor(GRACE_SECONDS, TimeUnit.SECONDS)
                .execute(() -> {
                    if (retiring.remove(generation)) {
                        destroy(generation);
                    }
                });
    }

    /** Frees the keys of every pair; for {@link #close()}. Nothing is issued after it. */
    protected final synchronized void destroyKeys() {
        keysDestroyed = true;
        destroy(current);
        destroy(previous);
        destroyRetiring();
    }

    private void destroyRetiring() {
        for (Generation generation : java.util.List.copyOf(retiring)) {
            if (retiring.remove(generation)) {
                destroy(generation);
            }
        }
    }

    /**
     * For a pair whose key cannot be read again - issued by a CA, fetched from
     * an agent: before a checkpoint its key is freed, as it would otherwise be
     * in the CRaC or SnapStart image, and the first use after the restore
     * gets a new pair ({@link #restore()}). A subclass calls it once it has a
     * pair; a key read from a file needs none of this, it is read again on
     * its own.
     */
    protected final void dropAtCheckpoints() {
        space.seclume.internal.Checkpoint.register(this, RotatingKeyManager::drop);
    }

    /** A new pair after a checkpoint dropped the one in hand: {@link #install} it. */
    protected void restore() throws java.io.IOException {
        throw new IllegalStateException("this key manager's keys are not dropped at checkpoints");
    }

    private synchronized void drop() {
        destroyRetiring();
        if (dropped || keysDestroyed) {
            return;
        }
        destroy(current);
        destroy(previous);
        previous = null;
        dropped = true;
    }

    private static void destroy(Generation generation) {
        if (generation != null) {
            ((OpenSslPrivateKey) generation.manager().getPrivateKey(SeclumeKeyManager.ALIAS))
                    .destroy();
        }
    }

    /**
     * Before every use: the new pair if a checkpoint dropped the one in hand.
     * A failure is recorded and logged; the handshake then finds no usable
     * key, and the next one asks again.
     */
    private void afterRestore() {
        if (!dropped || keysDestroyed) {
            return;
        }
        synchronized (this) {
            if (!dropped || keysDestroyed) {
                return;
            }
            try {
                restoring = true;
                try {
                    restore();
                } finally {
                    restoring = false;
                }
                previous = null;            // the one before was freed already
                dropped = false;
                succeeded();
            } catch (java.io.IOException | RuntimeException e) {
                failed(e.getMessage());
                System.getLogger(RotatingKeyManager.class.getName()).log(
                        System.Logger.Level.WARNING, "no new certificate for " + name()
                        + " after the restore (" + e.getMessage() + "); asking again at the "
                        + "next handshake");
            }
        }
    }

    /** Listed from now on by {@link SeclumeKeys#managedCertificates()}; a subclass calls it once it has a pair. */
    protected final void register() {
        OPEN.add(this);
    }

    /** Listed no more - on close. */
    protected final void unregister() {
        OPEN.remove(this);
    }

    /** That replacing the pair failed, and why; cleared by the next success. */
    protected final void failed(String why) {
        lastFailure = why;
        failedAt = java.time.Instant.now();
    }

    /** That replacing it worked. */
    protected final void succeeded() {
        lastFailure = null;
        failedAt = null;
    }

    /** Every open manager's certificate, as it stands. */
    static java.util.List<ManagedCertificate> all() {
        return OPEN.stream().map(RotatingKeyManager::status)
                .sorted(java.util.Comparator.comparing(ManagedCertificate::name)).toList();
    }

    /** This one's certificate as it stands. */
    final ManagedCertificate status() {
        X509Certificate leaf = currentChain()[0];
        return new ManagedCertificate(name(), kind(), leaf.getSubjectX500Principal().getName(),
                leaf.getNotBefore().toInstant(), leaf.getNotAfter().toInstant(), nextRenewal(),
                generations(), lastFailure, failedAt);
    }

    /** What it is configured under. */
    abstract String name();

    /** {@code vault-pki} or {@code file}. */
    abstract String kind();

    /** When it replaces the pair itself, or {@code null}. */
    abstract java.time.Instant nextRenewal();

    /** How many times a pair was installed, the first time included - for tests and metrics. */
    synchronized int generations() {
        return generations;
    }

    /** The chain handshakes get now. */
    X509Certificate[] currentChain() {
        // Not a use: listing the certificate asks nobody for a new one after a
        // restore - the chain in hand is public and still there.
        return current.manager().getCertificateChain(SeclumeKeyManager.ALIAS);
    }

    private SeclumeKeyManager of(String alias) {
        afterRestore();
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

    /** The pair handshakes get now - a new one first, after a restore. */
    private SeclumeKeyManager now() {
        afterRestore();
        return current.manager();
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return aliases(now().getClientAliases(keyType, issuers));
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return alias(now().chooseClientAlias(keyType, issuers, socket));
    }

    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers,
                                          SSLEngine engine) {
        return alias(now().chooseEngineClientAlias(keyType, issuers, engine));
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return aliases(now().getServerAliases(keyType, issuers));
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return alias(now().chooseServerAlias(keyType, issuers, socket));
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers,
                                          SSLEngine engine) {
        return alias(now().chooseEngineServerAlias(keyType, issuers, engine));
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

    @Override
    public abstract void close();
}
