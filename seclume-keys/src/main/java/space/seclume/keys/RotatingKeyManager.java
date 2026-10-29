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

    /** Makes {@code manager} the one handshakes get from now on; the one before the last is freed. */
    protected final synchronized void install(SeclumeKeyManager manager) {
        Generation next = new Generation("seclume-" + (++generations), manager);
        Generation retired = previous;
        previous = current;
        current = next;
        if (retired != null) {
            destroyLater(retired);
        }
    }

    private static void destroyLater(Generation generation) {
        CompletableFuture.delayedExecutor(GRACE_SECONDS, TimeUnit.SECONDS)
                .execute(() -> ((OpenSslPrivateKey) generation.manager()
                        .getPrivateKey(SeclumeKeyManager.ALIAS)).destroy());
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
        return current.manager().getCertificateChain(SeclumeKeyManager.ALIAS);
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

    @Override
    public abstract void close();
}
