package space.seclume.keys;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import space.seclume.secret.SecretProviders;
import space.seclume.secret.VaultPkiIssuer;

/**
 * A client (or server) certificate from Vault's PKI engine whose key was never
 * anywhere but in OpenSSL.
 *
 * <p>{@code pki/issue} would be the short way, and Vault would make the key -
 * and send it back in a JSON answer, where every client turns it into a
 * {@code String}. Here {@link VaultPkiIssuer} generates the key in OpenSSL (or
 * CNG), signs a certification request with it there, and {@code pki/sign/<role>}
 * returns only the certificate: the key leaves neither the process nor native
 * memory, and Vault never has it.
 *
 * <p>The certificate is renewed - a new key, a new request - once
 * {@code renew-at} of its lifetime has passed (two thirds by default), and
 * the new pair is used from the next handshake on; generations and their
 * aliases are {@link RotatingKeyManager}'s. A renewal that fails is tried
 * again, sooner the closer the end, and the certificate in hand stays until
 * it expires. The Vault token comes from the same settings and logins as
 * {@code provider=vault}'s ({@link SecretProviders#vaultToken}).
 *
 * <p>The chain is the certificate and its issuing CA, as Vault reports them:
 * what a peer that trusts the root needs from a two-level PKI.
 */
final class VaultPkiKeyManager extends RotatingKeyManager {

    private static final System.Logger LOG =
            System.getLogger(VaultPkiKeyManager.class.getName());

    private final VaultPkiIssuer issuer;
    private final Clock clock;
    private final ScheduledExecutorService scheduler;
    private volatile Instant notAfter;
    private volatile Instant nextRenewal;
    private boolean closed;

    VaultPkiKeyManager(Map<String, String> settings, Clock clock) {
        this.clock = clock;
        this.issuer = new VaultPkiIssuer(settings);
        try {
            install(issue());
        } catch (IOException | RuntimeException e) {
            issuer.close();
            throw new IllegalStateException("no certificate from Vault at " + issuer.address()
                    + issuer.signPath() + ": " + e.getMessage(), e);
        }
        register();
        this.scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "seclume-vault-pki " + issuer.commonName());
            thread.setDaemon(true);
            return thread;
        });
        schedule(Duration.between(clock.instant(), nextRenewal));
    }

    /** When the certificate in hand ends. */
    Instant notAfter() {
        return notAfter;
    }

    /** When it is to be replaced. */
    @Override
    Instant nextRenewal() {
        return nextRenewal;
    }

    @Override
    String name() {
        return issuer.name();
    }

    @Override
    String kind() {
        return "vault-pki";
    }

    /** Replaces the certificate now - a new key, a new request. */
    synchronized void renewNow() throws IOException {
        try {
            install(issue());
        } catch (IOException | RuntimeException e) {
            failed(e.getMessage());
            throw e;
        }
        succeeded();
        LOG.log(System.Logger.Level.INFO, "a new certificate for " + issuer.commonName()
                + " from " + issuer.signPath() + ", valid until " + notAfter
                + "; used from the next handshake on");
    }

    private void schedule(Duration delay) {
        long millis = Math.max(0, delay.toMillis());
        scheduler.schedule(this::renewOrRetry, millis, TimeUnit.MILLISECONDS);
    }

    private void renewOrRetry() {
        synchronized (this) {
            if (closed) {
                return;
            }
        }
        try {
            renewNow();
            schedule(Duration.between(clock.instant(), nextRenewal));
        } catch (IOException | RuntimeException e) {
            Duration retry = VaultPkiIssuer.retryAfter(clock.instant(), notAfter);
            LOG.log(System.Logger.Level.WARNING, "the certificate for " + issuer.commonName()
                    + " could not be renewed (" + e.getMessage() + "); the one in hand ends "
                    + notAfter + ", trying again in " + retry.toSeconds() + "s");
            schedule(retry);
        }
    }

    /** A certificate from the issuer as this module's key and chain - recorded either way. */
    private SeclumeKeyManager issue() throws IOException {
        space.seclume.jfr.SeclumeEvents.CertificateRenewal event =
                space.seclume.jfr.Observed.beginCertificateRenewal();
        try {
            VaultPkiIssuer.Issued issued = issuer.issue();
            NativeKey key = NativeKey.of(issued.key());
            notAfter = issued.notAfter();
            nextRenewal = issuer.renewalTime(issued);
            SeclumeKeyManager manager = new SeclumeKeyManager(
                    issued.chain().toArray(X509Certificate[]::new), OpenSslPrivateKey.of(key));
            space.seclume.jfr.Observed.endCertificateRenewal(event, issuer.name(),
                    issuer.signPath(), true, notAfter.toEpochMilli(), null);
            return manager;
        } catch (IOException | RuntimeException e) {
            space.seclume.jfr.Observed.endCertificateRenewal(event, issuer.name(),
                    issuer.signPath(), false, notAfter == null ? 0 : notAfter.toEpochMilli(),
                    e.getMessage());
            throw e;
        }
    }

    /** Stops renewing; the certificates in use stay until the manager is gone. */
    @Override
    public void close() {
        synchronized (this) {
            if (closed) {
                return;
            }
            closed = true;
        }
        unregister();
        scheduler.shutdownNow();
        issuer.close();
    }
}
