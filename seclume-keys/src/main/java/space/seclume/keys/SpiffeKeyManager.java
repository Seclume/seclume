package space.seclume.keys;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import space.seclume.secret.SpiffeWorkloadApi;
import space.seclume.secret.VaultPkiIssuer;

/**
 * The workload's X.509-SVID from the SPIFFE Workload API as a JSSE key
 * manager - the key read off the agent's socket into native memory and kept
 * in OpenSSL or CNG ({@link SpiffeWorkloadApi}), never a {@code PrivateKey}
 * on the heap as every SPIFFE library has it.
 *
 * <p>SPIRE rotates an SVID when half its life is gone; this asks again once
 * 55% has passed, and again a little later each time the agent still has the
 * same one. A new SVID is used from the next handshake on; generations and
 * their aliases are {@link RotatingKeyManager}'s. The trust bundle of each
 * answer is kept for {@link SpiffeTrustManager}.
 */
final class SpiffeKeyManager extends RotatingKeyManager {

    private static final System.Logger LOG = System.getLogger(SpiffeKeyManager.class.getName());
    static final double ASK_AT = 0.55;

    private final SpiffeWorkloadApi api;
    private final String configuredName;
    private final Clock clock;
    private final ScheduledExecutorService scheduler;
    private volatile String spiffeId;
    private volatile List<X509Certificate> bundle = List.of();
    private volatile java.math.BigInteger serial; // seclume-allow: a certificate's serial, public
    private volatile Instant notBefore;
    private volatile Instant notAfter;
    private boolean closed;

    /** @param name what it is listed and recorded as; {@code null} for the SPIFFE ID */
    SpiffeKeyManager(SpiffeWorkloadApi api, String name, Clock clock) {
        this.api = api;
        this.configuredName = name == null || name.isBlank() ? null : name.trim();
        this.clock = clock;
        try {
            if (!fetch()) {
                throw new IOException("the first answer of the Workload API held no new SVID");
            }
        } catch (IOException | RuntimeException e) {
            throw new IllegalStateException("no X.509-SVID from the Workload API at "
                    + api.socket() + ": " + e.getMessage(), e);
        }
        register();
        this.scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "seclume-spiffe " + api.socket());
            thread.setDaemon(true);
            return thread;
        });
        schedule(Duration.between(clock.instant(), nextRenewal()));
    }

    /** Asks the agent; installs the SVID if it is a new one. Whether it was. */
    private boolean fetch() throws IOException {
        space.seclume.jfr.SeclumeEvents.CertificateRenewal event =
                space.seclume.jfr.Observed.beginCertificateRenewal();
        try {
            SpiffeWorkloadApi.X509Svid svid = api.fetchX509Svid();
            X509Certificate leaf = svid.chain().get(0);
            boolean fresh = !leaf.getSerialNumber().equals(serial);
            if (fresh) {
                NativeKey key = NativeKey.of(svid.key());
                install(new SeclumeKeyManager(svid.chain().toArray(X509Certificate[]::new),
                        OpenSslPrivateKey.of(key)));
                serial = leaf.getSerialNumber();
                notBefore = svid.notBefore();
                notAfter = svid.notAfter();
            } else {
                svid.key().close();
            }
            spiffeId = svid.spiffeId();
            bundle = svid.bundle();
            space.seclume.jfr.Observed.endCertificateRenewal(event, name(),
                    api.socket().toString(), true, notAfter.toEpochMilli(), null);
            return fresh;
        } catch (IOException | RuntimeException e) {
            space.seclume.jfr.Observed.endCertificateRenewal(event, name(),
                    api.socket().toString(), false, notAfter == null ? 0 : notAfter.toEpochMilli(),
                    e.getMessage());
            throw e;
        }
    }

    /** Asks now; whether the agent had a new SVID. */
    synchronized boolean renewNow() throws IOException {
        boolean fresh;
        try {
            fresh = fetch();
        } catch (IOException | RuntimeException e) {
            failed(e.getMessage());
            throw e;
        }
        succeeded();
        if (fresh) {
            LOG.log(System.Logger.Level.INFO, "a new X.509-SVID for " + spiffeId + ", valid until "
                    + notAfter + "; used from the next handshake on");
        }
        return fresh;
    }

    private void schedule(Duration delay) {
        scheduler.schedule(this::renewOrRetry, Math.max(0, delay.toMillis()),
                TimeUnit.MILLISECONDS);
    }

    private void renewOrRetry() {
        synchronized (this) {
            if (closed) {
                return;
            }
        }
        try {
            if (renewNow()) {
                schedule(Duration.between(clock.instant(), nextRenewal()));
            } else {
                schedule(VaultPkiIssuer.retryAfter(clock.instant(), notAfter));
            }
        } catch (IOException | RuntimeException e) {
            Duration retry = VaultPkiIssuer.retryAfter(clock.instant(), notAfter);
            LOG.log(System.Logger.Level.WARNING, "the X.509-SVID for " + spiffeId + " could not "
                    + "be renewed (" + e.getMessage() + "); the one in hand ends " + notAfter
                    + ", trying again in " + retry.toSeconds() + "s");
            schedule(retry);
        }
    }

    /** The trust bundle of the latest answer: the CAs of the workload's trust domain. */
    List<X509Certificate> bundle() {
        return bundle;
    }

    @Override
    String name() {
        if (configuredName != null) {
            return configuredName;
        }
        return spiffeId == null ? "an SVID" : spiffeId;
    }

    @Override
    String kind() {
        return "spiffe";
    }

    @Override
    Instant nextRenewal() {
        return VaultPkiIssuer.renewalTime(notBefore, notAfter, ASK_AT);
    }

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
    }
}
