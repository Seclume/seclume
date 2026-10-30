package space.seclume.keys;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
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
 * <p>SPIRE rotates an SVID when half its life is gone and pushes the new one
 * down the open {@code FetchX509SVID} stream, which this keeps open
 * ({@link SpiffeWorkloadApi#watchX509Svids}) - a rotated SVID, a changed bundle
 * is taken the moment it comes. Beside the stream it still asks once 55% has
 * passed, and again a little later each time the agent has the same one, in
 * case the stream is down. A new SVID is used from the next handshake on;
 * generations and their aliases are {@link RotatingKeyManager}'s. The trust
 * bundle of each answer, and the bundles of the trust domains it federates
 * with, are kept for {@link SpiffeTrustManager}.
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
    private volatile Map<String, List<X509Certificate>> federated = Map.of();
    private volatile String trustDomain;
    private SpiffeWorkloadApi.Watch watch;
    /**
     * The serials this has replaced - the last few. An answer that brings one
     * of them is late, not new: the stream's first message, say, overtaken by
     * a look that already found the next SVID.
     */
    private final java.util.Set<java.math.BigInteger> replaced = // seclume-allow: certificates' serials, which are public
            java.util.Collections.newSetFromMap(new java.util.LinkedHashMap<>() {
                private static final long serialVersionUID = 1L;

                @Override
                protected boolean removeEldestEntry(
                        Map.Entry<java.math.BigInteger, Boolean> eldest) { // seclume-allow: a public serial
                    return size() > 16;
                }
            });
    private volatile java.math.BigInteger serial; // seclume-allow: a certificate's serial, public
    private volatile Instant notBefore;
    private volatile Instant notAfter;
    private boolean closed;

    /**
     * @param name   what it is listed and recorded as; {@code null} for the SPIFFE ID
     * @param stream whether to keep the stream open for rotations as they come
     */
    SpiffeKeyManager(SpiffeWorkloadApi api, String name, Clock clock, boolean stream) {
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
        if (stream) {
            SpiffeWorkloadApi.Watch opened = api.watchX509Svids(this::pushed, failure -> {
                failed(failure.getMessage());
                LOG.log(System.Logger.Level.WARNING, "the stream of X.509-SVIDs from "
                        + api.socket() + " broke (" + failure.getMessage() + "); opening it "
                        + "again, and asking at " + nextRenewal() + " in any case");
            });
            synchronized (this) {
                if (closed) {
                    opened.close();
                } else {
                    watch = opened;
                }
            }
        }
    }

    /** An SVID the agent pushed down the open stream. */
    private void pushed(SpiffeWorkloadApi.X509Svid svid) {
        space.seclume.jfr.SeclumeEvents.CertificateRenewal event =
                space.seclume.jfr.Observed.beginCertificateRenewal();
        boolean fresh;
        synchronized (this) {
            if (closed) {
                svid.key().close();
                return;
            }
            fresh = take(svid);
        }
        succeeded();
        if (fresh) {
            space.seclume.jfr.Observed.endCertificateRenewal(event, name(),
                    api.socket().toString(), true, notAfter.toEpochMilli(), null);
            LOG.log(System.Logger.Level.INFO, "a new X.509-SVID for " + spiffeId + " pushed by "
                    + "the agent, valid until " + notAfter + "; used from the next handshake on");
        }
    }

    /** Asks the agent; installs the SVID if it is a new one. Whether it was. */
    private boolean fetch() throws IOException {
        space.seclume.jfr.SeclumeEvents.CertificateRenewal event =
                space.seclume.jfr.Observed.beginCertificateRenewal();
        try {
            SpiffeWorkloadApi.X509Svid svid = api.fetchX509Svid();
            boolean fresh;
            synchronized (this) {
                fresh = take(svid);
            }
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

    /**
     * Installs {@code svid} if it is a new one - a new serial - and takes its
     * bundles either way, closing its key when it is not used. Whether it was
     * new.
     */
    private boolean take(SpiffeWorkloadApi.X509Svid svid) {
        X509Certificate leaf = svid.chain().get(0);
        if (replaced.contains(leaf.getSerialNumber())) {
            // late: this SVID was in use once and has been replaced
            svid.key().close();
            return false;
        }
        boolean fresh = !leaf.getSerialNumber().equals(serial);
        if (fresh) {
            if (serial != null) {
                replaced.add(serial);
            }
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
        trustDomain = svid.trustDomain();
        bundle = svid.bundle();
        federated = svid.federatedBundles();
        return fresh;
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

    /**
     * The CAs a peer of {@code domain} is checked against: the workload's own
     * bundle for its own trust domain, a federated one's for another - none for
     * a domain it does not federate with.
     */
    List<X509Certificate> bundleFor(String domain) {
        if (domain.equals(trustDomain)) {
            return bundle;
        }
        return federated.getOrDefault(domain, List.of());
    }

    /** Every CA a peer may chain to: the own bundle and the federated ones. */
    List<X509Certificate> allBundles() {
        List<X509Certificate> all = new java.util.ArrayList<>(bundle);
        federated.values().forEach(all::addAll);
        return all;
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
            if (watch != null) {
                watch.close();
            }
        }
        unregister();
        scheduler.shutdownNow();
    }
}
