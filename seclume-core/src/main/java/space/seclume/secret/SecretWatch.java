package space.seclume.secret;

import java.lang.foreign.MemorySegment;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Hmac;
import space.seclume.internal.Entropy;
import space.seclume.jfr.Observed;
import space.seclume.jfr.SeclumeEvents;

/**
 * Notices when a secret changed at its source - a rotated password in a
 * mounted Kubernetes secret, a new Vault version, a replaced file - and says
 * so, so that what was built with the old one can be built again without a
 * restart.
 *
 * <pre>
 * SecretWatch watch = SecretWatch.start("orders-db", provider, Duration.ofSeconds(30),
 *         () -&gt; pool.rotateSecret(true));
 * </pre>
 *
 * <p>To tell old from new without keeping either, the watch keeps a
 * <b>fingerprint</b>: an HMAC-SHA256 of the secret under a random key. Both
 * the key and the fingerprint live in native memory, and the key exists only
 * in this process, so the fingerprint is no stand-in for the secret either - a
 * plain hash of a password is one dictionary away from the password, a keyed
 * one without its key is not. The secret itself is read into native memory,
 * fingerprinted and wiped, as for a login.
 *
 * <p>A source that cannot be read for a while - Vault restarting, the file
 * swapped mid-read - is not a change: the watch keeps the fingerprint it has
 * and tries again at the next tick. A rotation is reported once, when a
 * readable secret differs from the last readable one, as a
 * {@code space.seclume.SecretRotation} event.
 *
 * <p>How often to look is a trade: every tick is a read of the source - for a
 * file nothing, for Vault a request. The kubelet updates a mounted secret
 * within about a minute, so 30 seconds loses nothing there.
 */
public final class SecretWatch implements AutoCloseable {

    private static final System.Logger LOG = System.getLogger(SecretWatch.class.getName());

    /** One thread for every watch in the process: a tick is a short read. */
    private static final ScheduledExecutorService TICKS = scheduler();

    private final String name;
    private final SecretProvider source;
    private final Runnable onChange;
    private final SecretScope key = SecretScope.allocateShared(32);
    private final SecretScope fingerprint = SecretScope.allocateShared(32);
    private final SecretScope candidate = SecretScope.allocateShared(32);
    private final Object checking = new Object();
    private final AtomicLong changes = new AtomicLong();
    private boolean known;
    private boolean failing;
    private volatile boolean closed;
    private ScheduledFuture<?> ticking;

    private SecretWatch(String name, SecretProvider source, Runnable onChange) {
        this.name = name;
        this.source = source;
        this.onChange = onChange;
        Entropy.fill(key.segment(), 0, 32);
    }

    /**
     * Starts watching {@code source} every {@code interval}; {@code onChange}
     * runs on the watch thread after each rotation.
     *
     * @param name what the watch is for - a data source, a key - in events
     *             and log lines; no secret
     */
    public static SecretWatch start(String name, SecretProvider source, Duration interval,
                                    Runnable onChange) {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(onChange, "onChange");
        if (interval == null || interval.isNegative() || interval.isZero()) {
            throw new IllegalArgumentException("a secret watch needs an interval greater than "
                    + "zero, got " + interval);
        }
        SecretWatch watch = new SecretWatch(name, source, onChange);
        watch.check();                              // what the secret is now
        long millis = Math.max(1, interval.toMillis());
        watch.ticking = TICKS.scheduleWithFixedDelay(watch::tick, millis, millis,
                TimeUnit.MILLISECONDS);
        return watch;
    }

    /**
     * Looks now instead of at the next tick - after a deployment tool says it
     * rotated, or from a test.
     *
     * @return whether the secret changed since the last look
     */
    public boolean checkNow() {
        return check();
    }

    /** How many rotations this watch has seen. */
    public long changes() {
        return changes.get();
    }

    /** What the watch is for, as given. */
    public String name() {
        return name;
    }

    private void tick() {
        try {
            check();
        } catch (RuntimeException e) {
            // The next tick is worth having: a scheduled task that throws is
            // never run again.
            LOG.log(System.Logger.Level.WARNING, "the secret watch for " + name
                    + " failed, and tries again at its next tick", e);
        }
    }

    private boolean check() {
        synchronized (checking) {
            if (closed) {
                return false;
            }
            if (!fingerprint(candidate.segment())) {
                return false;
            }
            if (!known) {
                MemorySegment.copy(candidate.segment(), 0, fingerprint.segment(), 0, 32);
                known = true;
                return false;
            }
            if (candidate.segment().asSlice(0, 32)
                    .mismatch(fingerprint.segment().asSlice(0, 32)) < 0) {
                return false;
            }
            MemorySegment.copy(candidate.segment(), 0, fingerprint.segment(), 0, 32);
        }
        changes.incrementAndGet();
        SeclumeEvents.SecretRotation event = Observed.beginSecretRotation();
        String reason = "";
        try {
            onChange.run();
        } catch (RuntimeException e) {
            reason = e.getClass().getSimpleName() + ": " + e.getMessage();
            LOG.log(System.Logger.Level.WARNING, "the secret for " + name + " was rotated, "
                    + "but taking up the new one failed", e);
        }
        if (reason.isEmpty()) {
            LOG.log(System.Logger.Level.INFO, "the secret for " + name + " was rotated at "
                    + "its source; taken up without a restart");
        }
        Observed.endSecretRotation(event, name, reason.isEmpty(), reason);
        return true;
    }

    /** The keyed fingerprint of the secret now, into {@code out}; false if unreadable. */
    private boolean fingerprint(MemorySegment out) {
        try (SecretScope secret = SecretScope.fromProvider(source);
             Hmac mac = new Hmac(HashAlgorithm.SHA_256, key.segment(), 0, 32)) {
            mac.update(secret.segment(), 0, secret.length());
            mac.doFinal(out, 0);
            if (failing) {
                failing = false;
                LOG.log(System.Logger.Level.INFO, "the secret for " + name
                        + " can be read again");
            }
            return true;
        } catch (RuntimeException e) {
            if (!failing) {
                failing = true;
                LOG.log(System.Logger.Level.WARNING, "the secret for " + name + " cannot be "
                        + "read right now (" + e.getMessage() + "); keeping what was known and "
                        + "trying again");
            }
            return false;
        }
    }

    /** Stops watching; the source itself is the caller's to close. */
    @Override
    public void close() {
        synchronized (checking) {
            if (closed) {
                return;
            }
            closed = true;
            if (ticking != null) {
                ticking.cancel(false);
            }
            key.close();
            fingerprint.close();
            candidate.close();
        }
    }

    private static ScheduledExecutorService scheduler() {
        ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1, task -> {
            Thread thread = new Thread(task, "seclume-secret-watch");
            thread.setDaemon(true);
            return thread;
        });
        executor.setRemoveOnCancelPolicy(true);
        return executor;
    }
}
