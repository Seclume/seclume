package space.seclume.internal;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.function.Consumer;

/**
 * The secrets that are kept between logins, and a way to wipe all of them
 * before the process is written to disk as a checkpoint image.
 *
 * <p>Most secrets live for one login and are gone before anything can be
 * checkpointed. A few are cached on purpose, because fetching them for every
 * login would be wrong: Vault's database credential for the length of its
 * lease, the instance role's AWS keys, an OAuth access token. A CRaC or
 * SnapStart image taken after they were fetched contains them - locked pages
 * and {@code MADV_DONTDUMP} say nothing about a checkpoint, which copies the
 * process's memory by its own means - and a restore brings them back, in
 * every instance started from that image.
 *
 * <p>So every such cache registers here, and {@code seclume-crac} wipes them
 * all before the checkpoint. The next use after the restore fetches afresh,
 * as the first use did. Registration is weak: a cache that is no longer used
 * does not stay alive for this.
 */
public final class Checkpoint {

    private static final Map<Object, Consumer<Object>> HOLDERS = new WeakHashMap<>();

    /**
     * Guards {@link #holding}. While a checkpoint holds, no new secret may be
     * made: {@code SecretScope} waits here before it allocates anything.
     */
    private static final Object GATE = new Object();
    private static volatile boolean holding;
    private static long heldSince;

    /**
     * The longest one secret waits for a checkpoint, in milliseconds
     * ({@code seclume.crac.holdMillis}). Then that one is refused, rather than
     * hang - and the hold stays until the restore or the abort, since the
     * image may still be being written.
     */
    static final long HOLD_MILLIS = Long.getLong("seclume.crac.holdMillis", 60_000);

    /**
     * {@code seclume.crac.holdExpiry=release}: the opt-out - the hold ends
     * after {@link #HOLD_MILLIS}, as it did before 0.15.0, with a warning.
     */
    static final boolean RELEASE_ON_EXPIRY =
            "release".equals(System.getProperty("seclume.crac.holdExpiry"));

    private Checkpoint() {
    }

    /**
     * From now on no new secret is made until {@link #release()}: the window
     * between a checkpoint's barrier and the image being written stays empty.
     */
    public static void hold() {
        synchronized (GATE) {
            holding = true;
            heldSince = System.nanoTime();
        }
    }

    /** Lets new secrets be made again - after the restore, or when the checkpoint was refused. */
    public static void release() {
        synchronized (GATE) {
            holding = false;
            GATE.notifyAll();
        }
    }

    /** Whether a checkpoint holds new secrets back right now. */
    public static boolean holding() {
        return holding;
    }

    /**
     * Waits while a checkpoint holds new secrets back; returns at once
     * otherwise. Called by {@code SecretScope} before every allocation.
     *
     * @throws IllegalStateException if the thread is interrupted while waiting;
     *         the interrupt flag is kept
     */
    public static void awaitOpen() {
        if (!holding) {
            return;
        }
        awaitOpen(HOLD_MILLIS, RELEASE_ON_EXPIRY);
    }

    /** {@link #awaitOpen()} with its limits given - for a test. */
    static void awaitOpen(long holdMillis, boolean releaseOnExpiry) {
        synchronized (GATE) {
            while (holding) {
                long left = holdMillis - (System.nanoTime() - heldSince) / 1_000_000L;
                if (left <= 0) {
                    if (releaseOnExpiry) {
                        // Opted out: carry on, and say so - a secret made now
                        // may be in the image if the checkpoint is still going.
                        holding = false;
                        GATE.notifyAll();
                        System.getLogger("space.seclume.crac").log(System.Logger.Level.WARNING,
                                "a checkpoint held new secrets back for " + holdMillis
                                        + " ms and seclume.crac.holdExpiry=release lets them be "
                                        + "made again; one made before the image is written is in it");
                        return;
                    }
                    // Fail closed: the checkpoint may still be writing the
                    // image - a slow resource notified after seclume's - and a
                    // secret made now would be in it. This one is refused; the
                    // hold stays until the restore or the abort releases it.
                    throw new IllegalStateException("a checkpoint has held new secrets back for "
                            + holdMillis + " ms (seclume.crac.holdMillis) and the restore has not "
                            + "come; none is made until it does");
                }
                try {
                    GATE.wait(left);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("interrupted while a checkpoint holds new "
                            + "secrets back", e);
                }
            }
        }
    }

    /**
     * Registers a cache of secrets.
     *
     * @param wipe forgets and wipes what {@code owner} holds; must not
     *             capture {@code owner} itself (a method reference such as
     *             {@code Owner::forget} does not), or it is never collected
     */
    @SuppressWarnings("unchecked")
    public static <T> void register(T owner, Consumer<? super T> wipe) {
        synchronized (HOLDERS) {
            HOLDERS.put(owner, (Consumer<Object>) wipe);
        }
    }

    /**
     * Wipes every registered cache.
     *
     * @return how many caches were wiped
     * @throws IllegalStateException if any of them could not be; all the
     *         others are wiped regardless
     */
    public static int wipeAll() {
        List<Map.Entry<Object, Consumer<Object>>> holders;
        synchronized (HOLDERS) {
            holders = new ArrayList<>(HOLDERS.entrySet());
        }
        IllegalStateException failed = null;
        int wiped = 0;
        for (Map.Entry<Object, Consumer<Object>> holder : holders) {
            try {
                holder.getValue().accept(holder.getKey());
                wiped++;
            } catch (RuntimeException e) {
                if (failed == null) {
                    failed = new IllegalStateException("a cached secret could not be wiped "
                            + "before the checkpoint");
                }
                failed.addSuppressed(e);
            }
        }
        if (failed != null) {
            throw failed;
        }
        return wiped;
    }
}
