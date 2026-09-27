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
     * The longest a secret waits for a checkpoint, in milliseconds
     * ({@code seclume.crac.holdMillis}): if the restore - or the abort -
     * never comes round to {@link #release()}, logins carry on rather than
     * hang forever.
     */
    static final long HOLD_MILLIS = Long.getLong("seclume.crac.holdMillis", 60_000);

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
        synchronized (GATE) {
            while (holding) {
                long left = HOLD_MILLIS - (System.nanoTime() - heldSince) / 1_000_000L;
                if (left <= 0) {
                    // The restore or abort never released it: carry on rather
                    // than hang every login of the process.
                    holding = false;
                    GATE.notifyAll();
                    return;
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
