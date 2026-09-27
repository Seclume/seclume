package space.seclume.crac;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.crac.Context;
import org.crac.Core;
import org.crac.Resource;

import space.seclume.internal.Checkpoint;
import space.seclume.pool.SeclumePool;
import space.seclume.secret.SecretScope;

/**
 * seclume pools across a checkpoint (CRaC, AWS Lambda SnapStart).
 *
 * <pre>
 *   SeclumeCrac.register(pool);
 * </pre>
 *
 * <p>A checkpoint is the whole process written to disk, and it is refused
 * while a socket is open - so a pool with connections in it makes CRaC fail
 * outright, and a pool that closed them sloppily would leave each session's
 * encryption keys in the image. Registered here, a pool gives up every
 * connection before the checkpoint ({@link SeclumePool#suspend()}) and fills
 * again after the restore ({@link SeclumePool#resume()}) - from new logins,
 * with the secret fetched anew from its provider, so a rotated password after a
 * restore is simply the password.
 *
 * <p>The password itself was never in the image: seclume keeps it in native
 * memory only for the login and wipes it. What this adds is that nothing
 * derived from it stays behind either, and that the checkpoint can be taken at
 * all.
 */
public final class SeclumeCrac {

    /** Held strongly: CRaC keeps only weak references to what it is given. */
    private static final List<Resource> REGISTERED = new CopyOnWriteArrayList<>();

    private SeclumeCrac() {
    }

    /** Makes {@code pool} give up its connections before a checkpoint and resume after. */
    public static void register(SeclumePool pool) {
        Resource resource = new PoolResource(pool);
        REGISTERED.add(resource);
        Core.getGlobalContext().register(resource);
    }

    /**
     * How long a checkpoint waits for borrowed connections to come back and
     * running logins to finish, in milliseconds; {@code seclume.crac.quiesceMillis}.
     */
    static final long QUIESCE_MILLIS = Long.getLong("seclume.crac.quiesceMillis", 10_000);

    /**
     * Suspends {@code pool} and then <b>waits</b> until nothing secret is
     * left: no connection lent out, no login running, no cached credential.
     * Suspending alone returned at once, with borrowed connections - their
     * sessions' keys - and logins in flight still in the process; on
     * SnapStart, which does not refuse open sockets, the image was then taken
     * with them in it.
     *
     * <p>If the process does not get there in time, the checkpoint is refused
     * rather than taken: the exception aborts it, and the pool is resumed.
     *
     * <p>What this cannot promise: a login that starts after it returned and
     * before the checkpoint is taken. Take the checkpoint from a quiet
     * application - which is what CRaC and SnapStart expect anyway.
     */
    static void quiesce(SeclumePool pool, long millis) throws InterruptedException {
        pool.suspend();
        long deadline = System.nanoTime() + millis * 1_000_000L;
        while (true) {
            // Again on every round: a login that ran meanwhile may have
            // filled a cache the previous round had wiped.
            Checkpoint.wipeAll();
            int borrowed = pool.activeCount();
            long secrets = SecretScope.open();
            if (borrowed == 0 && secrets == 0) {
                return;
            }
            if (System.nanoTime() - deadline >= 0) {
                pool.resume();
                throw new IllegalStateException("seclume refuses the checkpoint: after "
                        + millis + " ms " + borrowed + " connection(s) are still "
                        + "borrowed and " + secrets + " secret(s) still open; an image "
                        + "taken now would contain them (seclume.crac.quiesceMillis sets "
                        + "the wait)");
            }
            Thread.sleep(20);
        }
    }

    private record PoolResource(SeclumePool pool) implements Resource {

        /** See {@link SeclumeCrac#quiesce}; an exception here aborts the checkpoint. */
        @Override
        public void beforeCheckpoint(Context<? extends Resource> context) throws Exception {
            quiesce(pool, QUIESCE_MILLIS);
        }

        @Override
        public void afterRestore(Context<? extends Resource> context) {
            pool.resume();
        }
    }
}
