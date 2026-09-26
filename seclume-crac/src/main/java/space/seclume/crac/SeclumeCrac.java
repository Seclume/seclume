package space.seclume.crac;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.crac.Context;
import org.crac.Core;
import org.crac.Resource;

import space.seclume.pool.SeclumePool;

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

    private record PoolResource(SeclumePool pool) implements Resource {

        @Override
        public void beforeCheckpoint(Context<? extends Resource> context) {
            pool.suspend();
        }

        @Override
        public void afterRestore(Context<? extends Resource> context) {
            pool.resume();
        }
    }
}
