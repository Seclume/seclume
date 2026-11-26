package space.seclume.crac;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.crac.Context;
import org.crac.Core;
import org.crac.Resource;

import space.seclume.crypto.OpenSslRandom;
import space.seclume.crypto.PrivateSigningKey;
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
 * all. Private keys in OpenSSL's or CNG's memory are freed when they can be
 * read again from their source, and refuse the checkpoint when they cannot.
 */
public final class SeclumeCrac {

    /** Held strongly: CRaC keeps only weak references to what it is given. */
    private static final List<Resource> REGISTERED = new CopyOnWriteArrayList<>();

    private SeclumeCrac() {
    }

    /**
     * The process's own part: wiping what is cached, waiting for open secrets
     * and keys, holding new ones, and reseeding OpenSSL's generator after the
     * restore. It ran only inside a pool's resource - an application using
     * seclume for TLS without a seclume pool (seclume-keys behind Tomcat, the
     * HTTP, Kafka, Redis or MongoDB clients) got none of it, and every clone of
     * its image drew the same "random" TLS key shares. Registered when this
     * class is loaded, before any pool: CRaC asks the pools first before a
     * checkpoint and this first after the restore.
     */
    private static final Resource PROCESS = new ProcessResource();

    static {
        REGISTERED.add(PROCESS);
        Core.getGlobalContext().register(PROCESS);
    }

    /**
     * Registers the process's part - for an application without a seclume
     * pool. Loading this class does it; calling this says so in the code.
     */
    public static void registerProcess() {
        // the static initializer has run by now
    }

    /** Whether the process's part is registered - for a test. */
    static boolean processRegistered() {
        return REGISTERED.contains(PROCESS);
    }

    /** Makes {@code pool} give up its connections before a checkpoint and resume after. */
    public static void register(SeclumePool pool) {
        Resource resource = new PoolResource(pool);
        REGISTERED.add(resource);
        Core.getGlobalContext().register(resource);
    }

    /**
     * A client that can let go of its connections before a checkpoint and
     * open new ones after the restore - a MongoDB, HTTP or Redis client
     * behind seclume's TLS, wrapped by the application, which knows how its
     * client is rebuilt.
     */
    public interface Suspendable {

        /** Before the checkpoint: every connection closed. An exception refuses the checkpoint. */
        void suspend() throws Exception;

        /** After the restore - or a refused checkpoint: connections again. */
        void resume() throws Exception;
    }

    /**
     * Makes {@code client} suspend before a checkpoint and resume after, as a
     * pool does. Asked before the process's own part, which then still checks
     * that no seclume TLS connection is left open and names who opened any
     * that are - a client nobody registered refuses the checkpoint there.
     */
    public static void register(Suspendable client) {
        Resource resource = new ClientResource(client);
        REGISTERED.add(resource);
        Core.getGlobalContext().register(resource);
    }

    /**
     * Closes {@code client} before a checkpoint, for one that cannot be
     * suspended: after the restore the application makes a new one.
     */
    public static void closeBeforeCheckpoint(AutoCloseable client) {
        register(new Suspendable() {
            @Override
            public void suspend() throws Exception {
                client.close();
            }

            @Override
            public void resume() {
                // closed for good; the application builds a new one
            }
        });
    }

    /** The resources registered, in order - for a test. */
    static List<Resource> registered() {
        return List.copyOf(REGISTERED);
    }

    /**
     * How long a checkpoint waits for borrowed connections to come back and
     * running logins to finish, in milliseconds; {@code seclume.crac.quiesceMillis}.
     */
    static final long QUIESCE_MILLIS = Long.getLong("seclume.crac.quiesceMillis", 10_000);

    /**
     * Whether new secrets wait from the barrier until the restore
     * ({@code seclume.crac.holdSecrets}, on by default). Without it a login
     * that starts after the barrier and before the image is written ends up
     * in the image; with it, that login waits for the restore - at most
     * {@code seclume.crac.holdMillis}.
     */
    static final boolean HOLD_SECRETS = !"false".equalsIgnoreCase(
            System.getProperty("seclume.crac.holdSecrets"));

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
            // Keys in OpenSSL's or CNG's memory: a reloadable one was freed by
            // wipeAll above; one that cannot be read again is still here.
            int keys = PrivateSigningKey.held();
            if (borrowed == 0 && secrets == 0 && keys == 0) {
                if (!HOLD_SECRETS) {
                    return;
                }
                // Quiet - now keep it so until the restore: no new secret is
                // made from here on. Checked once more under the hold, since
                // a login may have started between the count and the hold.
                Checkpoint.hold();
                if (SecretScope.open() == 0 && pool.activeCount() == 0
                        && PrivateSigningKey.held() == 0) {
                    return;
                }
                Checkpoint.release();
                continue;
            }
            if (System.nanoTime() - deadline >= 0) {
                pool.resume();
                throw new IllegalStateException("seclume refuses the checkpoint: after "
                        + millis + " ms " + borrowed + " connection(s) are still "
                        + "borrowed, " + secrets + " secret(s) still open" + secretsOpenedAt()
                        + " and " + keys
                        + " private key(s) held" + heldBy() + "; an image taken now would "
                        + "contain them (seclume.crac.quiesceMillis sets the wait). A key read "
                        + "from its source - a keySpec, a key file - is dropped and read again "
                        + "after the restore; one that cannot be (generated, issued, decoded "
                        + "from a provider handed in) has to be closed before the checkpoint");
            }
            Thread.sleep(20);
        }
    }

    /** Where the open secrets were opened, with -Dseclume.debug.scopes=true; else how to find out. */
    private static String secretsOpenedAt() {
        if (!SecretScope.tracingOrigins()) {
            return " (-Dseclume.debug.scopes=true names where they were opened)";
        }
        List<String> where = SecretScope.openedAt(5);
        return where.isEmpty() ? "" : " (opened at " + String.join(", ", where) + ")";
    }

    /** Who opened the TLS connections still open, distinct: class names only. */
    private static String openedBy() {
        java.util.List<String> by = space.seclume.internal.LiveTls.origins().stream().distinct()
                .sorted().toList();
        return by.isEmpty() ? "" : " (opened by " + String.join(", ", by) + ")";
    }

    /** Who made the keys still held, distinct: class names, nothing of the keys. */
    private static String heldBy() {
        java.util.List<String> by = PrivateSigningKey.heldBy().stream().distinct().sorted().toList();
        return by.isEmpty() ? "" : " (made by " + String.join(", ", by) + ")";
    }

    /**
     * After the restore - or a refused checkpoint: OpenSSL's random generator
     * gets fresh entropy <b>before</b> new secrets are let through, so the first
     * handshake of a restored instance does not draw from a generator state it
     * shares with every other instance started from the same image. Then the
     * pool fills again.
     *
     * @throws IllegalStateException if OpenSSL refused the reseed; logins are
     *         let through regardless, and the restore reports the failure
     */
    static void restored(SeclumePool pool) {
        try {
            OpenSslRandom.reseed();
        } finally {
            Checkpoint.release();
            pool.resume();
        }
    }

    /**
     * The pool's part: suspended, and its borrowed connections back - within
     * {@link #QUIESCE_MILLIS}, or the checkpoint is refused and it resumes.
     */
    static void quiescePool(SeclumePool pool, long millis) throws InterruptedException {
        pool.suspend();
        long deadline = System.nanoTime() + millis * 1_000_000L;
        while (pool.activeCount() > 0) {
            if (System.nanoTime() - deadline >= 0) {
                pool.resume();
                throw new IllegalStateException("seclume refuses the checkpoint: after " + millis
                        + " ms " + pool.activeCount() + " connection(s) are still borrowed "
                        + "(seclume.crac.quiesceMillis sets the wait)");
            }
            Thread.sleep(20);
        }
    }

    /**
     * The process's part before a checkpoint: what is cached wiped, no secret
     * open and no key held - within {@link #QUIESCE_MILLIS}, or the checkpoint
     * is refused - and then no new secret until the restore.
     */
    static void quiesceProcess(long millis) throws InterruptedException {
        long deadline = System.nanoTime() + millis * 1_000_000L;
        while (true) {
            Checkpoint.wipeAll();
            long secrets = SecretScope.open();
            int keys = PrivateSigningKey.held();
            int tls = space.seclume.internal.LiveTls.count();
            if (secrets == 0 && keys == 0 && tls == 0) {
                if (!HOLD_SECRETS) {
                    return;
                }
                Checkpoint.hold();
                if (SecretScope.open() == 0 && PrivateSigningKey.held() == 0
                        && space.seclume.internal.LiveTls.count() == 0) {
                    return;
                }
                Checkpoint.release();
                continue;
            }
            if (System.nanoTime() - deadline >= 0) {
                throw new IllegalStateException("seclume refuses the checkpoint: after " + millis
                        + " ms " + secrets + " secret(s) are still open" + secretsOpenedAt()
                        + ", " + keys
                        + " private key(s) held" + heldBy() + " and " + tls + " TLS connection(s) "
                        + "open" + openedBy() + "; an image taken now would contain their keys - "
                        + "close the clients before the checkpoint "
                        + "(seclume.crac.quiesceMillis sets the wait)");
            }
            Thread.sleep(20);
        }
    }

    /** The process's part after the restore - or a refused checkpoint. */
    static void restoredProcess() {
        try {
            OpenSslRandom.reseed();
        } finally {
            Checkpoint.release();
        }
    }

    private record PoolResource(SeclumePool pool) implements Resource {

        /** See {@link SeclumeCrac#quiescePool}; an exception here aborts the checkpoint. */
        @Override
        public void beforeCheckpoint(Context<? extends Resource> context) throws Exception {
            quiescePool(pool, QUIESCE_MILLIS);
        }

        @Override
        public void afterRestore(Context<? extends Resource> context) {
            pool.resume();
        }
    }

    private record ClientResource(Suspendable client) implements Resource {

        /** An exception here aborts the checkpoint. */
        @Override
        public void beforeCheckpoint(Context<? extends Resource> context) throws Exception {
            client.suspend();
        }

        @Override
        public void afterRestore(Context<? extends Resource> context) throws Exception {
            client.resume();
        }
    }

    private static final class ProcessResource implements Resource {

        /** See {@link SeclumeCrac#quiesceProcess}; an exception here aborts the checkpoint. */
        @Override
        public void beforeCheckpoint(Context<? extends Resource> context) throws Exception {
            quiesceProcess(QUIESCE_MILLIS);
        }

        @Override
        public void afterRestore(Context<? extends Resource> context) {
            restoredProcess();
        }
    }
}
