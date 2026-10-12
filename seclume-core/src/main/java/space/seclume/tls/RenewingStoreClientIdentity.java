package space.seclume.tls;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * A certificate in the Windows store named by its subject, so that a renewal
 * - a new certificate, a new key, a new thumbprint - is taken up without the
 * setting changed or the application restarted.
 *
 * <p>At most once a minute, before a handshake, the store is asked again for
 * the newest certificate with that subject that is valid now. When it is
 * another one, the next handshakes use it; the previous key is closed a
 * minute later, so that a handshake that began with it can finish. A
 * certificate that cannot be used (no key this account may use, say) leaves
 * the previous one in place and is tried again at the next look.
 */
final class RenewingStoreClientIdentity implements ClientIdentity {

    static volatile long lookEveryMillis = 60_000;
    static final long GRACE_MILLIS = 60_000;

    private static final System.Logger LOG =
            System.getLogger(RenewingStoreClientIdentity.class.getName());

    private static final class Closer {
        private static final ScheduledExecutorService SERVICE =
                Executors.newSingleThreadScheduledExecutor(runnable -> {
                    Thread thread = new Thread(runnable, "seclume-store-identity-closer");
                    thread.setDaemon(true);
                    return thread;
                });
    }

    private final String subject;
    private final boolean machine;
    private ClientIdentity current;
    private String thumbprint;
    private long lookedAt;
    private final List<ClientIdentity> retiring = new ArrayList<>();
    private long renewals;
    private boolean closed;

    RenewingStoreClientIdentity(String subject, boolean machine) {
        this.subject = subject;
        this.machine = machine;
        this.thumbprint = WindowsStoreClientIdentity.newestBySubject(subject, machine);
        this.current = new WindowsStoreClientIdentity(thumbprint, machine);
        this.lookedAt = System.nanoTime();
    }

    @Override
    public synchronized ClientIdentity forHandshake() {
        if (closed) {
            throw new IllegalStateException("this client identity is closed");
        }
        if (System.nanoTime() - lookedAt < lookEveryMillis * 1_000_000L) {
            return current;
        }
        lookedAt = System.nanoTime();
        String newest;
        try {
            newest = WindowsStoreClientIdentity.newestBySubject(subject, machine);
        } catch (RuntimeException gone) {
            // Expired with no successor: what was loaded fails at its expiry
            // with the server's own words, which say more than this would.
            return current;
        }
        if (newest.equals(thumbprint)) {
            return current;
        }
        try {
            ClientIdentity next = new WindowsStoreClientIdentity(newest, machine);
            ClientIdentity previous = current;
            current = next;
            thumbprint = newest;
            renewals++;
            retire(previous);
            LOG.log(System.Logger.Level.INFO, "client certificate {0} renewed: now {1}",
                    subject, newest);
        } catch (RuntimeException notUsable) {
            LOG.log(System.Logger.Level.WARNING, "client certificate {0}: the newer {1} cannot "
                    + "be used, so the previous one stays: {2}", subject, newest,
                    notUsable.getMessage());
        }
        return current;
    }

    private void retire(ClientIdentity previous) {
        retiring.add(previous);
        Closer.SERVICE.schedule(() -> {
            synchronized (this) {
                if (retiring.remove(previous)) {
                    previous.close();
                }
            }
        }, GRACE_MILLIS, TimeUnit.MILLISECONDS);
    }

    synchronized long renewals() {
        return renewals;
    }

    synchronized String thumbprint() {
        return thumbprint;
    }

    @Override
    public synchronized List<byte[]> chain() {
        return current.chain();
    }

    @Override
    public synchronized int signatureScheme() {
        return current.signatureScheme();
    }

    @Override
    public synchronized byte[] sign(byte[] content) {
        return current.sign(content);
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        current.close();
        for (ClientIdentity old : retiring) {
            old.close();
        }
        retiring.clear();
    }
}
