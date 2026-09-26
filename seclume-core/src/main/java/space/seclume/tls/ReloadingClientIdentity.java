package space.seclume.tls;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import space.seclume.secret.SecretProvider;

/**
 * A client identity that follows its certificate file.
 *
 * <p>Certificates are rotated on disk and nobody restarts the JVM for it:
 * cert-manager renews a certificate before it expires, a SPIFFE agent issues a
 * fresh SVID every hour, an operator replaces a mounted secret. A driver that
 * loaded the key once and kept it for the life of the process presents the old
 * certificate until it expires, and then every new connection fails - on a
 * schedule, at an hour nobody chose, and the fix is a restart.
 *
 * <p><b>The certificate is the signal.</b> It is public, so it can be read and
 * compared as often as needed, and a new key always comes with a new
 * certificate. The private key is never looked at to decide anything; it is
 * read through its provider only when the certificate says there is something
 * new to load.
 *
 * <p><b>Checked once per handshake, and only when a server asks.</b> A
 * connection to a server that does not want a client certificate reads
 * nothing. One that does reads a file of a few kilobytes next to a handshake
 * of several round trips.
 *
 * <p><b>A reload that fails keeps the identity that works.</b> Rotations are
 * rarely atomic - the certificate lands, then the key a moment later - and a
 * certificate that does not match the key it is loaded with is refused by the
 * pair check. That refusal is logged and recorded, the previous identity goes
 * on signing, and the next handshake after a short pause tries again. Turning
 * a half-finished rotation into an outage would be the worst available
 * reading of it.
 *
 * <p><b>The old key is released, not kept.</b> A handshake that started with
 * the previous version holds on to it until it finishes - see
 * {@link ClientIdentity#forHandshake()} - so the previous version is closed
 * after a grace period rather than at once, and then its key leaves native
 * memory. Keeping it until the next rotation would mean the old key stays
 * resident for another whole certificate lifetime.
 */
final class ReloadingClientIdentity implements ClientIdentity {

    /** How long a replaced identity stays usable for handshakes already under way. */
    static final long GRACE_MILLIS = 60_000;

    /** How long a certificate that could not be loaded is left alone before trying again. */
    static final long RETRY_MILLIS = 5_000;

    /** {@link #RETRY_MILLIS}, shorter in a test that waits it out. */
    static volatile long retryMillis = RETRY_MILLIS;

    private static final System.Logger LOG =
            System.getLogger(ReloadingClientIdentity.class.getName());

    /** One daemon thread for every identity in the process; it only ever closes things. */
    private static final class Closer {
        private static final ScheduledExecutorService SERVICE =
                Executors.newSingleThreadScheduledExecutor(runnable -> {
                    Thread thread = new Thread(runnable, "seclume-identity-closer");
                    thread.setDaemon(true);
                    return thread;
                });
    }

    private final Path certificate;
    private final SecretProvider key;

    private ClientIdentity current;
    private byte[] loaded; // seclume-allow: the certificate chain, which is public
    private byte[] refused; // seclume-allow: the certificate chain, which is public
    private long refusedAt;
    private final List<ClientIdentity> retiring = new ArrayList<>();
    private long reloads;
    private boolean closed;

    /**
     * Loads the identity now, so that a configuration that cannot work fails
     * where it is configured and not at the first handshake.
     */
    ReloadingClientIdentity(Path certificate, SecretProvider key) {
        this.certificate = certificate;
        this.key = key;
        byte[] content = read(certificate);
        this.current = new P256ClientIdentity(P256ClientIdentity.parseChain(content, certificate),
                key);
        this.loaded = content;
    }

    @Override
    public synchronized ClientIdentity forHandshake() {
        if (closed) {
            throw new IllegalStateException("this client identity is closed");
        }
        byte[] now;
        try {
            now = Files.readAllBytes(certificate); // seclume-allow: the certificate chain, which is public
        } catch (IOException | RuntimeException unreadable) {
            // Mid-rotation a file can be briefly absent. What was loaded still
            // works, and a certificate that is gone for good will show itself
            // at its expiry with a clearer message than this one.
            return current;
        }
        if (Arrays.equals(now, loaded)) {
            return current;
        }
        if (Arrays.equals(now, refused)
                && System.currentTimeMillis() - refusedAt < retryMillis) {
            return current;
        }
        space.seclume.jfr.SeclumeEvents.CertificateReload event =
                space.seclume.jfr.Observed.beginCertificateReload();
        try {
            ClientIdentity next = new P256ClientIdentity(
                    P256ClientIdentity.parseChain(now, certificate), key);
            ClientIdentity previous = current;
            current = next;
            loaded = now;
            refused = null;
            reloads++;
            retire(previous);
            space.seclume.jfr.Observed.endCertificateReload(event, certificate.toString(),
                    true, "");
            LOG.log(System.Logger.Level.INFO, "client certificate {0} reloaded", certificate);
        } catch (RuntimeException notYet) {
            refused = now;
            refusedAt = System.currentTimeMillis();
            space.seclume.jfr.Observed.endCertificateReload(event, certificate.toString(),
                    false, String.valueOf(notYet.getMessage()));
            LOG.log(System.Logger.Level.WARNING, "client certificate {0} changed and could not "
                    + "be loaded, so the previous one stays in use: {1}", certificate,
                    notYet.getMessage());
        }
        return current;
    }

    /** Closed after the grace period, unless the whole identity is closed first. */
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

    /** How often a new certificate was taken up - for tests and for a curious operator. */
    synchronized long reloads() {
        return reloads;
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

    private static byte[] read(Path file) {
        try {
            return Files.readAllBytes(file); // seclume-allow: the certificate chain, which is public
        } catch (IOException e) {
            throw new IllegalArgumentException("the client certificate chain in " + file
                    + " cannot be read", e);
        }
    }
}
