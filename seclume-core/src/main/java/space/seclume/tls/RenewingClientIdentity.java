package space.seclume.tls;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import space.seclume.crypto.PrivateSigningKey;
import space.seclume.secret.VaultPkiIssuer;

/**
 * A client identity whose key and certificate come from a service and are
 * replaced before they end - Vault's PKI ({@link VaultPkiClientIdentity}), the
 * SPIFFE Workload API ({@link SpiffeClientIdentity}).
 *
 * <p>Each pair is a {@link Generation}: a key in OpenSSL or CNG and its chain.
 * A handshake takes the current one ({@link #forHandshake()}) and keeps it to
 * its end; a replaced one is closed - its key leaving native memory - a minute
 * later. When to look for the next pair is the subclass's to say; a look that
 * fails is repeated, sooner the closer the end, while the pair in hand still
 * works. Each look is a {@code space.seclume.CertificateRenewal} event.
 */
abstract class RenewingClientIdentity implements ClientIdentity {

    /** How long a replaced key stays usable for handshakes already under way. */
    static final long GRACE_MILLIS = 60_000;

    private static final System.Logger LOG =
            System.getLogger(RenewingClientIdentity.class.getName());

    /** One key and its chain: what a handshake holds. */
    static final class Generation implements ClientIdentity {

        private final List<byte[]> chain;
        private final PrivateSigningKey key;
        private final int scheme;
        private final String digest;
        final Instant notBefore;
        final Instant notAfter;
        final java.math.BigInteger serial; // seclume-allow: a certificate's serial number, which is public
        private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
        private boolean closed;

        /** Takes {@code key}, an EC key on P-256 or P-384, and closes it if the pair will not do. */
        Generation(List<X509Certificate> chain, PrivateSigningKey key) {
            try {
                if (!key.is("EC") || !(chain.get(0).getPublicKey() instanceof ECPublicKey ec)) {
                    throw new IllegalArgumentException("a client certificate for seclume's TLS "
                            + "has a P-256 or P-384 key - this one is not EC");
                }
                int field = ec.getParams().getCurve().getField().getFieldSize();
                if (field == 256) {
                    scheme = HandshakeSignature.ECDSA_SECP256R1_SHA256;
                    digest = "SHA256";
                } else if (field == 384) {
                    scheme = HandshakeSignature.ECDSA_SECP384R1_SHA384;
                    digest = "SHA384";
                } else {
                    throw new IllegalArgumentException("a client certificate for seclume's "
                            + "TLS has a P-256 or P-384 key - this one is on a " + field
                            + "-bit curve");
                }
                List<byte[]> der = new ArrayList<>();
                for (X509Certificate certificate : chain) {
                    der.add(certificate.getEncoded());
                }
                this.chain = List.copyOf(der);
            } catch (CertificateEncodingException | RuntimeException e) {
                key.close();
                if (e instanceof RuntimeException runtime) {
                    throw runtime;
                }
                throw new IllegalStateException("a certificate could not be encoded", e);
            }
            this.key = key;
            this.notBefore = chain.get(0).getNotBefore().toInstant();
            this.notAfter = chain.get(0).getNotAfter().toInstant();
            this.serial = chain.get(0).getSerialNumber();
        }

        @Override
        public List<byte[]> chain() {
            return chain;
        }

        @Override
        public int signatureScheme() {
            return scheme;
        }

        @Override
        public byte[] sign(byte[] content) {
            lock.readLock().lock();
            try {
                if (closed) {
                    throw new IllegalStateException("this client identity is closed");
                }
                try (Arena arena = Arena.ofConfined()) {
                    // Public on both sides: the content comes from a transcript
                    // the server has too, and a signature is meant to be seen.
                    MemorySegment message = arena.allocate(Math.max(1, content.length));
                    MemorySegment.copy(content, 0, message, ValueLayout.JAVA_BYTE, 0,
                            content.length);
                    MemorySegment out = arena.allocate(PrivateSigningKey.MAX_SIGNATURE);
                    int written = key.sign(digest, false, message, content.length, out);
                    return out.asSlice(0, written).toArray(ValueLayout.JAVA_BYTE);
                }
            } finally {
                lock.readLock().unlock();
            }
        }

        @Override
        public void close() {
            lock.writeLock().lock();
            try {
                if (!closed) {
                    closed = true;
                    key.close();
                }
            } finally {
                lock.writeLock().unlock();
            }
        }
    }

    private final Clock clock;
    private ScheduledExecutorService scheduler;
    private final List<Generation> retiring = new ArrayList<>();
    private Generation current;
    private Instant nextLook;
    private int generations;
    private boolean closed;

    RenewingClientIdentity(Clock clock) {
        this.clock = clock;
    }

    /**
     * Obtains the first pair now - so that a configuration that cannot work
     * fails where it is configured - and schedules the next look. A subclass
     * calls it last in its constructor.
     */
    final void start(String thread) throws IOException {
        Generation first = look(null);
        if (first == null) {
            throw new IOException("no certificate to begin with");
        }
        synchronized (this) {
            this.current = first;
            this.generations = 1;
            this.nextLook = nextLook(first);
            this.scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
                Thread daemon = new Thread(runnable, thread);
                daemon.setDaemon(true);
                return daemon;
            });
        }
        schedule(Duration.between(clock.instant(), nextLook()));
    }

    /**
     * A new pair, or {@code null} when the service still has the one in hand
     * ({@code current}, {@code null} the first time).
     */
    abstract Generation obtain(Generation current) throws IOException;

    /** When to look for the pair after {@code generation}. */
    abstract Instant nextLook(Generation generation);

    /** What the certificate is called in recordings and logs. */
    abstract String name();

    /** Where it comes from - a Vault path, a socket. */
    abstract String source();

    /** Lets go of the service - a token, nothing. */
    abstract void release();

    private Generation look(Generation now) throws IOException {
        space.seclume.jfr.SeclumeEvents.CertificateRenewal event =
                space.seclume.jfr.Observed.beginCertificateRenewal();
        try {
            Generation next = obtain(now);
            Generation inUse = next != null ? next : now;
            space.seclume.jfr.Observed.endCertificateRenewal(event, name(), source(), true,
                    inUse == null ? 0 : inUse.notAfter.toEpochMilli(), null);
            return next;
        } catch (IOException | RuntimeException e) {
            space.seclume.jfr.Observed.endCertificateRenewal(event, name(), source(), false,
                    now == null ? 0 : now.notAfter.toEpochMilli(), e.getMessage());
            throw e;
        }
    }

    /** Looks now; a new pair is presented by the next handshake. Whether there was one. */
    boolean renewNow() throws IOException {
        Generation now;
        synchronized (this) {
            now = current;
        }
        Generation next = look(now);
        synchronized (this) {
            if (next == null) {
                return false;
            }
            if (closed) {
                next.close();
                return false;
            }
            Generation previous = current;
            current = next;
            generations++;
            nextLook = nextLook(next);
            retire(previous);
        }
        LOG.log(System.Logger.Level.INFO, "a new client certificate {0} from {1}, valid until "
                + "{2}; the next handshake presents it", name(), source(), next.notAfter);
        return true;
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
                schedule(Duration.between(clock.instant(), nextLook()));
            } else {
                // the same pair again: not rotated yet - ask again a little later
                schedule(VaultPkiIssuer.retryAfter(clock.instant(), notAfter()));
            }
        } catch (IOException | RuntimeException e) {
            Duration retry = VaultPkiIssuer.retryAfter(clock.instant(), notAfter());
            LOG.log(System.Logger.Level.WARNING, "the client certificate {0} could not be "
                    + "renewed from {1} ({2}); the one in hand ends {3}, trying again in {4}s",
                    name(), source(), e.getMessage(), notAfter(), retry.toSeconds());
            schedule(retry);
        }
    }

    /** Closed after the grace period, unless the whole identity is closed first. */
    private void retire(Generation previous) {
        retiring.add(previous);
        scheduler.schedule(() -> {
            synchronized (this) {
                if (retiring.remove(previous)) {
                    previous.close();
                }
            }
        }, GRACE_MILLIS, TimeUnit.MILLISECONDS);
    }

    synchronized Instant notAfter() {
        return current.notAfter;
    }

    synchronized Instant nextLook() {
        return nextLook;
    }

    /** How many pairs it has had, the first included. */
    synchronized int generations() {
        return generations;
    }

    @Override
    public synchronized ClientIdentity forHandshake() {
        if (closed) {
            throw new IllegalStateException("this client identity is closed");
        }
        return current;
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
    public byte[] sign(byte[] content) {
        return forHandshake().sign(content);
    }

    @Override
    public void close() {
        synchronized (this) {
            if (closed) {
                return;
            }
            closed = true;
            if (current != null) {
                current.close();
            }
            for (Generation old : retiring) {
                old.close();
            }
            retiring.clear();
        }
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
        release();
    }
}
