package space.seclume.internal;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * The transport under {@link SeclumeSslEngine}'s TLS connection: what the
 * engine is given to unwrap goes in, what the connection writes collects until
 * the engine's next wrap takes it out.
 *
 * <p>Only TLS records pass through here - the handshake's public messages and
 * ciphertext - never plaintext, so the two queues may be heap arrays.
 *
 * <p>During the handshake the connection runs on a thread of its own and a
 * read waits for bytes, as on a socket; the engine waits in turn until that
 * thread is waiting too, or done ({@link #awaitQuiet}). After the handshake
 * the connection is read from the engine's caller, and a read with nothing
 * there throws {@link WouldBlock} instead - at a record boundary, because the
 * engine only ever puts whole records in.
 */
final class EnginePipe implements Transport {

    /** A read with nothing to read, after the handshake. */
    static final class WouldBlock extends IOException {
        private static final long serialVersionUID = 1L;

        WouldBlock(String message) {
            super(message);
        }
    }

    private static final long HANDSHAKE_SILENCE_SECONDS = 120;

    private final ReentrantLock lock = new ReentrantLock();
    private final Condition changed = lock.newCondition();
    private byte[] in = new byte[8192];
    private int inStart;
    private int inEnd;
    private byte[] out = new byte[8192];
    private int outStart;
    private int outEnd;
    private boolean blocking = true;
    private boolean waiting;
    private boolean done;
    private boolean closed;

    @Override
    public int read(ByteBuffer into) throws IOException {
        lock.lock();
        try {
            while (inEnd == inStart) {
                if (closed) {
                    return -1;
                }
                if (!blocking) {
                    throw new WouldBlock("no complete TLS record has arrived yet");
                }
                waiting = true;
                changed.signalAll();
                try {
                    // A peer silent this long in the handshake is not coming
                    // back, and a caller that dropped the engine without
                    // closing it must not keep this thread forever.
                    if (!changed.await(HANDSHAKE_SILENCE_SECONDS, TimeUnit.SECONDS)
                            && inEnd == inStart && !closed) {
                        throw new java.net.SocketTimeoutException("the server said nothing for "
                                + HANDSHAKE_SILENCE_SECONDS + " s in the TLS handshake");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new InterruptedIOException("interrupted in the TLS handshake");
                } finally {
                    waiting = false;
                }
            }
            int n = Math.min(into.remaining(), inEnd - inStart);
            into.put(in, inStart, n);
            inStart += n;
            return n;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public int write(ByteBuffer from) throws IOException {
        lock.lock();
        try {
            if (closed) {
                throw new IOException("the TLS engine is closed");
            }
            int n = from.remaining();
            if (out.length - outEnd < n) {
                int live = outEnd - outStart;
                byte[] grown = live + n > out.length ? new byte[Math.max(out.length * 2, live + n)]
                        : out;
                System.arraycopy(out, outStart, grown, 0, live);
                out = grown;
                outStart = 0;
                outEnd = live;
            }
            from.get(out, outEnd, n);
            outEnd += n;
            changed.signalAll();
            return n;
        } finally {
            lock.unlock();
        }
    }

    /** Takes {@code count} bytes of {@code src} in, for the connection to read. */
    void feed(ByteBuffer src, int count) {
        lock.lock();
        try {
            if (in.length - inEnd < count) {
                int live = inEnd - inStart;
                byte[] grown = live + count > in.length
                        ? new byte[Math.max(in.length * 2, live + count)] : in;
                System.arraycopy(in, inStart, grown, 0, live);
                in = grown;
                inStart = 0;
                inEnd = live;
            }
            src.get(in, inEnd, count);
            inEnd += count;
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /** Moves what the connection wrote into {@code dst}, as much as fits. */
    int drain(ByteBuffer dst) {
        lock.lock();
        try {
            int n = Math.min(dst.remaining(), outEnd - outStart);
            dst.put(out, outStart, n);
            outStart += n;
            if (outStart == outEnd) {
                outStart = 0;
                outEnd = 0;
            }
            return n;
        } finally {
            lock.unlock();
        }
    }

    int pendingOut() {
        lock.lock();
        try {
            return outEnd - outStart;
        } finally {
            lock.unlock();
        }
    }

    /** The length of the whole record waiting to be read, or 0. */
    int nextRecordLength() {
        lock.lock();
        try {
            return recordLength(in, inStart, inEnd - inStart);
        } finally {
            lock.unlock();
        }
    }

    /** From now on a read with nothing there does not wait. */
    void stopBlocking() {
        lock.lock();
        try {
            blocking = false;
        } finally {
            lock.unlock();
        }
    }

    /** The handshake thread is done, well or badly. */
    void handshakeDone() {
        lock.lock();
        try {
            done = true;
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Waits until the handshake thread cannot go on without bytes from the
     * peer, or is done. Its work in between is computation - signatures,
     * the certificate chain - never the network.
     *
     * @return false when it took longer than {@code millis}
     */
    boolean awaitQuiet(long millis) {
        lock.lock();
        try {
            long left = TimeUnit.MILLISECONDS.toNanos(millis);
            while (!done && !(waiting && inEnd == inStart)) {
                if (left <= 0) {
                    return false;
                }
                try {
                    left = changed.awaitNanos(left);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
            return true;
        } finally {
            lock.unlock();
        }
    }

    /**
     * The length of the whole TLS record at {@code offset}, or 0 when it has
     * not all arrived.
     */
    static int recordLength(byte[] bytes, int offset, int available) {
        if (available < 5) {
            return 0;
        }
        int length = 5 + (((bytes[offset + 3] & 0xff) << 8) | (bytes[offset + 4] & 0xff));
        return length <= available ? length : 0;
    }

    /** The same for a buffer, from its position. */
    static int recordLength(ByteBuffer src) {
        int available = src.remaining();
        if (available < 5) {
            return 0;
        }
        int at = src.position();
        int length = 5 + (((src.get(at + 3) & 0xff) << 8) | (src.get(at + 4) & 0xff));
        return length <= available ? length : 0;
    }

    @Override
    public boolean isOpen() {
        lock.lock();
        try {
            return !closed;
        } finally {
            lock.unlock();
        }
    }

    /** Ends reading; what was written stays, for the engine to send - a close_notify. */
    @Override
    public void close() {
        lock.lock();
        try {
            closed = true;
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }
}
