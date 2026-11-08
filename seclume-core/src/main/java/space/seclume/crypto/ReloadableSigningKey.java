package space.seclume.crypto;

import java.lang.foreign.MemorySegment;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Function;
import java.util.function.Supplier;

import space.seclume.internal.Checkpoint;

/**
 * A signing key that can be read again from its source: freed before a
 * checkpoint, so that a CRaC or SnapStart image does not hold it, and read
 * again on first use after the restore. See {@link PrivateSigningKey#reloadable}.
 *
 * <p>Signatures share the read side of the lock; dropping the key, reading it
 * again and closing take the write side - nothing is freed under a signature.
 */
final class ReloadableSigningKey implements PrivateSigningKey {

    private final Supplier<? extends PrivateSigningKey> source;
    private final String what;
    private final byte[] publicKey;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private PrivateSigningKey key;                // guarded by lock; null once dropped
    private boolean closed;                       // guarded by lock

    private ReloadableSigningKey(Supplier<? extends PrivateSigningKey> source, String what,
                                 PrivateSigningKey first) {
        this.source = source;
        this.what = what;
        this.publicKey = first.publicKey();
        this.key = first;
    }

    static ReloadableSigningKey of(Supplier<? extends PrivateSigningKey> source, String what) {
        Objects.requireNonNull(source, "the key's source");
        PrivateSigningKey first = Objects.requireNonNull(source.get(), "the key's source gave none");
        ReloadableSigningKey reloadable;
        try {
            reloadable = new ReloadableSigningKey(source, what, first);
        } catch (RuntimeException e) {
            first.close();
            throw e;
        }
        Checkpoint.register(reloadable, ReloadableSigningKey::drop);
        return reloadable;
    }

    /** Before a checkpoint: the key freed; the next use reads it again. */
    private void drop() {
        lock.writeLock().lock();
        try {
            if (key != null) {
                key.close();
                key = null;
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** Whether the key is in memory now - for tests and diagnostics. */
    boolean loaded() {
        Lock read = lock.readLock();
        read.lock();
        try {
            return key != null;
        } finally {
            read.unlock();
        }
    }

    private <T> T withKey(Function<PrivateSigningKey, T> work) {
        while (true) {
            Lock read = lock.readLock();
            read.lock();
            try {
                if (closed) {
                    throw new IllegalStateException("this signing key is closed");
                }
                if (key != null) {
                    return work.apply(key);
                }
            } finally {
                read.unlock();
            }
            reload();
        }
    }

    private void reload() {
        lock.writeLock().lock();
        try {
            if (closed || key != null) {
                return;
            }
            PrivateSigningKey fresh = Objects.requireNonNull(source.get(),
                    "the key's source gave none");
            if (!Arrays.equals(fresh.publicKey(), publicKey)) {
                fresh.close();
                throw new IllegalStateException(what + " is another key at its source now than "
                        + "the one this was made with - read again after a checkpoint, it has to "
                        + "be the same key; make a new one to use another");
            }
            key = fresh;
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public boolean is(String type) {
        return withKey(k -> k.is(type));
    }

    @Override
    public byte[] publicKey() {
        return publicKey.clone();
    }

    @Override
    public int sign(String digest, boolean pss, MemorySegment message, long length,
                    MemorySegment signature) {
        return withKey(k -> k.sign(digest, pss, message, length, signature));
    }

    @Override
    public void close() {
        lock.writeLock().lock();
        try {
            closed = true;
            if (key != null) {
                key.close();
                key = null;
            }
        } finally {
            lock.writeLock().unlock();
        }
    }
}
