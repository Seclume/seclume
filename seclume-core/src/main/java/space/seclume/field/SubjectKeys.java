package space.seclume.field;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.internal.Entropy;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * A data key per subject - a customer, a patient, a tenant - so that one
 * subject's data can be made unreadable everywhere at once by deleting one
 * key: crypto-shredding.
 *
 * <pre>{@code
 * SubjectKeys subjects = SubjectKeys.of(ring, SubjectKeyStore.jdbc(dataSource, "subject_keys"));
 * EncryptedColumn email = subjects.column("customer-4711", "customer.email", Mode.DETERMINISTIC);
 * email.set(insert, 3, address);          // as with any column
 * ...
 * subjects.shred("customer-4711");          // the right to erasure: every value of theirs is noise
 * }</pre>
 *
 * <p><b>How.</b> A subject's key is 32 random bytes, made the first time the
 * subject is written for. It is stored wrapped - encrypted under the ring's
 * primary key, bound to the subject's name - in a {@link SubjectKeyStore},
 * and unwrapped into locked native memory when the subject's values are read or
 * written. Each subject's values are encrypted with a ring of its own built
 * from that key, in the same format as every other column; a value carries the
 * key commitment, so one subject's value never opens under another's key.
 * Recently used subjects' rings are kept (at most {@code cached}), the rest
 * wiped.
 *
 * <p><b>Shredding</b> deletes the wrapped key from the store and wipes the
 * cached ring: from then on {@link #column} refuses the subject, and every
 * value of theirs - in the table, in its indexes, in a log, in a copy -
 * decrypts to nothing ever again. Unless a copy of the <i>key store</i> is
 * kept somewhere: a backup of the key table still holds the wrapped key, and
 * the ring still opens it. That ends when the ring's key that wrapped it is
 * gone: rotate the ring regularly ({@link ColumnRotation} over the key table,
 * with {@code Context.ROW_ID}, rewraps every live key) and destroy the old key
 * once the backups older than the rotation have expired - after that, a shredded
 * subject stays shredded in every backup too.
 *
 * <p>The subject's name is no secret and is stored as it is given; a name that
 * says who someone is (an e-mail address) is better replaced by an id.
 */
public final class SubjectKeys implements AutoCloseable {

    /** The column of the ring the subject keys are wrapped with. */
    static final String WRAPPING = "seclume.subject-key";
    /** Every subject's ring has one key, under this number. */
    static final int SUBJECT_KEY = 1;

    private final FieldKeys ring;
    private final SubjectKeyStore store;
    private final int cached;
    private final LinkedHashMap<String, FieldKeys> rings;
    private boolean closed;

    private SubjectKeys(FieldKeys ring, SubjectKeyStore store, int cached) {
        this.ring = ring;
        this.store = store;
        this.cached = cached;
        this.rings = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, FieldKeys> eldest) {
                if (size() > SubjectKeys.this.cached) {
                    eldest.getValue().close();
                    return true;
                }
                return false;
            }
        };
    }

    /** Subject keys wrapped by {@code ring}, kept in {@code store}, the last 1000 used cached. */
    public static SubjectKeys of(FieldKeys ring, SubjectKeyStore store) {
        return of(ring, store, 1000);
    }

    /** As {@link #of(FieldKeys, SubjectKeyStore)}, with at most {@code cached} rings kept. */
    public static SubjectKeys of(FieldKeys ring, SubjectKeyStore store, int cached) {
        if (ring == null || store == null) {
            throw new IllegalArgumentException("subject keys need the ring that wraps them and a store");
        }
        if (cached < 1) {
            throw new IllegalArgumentException("at least one subject's ring is cached, not " + cached);
        }
        return new SubjectKeys(ring, store, cached);
    }

    /**
     * The subject's column, to write and read with - the subject's key made
     * now if it has none. Use it for the work at hand and ask again next time:
     * a subject's ring that falls out of the cache is wiped, and its columns
     * refuse from then on.
     */
    public EncryptedColumn column(String subject, String name, Mode mode) {
        return ring(subject, true).column(name, mode);
    }

    /**
     * The subject's column, to read with only: a subject without a key - never
     * written for, or shredded - is refused rather than given a new one.
     *
     * @throws FieldEncryptionException when the subject has no key
     */
    public EncryptedColumn existingColumn(String subject, String name, Mode mode) {
        return ring(subject, false).column(name, mode);
    }

    /** Whether the subject has a key. */
    public boolean exists(String subject) {
        check(subject);
        synchronized (this) {
            if (rings.containsKey(subject)) {
                return true;
            }
        }
        return store.load(subject) != null;
    }

    /**
     * Deletes the subject's key and wipes its ring. Every value encrypted for
     * the subject is unreadable from now on - see the class comment on
     * backups of the key store. Returns whether there was a key.
     */
    public boolean shred(String subject) {
        check(subject);
        synchronized (this) {
            FieldKeys open = rings.remove(subject);
            if (open != null) {
                open.close();
            }
        }
        return store.delete(subject);
    }

    private FieldKeys ring(String subject, boolean create) {
        check(subject);
        synchronized (this) {
            if (closed) {
                throw new IllegalStateException("these subject keys are closed");
            }
            FieldKeys open = rings.get(subject);
            if (open != null) {
                return open;
            }
        }
        byte[] context = subject.getBytes(StandardCharsets.UTF_8); // seclume-allow: a subject's name, not a secret
        EncryptedColumn wrapping = ring.column(WRAPPING, Mode.RANDOMIZED);
        byte[] wrapped = store.load(subject);
        if (wrapped == null) {
            if (!create) {
                throw new FieldEncryptionException("the subject " + subject + " has no key - it was "
                        + "shredded, or nothing was ever written for it");
            }
            try (SecretScope fresh = SecretScope.allocate(FieldKeys.KEY_LENGTH)) {
                Entropy.fill(fresh.segment(), 0, FieldKeys.KEY_LENGTH);
                fresh.length(FieldKeys.KEY_LENGTH);
                byte[] made = wrapping.encrypt(fresh.secret(), context);
                if (!store.insert(subject, made)) {
                    made = store.load(subject); // another writer was first: theirs counts
                    if (made == null) {
                        throw new FieldEncryptionException("the subject " + subject
                                + " was given a key and shredded at the same time");
                    }
                }
                wrapped = made;
            }
        }
        FieldKeys subjectRing;
        try (SecretScope key = SecretScope.allocate(FieldKeys.KEY_LENGTH)) {
            int length = wrapping.decrypt(wrapped, context, key.segment());
            if (length != FieldKeys.KEY_LENGTH) {
                throw new FieldEncryptionException("the stored key of " + subject + " is "
                        + length + " bytes, not " + FieldKeys.KEY_LENGTH);
            }
            key.length(length);
            subjectRing = FieldKeys.builder().key(SUBJECT_KEY, copyOf(key.secret())).unlisted().build();
        }
        synchronized (this) {
            FieldKeys raced = rings.get(subject);
            if (raced != null) {
                subjectRing.close();
                return raced;
            }
            rings.put(subject, subjectRing);
            return subjectRing;
        }
    }

    /** Hands the unwrapped key to the ring builder, native memory to native memory. */
    private static SecretProvider copyOf(MemorySegment key) {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                MemorySegment.copy(key, 0, target, 0, key.byteSize());
                return (int) key.byteSize();
            }

            @Override
            public int maxSecretLength() {
                return (int) key.byteSize();
            }
        };
    }

    private static void check(String subject) {
        if (subject == null || subject.isEmpty() || subject.length() > 200) {
            throw new IllegalArgumentException("a subject is a name of 1 to 200 characters");
        }
    }

    /** Wipes every cached ring. The ring that wraps the keys stays the caller's. */
    @Override
    public synchronized void close() {
        closed = true;
        for (FieldKeys open : rings.values()) {
            open.close();
        }
        rings.clear();
    }

    @Override
    public synchronized String toString() {
        return "SubjectKeys[" + rings.size() + " of at most " + cached + " cached]";
    }
}
