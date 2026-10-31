package space.seclume.field;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Hkdf;
import space.seclume.internal.Base64Off;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * The data keys of field encryption: a ring of 256-bit keys, each under a
 * number, one of them the key new values are encrypted with.
 *
 * <p>Each key is read once, when the ring is built, from a
 * {@link SecretProvider} - Vault, a cloud secret manager, a file, Vault's
 * transit engine unwrapping a data key ({@code provider=vault-transit}) - into
 * locked native memory, and stays there until {@link #close}. A key is either
 * the 32 bytes themselves or their Base64, which is how a secret manager
 * carries them; nothing else is taken.
 *
 * <pre>
 * try (FieldKeys keys = FieldKeys.builder()
 *         .key(1, SecretProviders.fromUri("vault?address=https://vault:8200&amp;path=secret/data/app&amp;field=field-key-1&amp;..."))
 *         .key(2, SecretProviders.fromUri("vault?...&amp;field=field-key-2"))
 *         .primary(2)
 *         .build()) {
 *     EncryptedColumn ssn = keys.column("patient.ssn", EncryptedColumn.Mode.DETERMINISTIC);
 *     ...
 * }
 * </pre>
 *
 * <h2>Rotation</h2>
 *
 * <p>Every value carries the number of the key it was encrypted with. A new
 * key is added under a new number and made primary; values under the old one
 * still decrypt, and {@link EncryptedColumn#reencrypt} moves them over one at
 * a time - with the plaintext in native memory only. The old key is dropped
 * from the ring when no value uses it any more.
 *
 * <h2>One key per column</h2>
 *
 * <p>A column does not encrypt with the data key itself but with a key derived
 * from it, its name and its mode (HKDF-SHA-256) - and a second key from the
 * same derivation commits every value to the key it was made with. The same value in two columns
 * therefore never has the same ciphertext, even deterministically, and a
 * ciphertext copied from one column into another does not decrypt there.
 */
public final class FieldKeys implements AutoCloseable {

    /** A data key is 256 bits; AES-256-GCM-SIV is what it keys. */
    public static final int KEY_LENGTH = 32;

    private static final MemorySegment SALT = utf8("seclume field encryption v1");

    private final SortedMap<Integer, SecretScope> keys;
    private final int primary;
    private final Map<String, EncryptedColumn> columns = new HashMap<>();
    /** Values are encrypted under the read lock; {@link #close} wipes under the write lock. */
    private final ReentrantReadWriteLock use = new ReentrantReadWriteLock();
    private volatile boolean closed;

    private FieldKeys(SortedMap<Integer, SecretScope> keys, int primary) {
        this.keys = keys;
        this.primary = primary;
    }

    /** The ring {@link #install} made available to code that cannot be handed one. */
    private static volatile FieldKeys installed;

    /**
     * Makes {@code keys} the ring of code that is constructed by a framework
     * rather than handed one - JPA attribute converters, chiefly. The Spring
     * Boot starter installs the ring it builds; closing an installed ring
     * uninstalls it.
     *
     * @param keys the ring, or {@code null} to uninstall
     */
    public static void install(FieldKeys keys) {
        if (keys != null) {
            keys.checkOpen();
        }
        installed = keys;
    }

    /**
     * The installed ring.
     *
     * @throws IllegalStateException if none is - with what to do about it
     */
    public static FieldKeys installed() {
        FieldKeys keys = installed;
        if (keys == null) {
            throw new IllegalStateException("no field encryption keys are installed: configure "
                    + "seclume.field-encryption.keys.<n>.* with the Spring Boot starter, or call "
                    + "FieldKeys.install(keys) before the first value is encrypted");
        }
        return keys;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** The number new values are encrypted under. */
    public int primary() {
        return primary;
    }

    /** The numbers of the ring, in ascending order. */
    public List<Integer> keyIds() {
        return List.copyOf(keys.keySet());
    }

    /**
     * The column of this name and mode, made once and then shared.
     *
     * @param name the column's name as the application chooses it, usually
     *             {@code table.column}; it binds every value to the column, so
     *             it must not change while values exist
     */
    public synchronized EncryptedColumn column(String name, EncryptedColumn.Mode mode) {
        checkOpen();
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("a column needs a name: it is part of its key");
        }
        if (mode == null) {
            throw new IllegalArgumentException("a column needs a mode");
        }
        return columns.computeIfAbsent(mode.name() + '\u0000' + name,
                ignored -> new EncryptedColumn(this, name, mode, derive(name, mode)));
    }

    /**
     * HKDF-SHA-256 of each data key: salt {@code "seclume field encryption v1"},
     * info the mode's flag byte, a zero, and the column's name in UTF-8.
     */
    private Map<Integer, SecretScope> derive(String name, EncryptedColumn.Mode mode) {
        Map<Integer, SecretScope> derived = new LinkedHashMap<>();
        try (Arena arena = Arena.ofConfined()) {
            byte[] label = utf8Bytes(name);
            MemorySegment info = arena.allocate(2L + label.length);
            info.set(ValueLayout.JAVA_BYTE, 0, mode.flag());
            info.set(ValueLayout.JAVA_BYTE, 1, (byte) 0);
            MemorySegment.copy(label, 0, info, ValueLayout.JAVA_BYTE, 2, label.length);
            for (Map.Entry<Integer, SecretScope> key : keys.entrySet()) {
                // 64 bytes: the column's encryption key, then its commitment key.
                SecretScope columnKey = SecretScope.allocate(2 * KEY_LENGTH);
                try (SecretScope prk = SecretScope.in(arena, KEY_LENGTH)) {
                    Hkdf.extract(HashAlgorithm.SHA_256, SALT, key.getValue().secret(),
                            prk.segment(), 0);
                    Hkdf.expand(HashAlgorithm.SHA_256, prk.segment(), info,
                            columnKey.segment(), 0, 2 * KEY_LENGTH);
                    columnKey.length(2 * KEY_LENGTH);
                } catch (RuntimeException e) {
                    columnKey.close();
                    derived.values().forEach(SecretScope::close);
                    throw e;
                }
                derived.put(key.getKey(), columnKey);
            }
        }
        return Collections.unmodifiableMap(derived);
    }

    Lock lock() {
        return use.readLock();
    }

    void checkOpen() {
        if (closed) {
            throw new IllegalStateException("these field keys are closed - their memory was wiped");
        }
    }

    /** Wipes every data key and every column key. Columns made from this ring stop working. */
    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        if (installed == this) {
            installed = null;
        }
        use.writeLock().lock();
        try {
            closed = true;
            for (EncryptedColumn column : columns.values()) {
                column.wipe();
            }
            columns.clear();
            keys.values().forEach(SecretScope::close);
        } finally {
            use.writeLock().unlock();
        }
    }

    @Override
    public String toString() {
        return "FieldKeys[keys=" + keys.keySet() + ", primary=" + primary
                + (closed ? ", closed" : "") + "]";
    }

    private static MemorySegment utf8(String text) {
        byte[] bytes = utf8Bytes(text);
        MemorySegment segment = Arena.global().allocate(bytes.length);
        MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return segment;
    }

    /** A column's name or a constant label: public, part of the schema, not a secret. */
    static byte[] utf8Bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8); // seclume-allow: a column name, not a secret
    }

    /** Collects the keys; {@link #build} reads them. */
    public static final class Builder {

        private final Map<Integer, SecretProvider> providers = new TreeMap<>();
        private Integer primary;

        private Builder() {
        }

        /**
         * A data key under {@code id}, read from {@code provider} when the
         * ring is built. The provider is closed then; the key stays.
         *
         * @param id a positive number, stored with every value encrypted under
         *           this key - so a number must never be reused for another key
         */
        public Builder key(int id, SecretProvider provider) {
            if (id <= 0) {
                throw new IllegalArgumentException("a key's number is positive, not " + id);
            }
            if (provider == null) {
                throw new IllegalArgumentException("key " + id + " needs a provider");
            }
            if (providers.putIfAbsent(id, provider) != null) {
                throw new IllegalArgumentException("key " + id + " is given twice");
            }
            return this;
        }

        /** The key new values are encrypted with; the highest number if not set. */
        public Builder primary(int id) {
            this.primary = id;
            return this;
        }

        /** Reads every key; on any failure, none stays in memory. */
        public FieldKeys build() {
            if (providers.isEmpty()) {
                throw new IllegalArgumentException("field encryption needs at least one key");
            }
            int chosen = primary != null ? primary : ((TreeMap<Integer, SecretProvider>) providers)
                    .lastKey();
            if (!providers.containsKey(chosen)) {
                throw new IllegalArgumentException("the primary key " + chosen
                        + " is not among the keys " + providers.keySet());
            }
            SortedMap<Integer, SecretScope> read = new TreeMap<>();
            List<RuntimeException> failures = new ArrayList<>();
            try {
                for (Map.Entry<Integer, SecretProvider> entry : providers.entrySet()) {
                    read.put(entry.getKey(), read(entry.getKey(), entry.getValue()));
                }
            } catch (RuntimeException e) {
                read.values().forEach(SecretScope::close);
                failures.add(e);
            } finally {
                for (SecretProvider provider : providers.values()) {
                    try {
                        provider.close();
                    } catch (Exception e) {
                        // the key is read; a source that does not close cleanly changes nothing
                    }
                }
            }
            if (!failures.isEmpty()) {
                throw failures.get(0);
            }
            FieldKeys keys = new FieldKeys(Collections.unmodifiableSortedMap(read), chosen);
            Map<Integer, String> sources = new TreeMap<>();
            providers.forEach((id, provider) -> sources.put(id,
                    space.seclume.inventory.CryptoInventory.kindOf(provider)));
            space.seclume.inventory.CryptoInventory.ring(keys, () -> keys.closed, sources, chosen,
                    "AES-256-GCM-SIV");
            return keys;
        }

        /** 32 bytes as they are, or their Base64 - decoded off the heap. */
        private static SecretScope read(int id, SecretProvider provider) {
            try (SecretScope given = SecretScope.fromProvider(provider)) {
                SecretScope key = SecretScope.allocate(Math.max(KEY_LENGTH,
                        Base64Off.decodedUpperBound(given.length())));
                try {
                    if (given.length() == KEY_LENGTH) {
                        if (allBase64Text(given)) {
                            // Random bytes are all Base64 characters once in 2^64: this is
                            // text - the Base64 of 24 bytes, a password - and no AES-256 key.
                            throw new IllegalArgumentException("key " + id + " is 32 characters "
                                    + "of text, not 32 random bytes; give the Base64 of a "
                                    + "32-byte key (44 characters)");
                        }
                        MemorySegment.copy(given.secret(), 0, key.segment(), 0, KEY_LENGTH);
                        key.length(KEY_LENGTH);
                        return key;
                    }
                    int decoded;
                    try {
                        decoded = Base64Off.decode(given.segment(), 0, trimmed(given),
                                key.segment(), 0);
                    } catch (RuntimeException notBase64) {
                        throw new IllegalArgumentException("key " + id + " is neither 32 bytes "
                                + "nor their Base64", notBase64);
                    }
                    if (decoded != KEY_LENGTH) {
                        throw new IllegalArgumentException("key " + id + " is " + decoded
                                + " bytes; field encryption takes 32 (AES-256)");
                    }
                    key.length(KEY_LENGTH);
                    return key;
                } catch (RuntimeException e) {
                    key.close();
                    throw e;
                }
            }
        }

        private static boolean allBase64Text(SecretScope given) {
            int text = 0;
            for (int i = 0; i < given.length(); i++) {
                int c = given.segment().get(ValueLayout.JAVA_BYTE, i) & 0xff;
                text |= (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                        || c == '+' || c == '/' || c == '=' || c == '-' || c == '_' ? 0 : 1;
            }
            return text == 0;
        }

        /** A file or a secret often ends in a line break; Base64 never does. */
        private static int trimmed(SecretScope given) {
            int length = given.length();
            while (length > 0) {
                byte last = given.segment().get(ValueLayout.JAVA_BYTE, length - 1L);
                if (last != '\n' && last != '\r' && last != ' ' && last != '\t') {
                    break;
                }
                length--;
            }
            return length;
        }
    }

}
