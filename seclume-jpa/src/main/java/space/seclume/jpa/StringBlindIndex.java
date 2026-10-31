package space.seclume.jpa;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

import space.seclume.field.BlindIndex;
import space.seclume.field.BlindIndex.Transform;
import space.seclume.field.FieldKeys;

/**
 * A {@link BlindIndex} for a {@code String} attribute: the index value an
 * entity stores next to its encrypted attribute, and a search through a
 * repository that returns what matches - for Jakarta Data, Spring Data, plain
 * JPA alike.
 *
 * <pre>
 * &#64;Entity
 * class Patient {
 *     static final StringBlindIndex NAME = StringBlindIndex.of("patient.name", 16,
 *             Transform.prefix(3).caseInsensitive());
 *
 *     &#64;Convert(converter = NameConverter.class)      // randomized
 *     String name;
 *
 *     &#64;Column(name = "name_index")
 *     Long nameIndex;
 *
 *     void name(String name) {
 *         this.name = name;
 *         this.nameIndex = NAME.term(name);              // where the value is set
 *     }
 * }
 *
 * &#64;Repository
 * interface Patients {
 *     &#64;Query("where nameIndex in :terms")
 *     List&lt;Patient&gt; byNameIndex(List&lt;Long&gt; terms);
 * }
 *
 * List&lt;Patient&gt; found = Patient.NAME.find("Mül", patients::byNameIndex, Patient::name);
 * </pre>
 *
 * <p>The index value is set where the attribute is - in the constructor and
 * the setter - rather than in a {@code @PrePersist} callback: Jakarta Data
 * repositories on Hibernate work through a stateless session, which does not
 * call an entity's callbacks.
 *
 * <p>{@link #find} asks the repository for every row under the value's
 * {@link BlindIndex#searchTerms search terms} - one per key in the ring, so
 * that rows indexed before a rotation are found - and keeps those whose
 * attribute {@link BlindIndex#matches matches}: an index of few bits returns
 * many rows that only share the index value, which is the point of it.
 *
 * <p>The ring is the one {@link FieldKeys#install installed}, looked up when
 * an index value is first asked for, as with the converters; or the one given
 * to {@link #of(FieldKeys, String, int, Transform)}. Values are
 * {@code String}s and so on the heap already; their UTF-8 bytes are wiped
 * after use.
 */
public final class StringBlindIndex {

    private final FieldKeys keys;
    private final String name;
    private final int bits;
    private final Transform transform;

    private StringBlindIndex(FieldKeys keys, String name, int bits, Transform transform) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("a blind index needs a name: it is part of its key");
        }
        if (bits < 1 || bits > 64) {
            throw new IllegalArgumentException("a blind index has 1 to 64 bits, not " + bits);
        }
        if (transform == null) {
            throw new IllegalArgumentException("a blind index needs a transform");
        }
        this.keys = keys;
        this.name = name;
        this.bits = bits;
        this.transform = transform;
    }

    /**
     * The index of this name, size and transform in the installed ring.
     *
     * @param name      usually the column's, {@code table.column}; part of the key
     * @param bits      1 to 64; see {@link BlindIndex#bitsFor}
     * @param transform what of the value is indexed
     */
    public static StringBlindIndex of(String name, int bits, Transform transform) {
        return new StringBlindIndex(null, name, bits, transform);
    }

    /** The same, in the ring given rather than the installed one. */
    public static StringBlindIndex of(FieldKeys keys, String name, int bits, Transform transform) {
        if (keys == null) {
            throw new IllegalArgumentException("a ring, or of(name, bits, transform) for the installed one");
        }
        return new StringBlindIndex(keys, name, bits, transform);
    }

    /** The index itself, from the ring given or installed. */
    public BlindIndex index() {
        return (keys != null ? keys : FieldKeys.installed()).blindIndex(name, bits, transform);
    }

    /** The index value to store with {@code value}, or {@code null} for {@code null}. */
    public Long term(String value) {
        if (value == null) {
            return null;
        }
        byte[] utf8 = utf8(value);
        try {
            return index().term(MemorySegment.ofArray(utf8));
        } finally {
            Arrays.fill(utf8, (byte) 0);
        }
    }

    /** The index values to search for {@code value}: the primary key's first, one per key. */
    public List<Long> searchTerms(String value) {
        if (value == null) {
            throw new IllegalArgumentException("NULL is searched with 'is null', not by its index");
        }
        byte[] utf8 = utf8(value);
        try {
            return index().searchTerms(MemorySegment.ofArray(utf8));
        } finally {
            Arrays.fill(utf8, (byte) 0);
        }
    }

    /** Whether {@code value} is {@code wanted} as the index sees it; {@code null} matches nothing. */
    public boolean matches(String value, String wanted) {
        if (value == null || wanted == null) {
            return false;
        }
        byte[] a = utf8(value);
        byte[] b = utf8(wanted);
        try {
            return index().matches(MemorySegment.ofArray(a), MemorySegment.ofArray(b));
        } finally {
            Arrays.fill(a, (byte) 0);
            Arrays.fill(b, (byte) 0);
        }
    }

    /** The candidates whose attribute matches {@code wanted}, in their order. */
    public <T> List<T> keep(Iterable<? extends T> candidates, Function<? super T, String> attribute,
            String wanted) {
        List<T> kept = new ArrayList<>();
        for (T candidate : candidates) {
            if (matches(attribute.apply(candidate), wanted)) {
                kept.add(candidate);
            }
        }
        return kept;
    }

    /**
     * Searches by the index: {@code query} is given the search terms and
     * returns the rows indexed under any of them - a repository method such as
     * {@code @Query("where nameIndex in :terms")} - and what it returns is
     * kept where {@code attribute} matches {@code wanted}.
     */
    public <T> List<T> find(String wanted, Function<? super List<Long>, ? extends Iterable<? extends T>> query,
            Function<? super T, String> attribute) {
        return keep(query.apply(searchTerms(wanted)), attribute, wanted);
    }

    /**
     * Searches for any of several values in one query: the search terms of
     * all of them, and the rows kept that match one. This is how a range is
     * searched without an index that reveals order - as the buckets it
     * covers: with {@code prefix(7)} over ISO dates, January to March 2026 is
     * {@code findAny(List.of("2026-01", "2026-02", "2026-03"), ...)}.
     *
     * @param wanted the values, at least one; {@code null} among them is refused
     */
    public <T> List<T> findAny(java.util.Collection<String> wanted,
            Function<? super List<Long>, ? extends Iterable<? extends T>> query,
            Function<? super T, String> attribute) {
        if (wanted == null || wanted.isEmpty()) {
            throw new IllegalArgumentException("at least one value to search for");
        }
        java.util.LinkedHashSet<Long> terms = new java.util.LinkedHashSet<>();
        for (String value : wanted) {
            terms.addAll(searchTerms(value));
        }
        List<T> kept = new ArrayList<>();
        for (T candidate : query.apply(List.copyOf(terms))) {
            String value = attribute.apply(candidate);
            for (String one : wanted) {
                if (matches(value, one)) {
                    kept.add(candidate);
                    break;
                }
            }
        }
        return kept;
    }

    private static byte[] utf8(String value) {
        // seclume-allow: the attribute is a String already - this keeps it from the database
        return value.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public String toString() {
        return "StringBlindIndex[" + name + ", " + bits + " bits]";
    }
}
