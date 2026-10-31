package space.seclume.elasticsearch;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.FieldEncryptionException;
import space.seclume.field.FieldKeys;

/**
 * Chosen fields of a search document encrypted before it is indexed - the
 * cluster, its snapshots and whoever queries it without the ring see Base64
 * ciphertext - and opened again when it is read.
 *
 * <pre>{@code
 * EncryptedDocument patients = EncryptedDocument.of(keys, "patients")
 *         .field("ssn", Mode.DETERMINISTIC)      // searchable with a term query
 *         .field("diagnosis", Mode.RANDOMIZED);
 * es.index(i -> i.index("patients").document(patients.encrypt(document)));
 * es.search(s -> s.query(q -> q.terms(t -> t.field("ssn.keyword")
 *         .terms(v -> v.value(patients.searchTerms("ssn", "123-45-6789").stream().map(FieldValue::of).toList())))), Map.class);
 * Map<String, Object> plain = patients.decrypt(hit.source());
 * }</pre>
 *
 * <p>Only string values of top-level fields are encrypted; a field that is
 * missing or {@code null} stays so. A deterministic field is found again with
 * an exact ({@code keyword}) term query on {@link #searchTerms} - one term per
 * key in the ring, the primary's first, so a rotation is searched through.
 * Full-text search, ranges and aggregations on an encrypted field are not
 * possible: what the cluster cannot read it cannot analyse. Each index name and
 * field has its own key, so a value copied into another field does not open
 * there; copied into the same field of another document, it does - the
 * document's id is not part of the value.
 */
public final class EncryptedDocument {

    private final FieldKeys ring;
    private final String index;
    private final Map<String, Mode> fields = new LinkedHashMap<>();

    private EncryptedDocument(FieldKeys ring, String index) {
        this.ring = ring;
        this.index = index;
    }

    /** @param ring the ring; {@code null} for the installed one */
    public static EncryptedDocument of(FieldKeys ring, String index) {
        FieldKeys chosen = ring != null ? ring : FieldKeys.installed();
        if (chosen == null) {
            throw new IllegalStateException("no field encryption keys: give a ring, or install one");
        }
        if (index == null || index.isBlank()) {
            throw new IllegalArgumentException("an encrypted document needs its index's name: part of its keys");
        }
        return new EncryptedDocument(chosen, index);
    }

    /** A field to encrypt, and how. */
    public EncryptedDocument field(String name, Mode mode) {
        if (name == null || name.isBlank() || mode == null) {
            throw new IllegalArgumentException("a field needs a name and a mode");
        }
        fields.put(name, mode);
        return this;
    }

    /** A copy of {@code source} with the chosen fields encrypted, the rest as it was. */
    public Map<String, Object> encrypt(Map<String, ?> source) {
        Map<String, Object> out = new LinkedHashMap<>(source);
        for (Map.Entry<String, Mode> field : fields.entrySet()) {
            Object value = source.get(field.getKey());
            if (value == null) {
                continue;
            }
            if (!(value instanceof String text)) {
                throw new IllegalArgumentException("the field " + field.getKey() + " is encrypted as a "
                        + "string, and this one is a " + value.getClass().getSimpleName());
            }
            out.put(field.getKey(), base64(column(field.getKey()).encrypt(utf8(text))));
        }
        return out;
    }

    /** A copy of {@code source} with the chosen fields opened again. */
    public Map<String, Object> decrypt(Map<String, ?> source) {
        Map<String, Object> out = new LinkedHashMap<>(source);
        for (String name : fields.keySet()) {
            Object value = source.get(name);
            if (value == null) {
                continue;
            }
            if (!(value instanceof String text)) {
                throw new FieldEncryptionException("the field " + name + " holds no ciphertext");
            }
            byte[] stored;
            try {
                // seclume-allow: ciphertext, not a secret
                stored = java.util.Base64.getDecoder().decode(text);
            } catch (IllegalArgumentException e) {
                throw new FieldEncryptionException("the field " + name + " holds no ciphertext", e);
            }
            EncryptedColumn column = column(name);
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment plain = arena.allocate(Math.max(1, column.plaintextLength(stored)));
                int length = column.decrypt(stored, plain);
                // The document is the application's own data, read as a String like every other field.
                // seclume-allow: the application's document, which it reads as a String anyway
                out.put(name, new String(plain.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE),
                        StandardCharsets.UTF_8));
                plain.fill((byte) 0);
            }
        }
        return out;
    }

    /**
     * What a deterministic field holds for {@code value}, under each key of the
     * ring, the primary's first - for a {@code terms} query.
     */
    public List<String> searchTerms(String field, String value) {
        Mode mode = fields.get(field);
        if (mode != Mode.DETERMINISTIC) {
            throw new IllegalArgumentException("only a deterministic field is searched, and " + field
                    + " is " + (mode == null ? "not encrypted" : "randomized"));
        }
        EncryptedColumn column = column(field);
        List<String> terms = new ArrayList<>();
        for (byte[] term : column.searchTerms(utf8(value))) {
            terms.add(base64(term));
        }
        return terms;
    }

    private EncryptedColumn column(String field) {
        return ring.column("search." + index + "." + field, fields.get(field));
    }

    private static MemorySegment utf8(String text) {
        // seclume-allow: the application's document, which it holds as a String anyway
        return MemorySegment.ofArray(text.getBytes(StandardCharsets.UTF_8));
    }

    private static String base64(byte[] ciphertext) {
        return java.util.Base64.getEncoder().encodeToString(ciphertext); // seclume-allow: ciphertext
    }
}
