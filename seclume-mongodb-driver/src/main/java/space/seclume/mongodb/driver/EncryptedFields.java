package space.seclume.mongodb.driver;

import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.List;

import org.bson.BsonBinarySubType;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.bson.types.Binary;

import com.mongodb.client.model.Filters;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.FieldEncryptionException;

/**
 * Field encryption for MongoDB documents: a field stored as the
 * {@link EncryptedColumn}'s ciphertext - BSON binary, user-defined subtype
 * {@code 0x80}, the same bytes as in a SQL column - and read back into native
 * memory; a deterministic field searched by equality. Works with this driver
 * and with the official one: it is BSON.
 *
 * <pre>
 * EncryptedColumn ssn = keys.column("patients.ssn", Mode.DETERMINISTIC);
 * patients.insertOne(new Document("_id", 7).append("ssn", EncryptedFields.encrypt(ssn, number)));
 * Document found = patients.find(EncryptedFields.eq("ssn", ssn, number)).first();
 * value.length(EncryptedFields.readInto(found, "ssn", ssn, value.segment()));
 * </pre>
 *
 * <p>Not MongoDB's own client-side field level encryption: that needs
 * libmongocrypt, keeps its keys in a key vault collection and holds them as
 * Java objects. This keeps the keys in locked native memory and needs nothing
 * on the server.
 */
public final class EncryptedFields {

    /** BSON's first user-defined binary subtype: these bytes are seclume's format. */
    public static final byte SUBTYPE = BsonBinarySubType.USER_DEFINED.getValue();

    private EncryptedFields() {
    }

    /** The field's value: the plaintext of native memory, encrypted. */
    public static Binary encrypt(EncryptedColumn column, MemorySegment plaintext) {
        return new Binary(SUBTYPE, column.encrypt(plaintext));
    }

    /** As {@link #encrypt(EncryptedColumn, MemorySegment)}, bound to {@code context}. */
    public static Binary encrypt(EncryptedColumn column, MemorySegment plaintext, byte[] context) {
        return new Binary(SUBTYPE, column.encrypt(plaintext, context));
    }

    /**
     * Decrypts {@code field} of {@code document} into native memory the caller owns.
     *
     * @return the length of the plaintext, or -1 when the field is absent or null
     * @throws FieldEncryptionException if it is not this column's, or does not authenticate
     */
    public static int readInto(Document document, String field, EncryptedColumn column,
            MemorySegment target) {
        return readInto(document, field, column, null, target);
    }

    /** As {@link #readInto(Document, String, EncryptedColumn, MemorySegment)}, bound to {@code context}. */
    public static int readInto(Document document, String field, EncryptedColumn column,
            byte[] context, MemorySegment target) {
        byte[] stored = stored(document.get(field), field);
        return stored == null ? -1 : column.decrypt(stored, context, target);
    }

    /**
     * Documents whose deterministic {@code field} holds {@code plaintext}:
     * {@code $in} over its value under every key of the ring, so that a value
     * not yet moved to the primary key is found too.
     */
    public static Bson eq(String field, EncryptedColumn column, MemorySegment plaintext) {
        List<Binary> terms = new ArrayList<>();
        for (byte[] term : column.searchTerms(plaintext)) {
            terms.add(new Binary(SUBTYPE, term));
        }
        return terms.size() == 1 ? Filters.eq(field, terms.get(0)) : Filters.in(field, terms);
    }

    /** The ciphertext - which may be on the heap: it is what the database holds. */
    private static byte[] stored(Object value, String field) {
        if (value == null) {
            return null;
        }
        if (value instanceof Binary binary) {
            if (binary.getType() != SUBTYPE) {
                throw new FieldEncryptionException(field + " is binary of subtype "
                        + (binary.getType() & 0xff) + ", not seclume's 0x80");
            }
            return binary.getData();
        }
        if (value instanceof byte[] bytes) {
            return bytes;
        }
        throw new FieldEncryptionException(field + " is a " + value.getClass().getSimpleName()
                + ", not an encrypted value");
    }
}
