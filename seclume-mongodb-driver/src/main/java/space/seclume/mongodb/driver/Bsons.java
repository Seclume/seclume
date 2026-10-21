package space.seclume.mongodb.driver;

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.bson.BsonArray;
import org.bson.BsonBoolean;
import org.bson.BsonDocument;
import org.bson.BsonDocumentReader;
import org.bson.BsonDocumentWriter;
import org.bson.BsonInt32;
import org.bson.BsonInt64;
import org.bson.BsonObjectId;
import org.bson.BsonString;
import org.bson.BsonValue;
import org.bson.RawBsonDocument;
import org.bson.codecs.Codec;
import org.bson.codecs.CollectibleCodec;
import org.bson.codecs.Decoder;
import org.bson.codecs.DecoderContext;
import org.bson.codecs.EncoderContext;
import org.bson.codecs.configuration.CodecRegistry;
import org.bson.conversions.Bson;

import com.mongodb.ReadConcern;
import com.mongodb.WriteConcern;
import com.mongodb.client.model.Collation;

/**
 * Between the application's types and the documents commands are made of:
 * filters and updates as {@link Bson} rendered with the application's
 * {@link CodecRegistry}, documents encoded and decoded with its codecs.
 */
final class Bsons {

    private static final DecoderContext DECODING = DecoderContext.builder().build();
    private static final EncoderContext COLLECTIBLE = EncoderContext.builder()
            .isEncodingCollectibleDocument(true).build();

    private Bsons() {
    }

    static BsonDocument toDocument(Bson bson, Class<?> documentClass, CodecRegistry registry) {
        return bson == null ? null : bson.toBsonDocument(documentClass, registry);
    }

    static BsonArray toArray(List<? extends Bson> stages, Class<?> documentClass,
            CodecRegistry registry) {
        BsonArray array = new BsonArray();
        for (Bson stage : stages) {
            if (stage == null) {
                throw new IllegalArgumentException("a pipeline stage or a filter is null");
            }
            array.add(toDocument(stage, documentClass, registry));
        }
        return array;
    }

    /** A document as the server stores it; for an insert with an {@code _id} made if it has none. */
    static <T> BsonDocument encode(T document, Codec<T> codec, boolean withId) {
        if (document == null) {
            throw new IllegalArgumentException("the document is null");
        }
        T toEncode = document;
        if (withId && codec instanceof CollectibleCodec<T> collectible) {
            // As the official driver does: the id is set on the application's
            // document too, so that it knows what was inserted.
            toEncode = collectible.generateIdIfAbsentFromDocument(document);
        }
        BsonDocument encoded = new BsonDocument();
        codec.encode(new BsonDocumentWriter(encoded), toEncode, COLLECTIBLE);
        if (withId && !encoded.containsKey("_id")) {
            BsonDocument withNewId = new BsonDocument("_id", new BsonObjectId());
            withNewId.putAll(encoded);
            return withNewId;
        }
        return encoded;
    }

    @SuppressWarnings("unchecked")
    static <T> T decode(BsonDocument document, Decoder<T> decoder) {
        if (document == null) {
            return null;
        }
        if (document instanceof RawBsonDocument raw) {
            // A cursor's document as it came: read once, from its bytes.
            return raw.decode(decoder);
        }
        return decoder.decode(new BsonDocumentReader(document), DECODING);
    }

    static <T> Codec<T> codec(CodecRegistry registry, Class<T> type) {
        return registry.get(type);
    }

    static void put(BsonDocument command, String name, Bson value, Class<?> documentClass,
            CodecRegistry registry) {
        if (value != null) {
            command.put(name, toDocument(value, documentClass, registry));
        }
    }

    static void put(BsonDocument command, String name, BsonValue value) {
        if (value != null) {
            command.put(name, value);
        }
    }

    static void put(BsonDocument command, String name, String value) {
        if (value != null) {
            command.put(name, new BsonString(value));
        }
    }

    static void put(BsonDocument command, String name, Boolean value) {
        if (value != null) {
            command.put(name, BsonBoolean.valueOf(value));
        }
    }

    static void putTrue(BsonDocument command, String name, boolean value) {
        if (value) {
            command.put(name, BsonBoolean.TRUE);
        }
    }

    static void put(BsonDocument command, String name, Integer value) {
        if (value != null) {
            command.put(name, new BsonInt32(value));
        }
    }

    static void put(BsonDocument command, String name, Collation collation) {
        if (collation != null) {
            command.put(name, collation.asDocument());
        }
    }

    static void maxTime(BsonDocument command, long millis) {
        if (millis > 0) {
            command.put("maxTimeMS", new BsonInt64(millis));
        }
    }

    /** The same for an option that may not be set at all. */
    static void maxTimeIfSet(BsonDocument command, Long millis) {
        if (millis != null) {
            maxTime(command, millis.longValue());
        }
    }

    static long millis(long duration, TimeUnit unit) {
        if (duration < 0) {
            throw new IllegalArgumentException("a negative time: " + duration);
        }
        return TimeUnit.MILLISECONDS.convert(duration, unit);
    }

    /** {@code hint} as a document or as an index name - the one that is set. */
    static void hint(BsonDocument command, Bson hint, String hintString, Class<?> documentClass,
            CodecRegistry registry) {
        if (hint != null) {
            command.put("hint", toDocument(hint, documentClass, registry));
        } else if (hintString != null) {
            command.put("hint", new BsonString(hintString));
        }
    }

    static void readConcern(BsonDocument command, ReadConcern readConcern) {
        if (readConcern != null && !readConcern.isServerDefault()) {
            command.put("readConcern", readConcern.asDocument());
        }
    }

    /** The write concern of a write; {@code w: 0} goes as moreToCome (see Writes.run). */
    static void writeConcern(BsonDocument command, WriteConcern writeConcern) {
        if (writeConcern == null || writeConcern.isServerDefault()) {
            return;
        }
        command.put("writeConcern", writeConcern.asDocument());
    }

    /** An update document must consist of update operators; a replacement must not. */
    static void checkUpdate(BsonDocument update) {
        if (update.isEmpty()) {
            throw new IllegalArgumentException("an update document may not be empty");
        }
        if (!update.getFirstKey().startsWith("$")) {
            throw new IllegalArgumentException("an update document must contain only update "
                    + "operators ($set, $inc, ...), not '" + update.getFirstKey() + "'");
        }
    }

    static void checkReplacement(BsonDocument replacement) {
        if (!replacement.isEmpty() && replacement.getFirstKey().startsWith("$")) {
            throw new IllegalArgumentException("a replacement document may not contain update "
                    + "operators ('" + replacement.getFirstKey() + "')");
        }
    }
}
