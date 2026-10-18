package space.seclume.mongodb.driver;

import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.bson.BsonDocument;
import org.bson.BsonInt64;
import org.bson.BsonString;
import org.bson.BsonValue;
import org.bson.codecs.configuration.CodecRegistry;

import com.mongodb.client.model.IndexModel;
import com.mongodb.client.model.IndexOptions;

/** An index as {@code createIndexes} takes it, and the name the server would give it. */
final class Indexes {

    private Indexes() {
    }

    static BsonDocument specification(IndexModel model, Class<?> documentClass,
            CodecRegistry registry) {
        BsonDocument keys = Bsons.toDocument(model.getKeys(), documentClass, registry);
        if (keys == null || keys.isEmpty()) {
            throw new IllegalArgumentException("an index needs at least one key");
        }
        IndexOptions options = model.getOptions();
        BsonDocument index = new BsonDocument("key", keys)
                .append("name", new BsonString(options.getName() != null ? options.getName()
                        : name(keys)));
        Bsons.putTrue(index, "background", options.isBackground());
        Bsons.putTrue(index, "unique", options.isUnique());
        Bsons.putTrue(index, "sparse", options.isSparse());
        Long expire = options.getExpireAfter(TimeUnit.SECONDS);
        if (expire != null) {
            index.put("expireAfterSeconds", new BsonInt64(expire));
        }
        Bsons.put(index, "v", options.getVersion());
        Bsons.put(index, "weights", options.getWeights(), documentClass, registry);
        Bsons.put(index, "default_language", options.getDefaultLanguage());
        Bsons.put(index, "language_override", options.getLanguageOverride());
        Bsons.put(index, "textIndexVersion", options.getTextVersion());
        Bsons.put(index, "2dsphereIndexVersion", options.getSphereVersion());
        Bsons.put(index, "bits", options.getBits());
        if (options.getMin() != null) {
            index.put("min", new org.bson.BsonDouble(options.getMin()));
        }
        if (options.getMax() != null) {
            index.put("max", new org.bson.BsonDouble(options.getMax()));
        }
        Bsons.put(index, "storageEngine", options.getStorageEngine(), documentClass, registry);
        Bsons.put(index, "partialFilterExpression", options.getPartialFilterExpression(),
                documentClass, registry);
        Bsons.put(index, "collation", options.getCollation());
        Bsons.put(index, "wildcardProjection", options.getWildcardProjection(), documentClass,
                registry);
        Bsons.putTrue(index, "hidden", options.isHidden());
        return index;
    }

    /** {@code a_1_b_-1}, {@code t_text}: each key and its direction or kind, joined by '_'. */
    static String name(BsonDocument keys) {
        StringBuilder name = new StringBuilder();
        for (Map.Entry<String, BsonValue> key : keys.entrySet()) {
            if (!name.isEmpty()) {
                name.append('_');
            }
            name.append(key.getKey()).append('_');
            BsonValue kind = key.getValue();
            if (kind.isString()) {
                name.append(kind.asString().getValue());
            } else if (kind.isNumber()) {
                double value = kind.asNumber().doubleValue();
                name.append(value == Math.rint(value) ? Long.toString((long) value)
                        : Double.toString(value));
            } else {
                name.append(kind.toString().replace(' ', '_'));
            }
        }
        return name.toString();
    }
}
