package space.seclume.mongodb.internal;

import java.util.Locale;
import java.util.Set;

import org.bson.BsonArray;
import org.bson.BsonDocument;
import org.bson.BsonValue;

/**
 * What seclume's JFR events say about a MongoDB command: its shape, never a
 * value. {@code find shop.orders filter {status: ?, total: {$gt: ?}}} - the command,
 * the namespace, and the field names and operators of its filter or
 * pipeline, the values replaced by {@code ?} as the SQL drivers' fingerprints
 * replace literals. The same query with other values is the same shape, which
 * is what grouping by fingerprint needs - and a value, which may be anything
 * the application stores, never reaches a recording.
 */
public final class CommandShape {

    /** Under the event's fingerprint limit, with room for the masking. */
    private static final int MAX_SHAPE = 2048;

    /**
     * Not recorded as queries: the monitor's {@code hello} waits on the server
     * for up to {@code heartbeatFrequencyMS} on purpose, and the login is
     * recorded as a login.
     */
    private static final Set<String> NOT_QUERIES = Set.of("hello", "ismaster", "saslstart",
            "saslcontinue", "authenticate", "ping");

    /** The fields that hold the query's own structure, by command. */
    private static final Set<String> SHAPED = Set.of("filter", "q", "query", "pipeline",
            "sort", "projection", "u", "update");

    private static final java.util.regex.Pattern FIELD = java.util.regex.Pattern.compile(
            "[A-Za-z_$][A-Za-z0-9_.$]{0,63}");

    private CommandShape() {
    }

    /** Whether the command is one a {@code Query} event is about. */
    public static boolean recorded(BsonDocument command) {
        return !command.isEmpty()
                && !NOT_QUERIES.contains(command.getFirstKey().toLowerCase(Locale.ROOT));
    }

    /** The command's shape; see the class. */
    public static String shape(String db, BsonDocument command) {
        StringBuilder out = new StringBuilder();
        String name = command.getFirstKey();
        out.append(name).append(' ').append(db);
        BsonValue target = command.get(name);
        if (target.isString()) {
            out.append('.').append(target.asString().getValue());
        }
        for (String field : command.keySet()) {
            if (SHAPED.contains(field)) {
                out.append(' ').append(field).append(' ');
                shape(command.get(field), out);
            }
        }
        if (out.length() > MAX_SHAPE) {
            out.setLength(MAX_SHAPE);
            out.append("...");
        }
        return out.toString();
    }

    private static void shape(BsonValue value, StringBuilder out) {
        if (out.length() > MAX_SHAPE) {
            return;
        }
        if (value.isDocument()) {
            BsonDocument document = value.asDocument();
            out.append('{');
            boolean first = true;
            for (String key : document.keySet()) {
                if (!first) {
                    out.append(", ");
                }
                first = false;
                // A field name is structure; one that is not a name - a map
                // keyed by data - is masked like a value.
                out.append(FIELD.matcher(key).matches() ? key : "?").append(": ");
                shape(document.get(key), out);
            }
            out.append('}');
        } else if (value.isArray()) {
            BsonArray array = value.asArray();
            // A pipeline's stages are structure; an array of values is one value.
            if (!array.isEmpty() && array.get(0).isDocument()) {
                // Parentheses, not brackets: the fingerprint takes [..] for a
                // quoted name and masks all of it.
                out.append('(');
                for (int i = 0; i < array.size(); i++) {
                    if (i > 0) {
                        out.append(", ");
                    }
                    shape(array.get(i), out);
                }
                out.append(')');
            } else {
                out.append('?');
            }
        } else {
            out.append('?');
        }
    }

    /** Documents returned or written, as far as the reply says. */
    public static long rows(BsonDocument reply) {
        BsonValue cursor = reply.get("cursor");
        if (cursor != null && cursor.isDocument()) {
            for (String batch : new String[] {"firstBatch", "nextBatch"}) {
                BsonValue documents = cursor.asDocument().get(batch);
                if (documents != null && documents.isArray()) {
                    return documents.asArray().size();
                }
            }
        }
        BsonValue n = reply.get("n");
        return n != null && n.isNumber() ? n.asNumber().longValue() : 0;
    }
}
