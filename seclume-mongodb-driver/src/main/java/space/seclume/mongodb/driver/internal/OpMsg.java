package space.seclume.mongodb.driver.internal;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.zip.CRC32C;

import org.bson.BsonArray;
import org.bson.BsonBinaryReader;
import org.bson.BsonBinaryWriter;
import org.bson.BsonDocument;
import org.bson.BSONException;
import org.bson.BsonMaximumSizeExceededException;
import org.bson.BsonString;
import org.bson.BsonType;
import org.bson.RawBsonDocument;
import org.bson.codecs.BsonDocumentCodec;
import org.bson.codecs.DecoderContext;
import org.bson.codecs.EncoderContext;
import org.bson.io.BasicOutputBuffer;

import com.mongodb.MongoInternalException;

/**
 * OP_MSG, the one message format of the wire protocol since MongoDB 3.6: a
 * 16-byte header, flag bits, then sections - one body document (kind 0) and
 * any number of document sequences (kind 1), which are fields of the body
 * sent apart so that a batch of inserts need not be one large array.
 *
 * <p>Written from the OP_MSG specification
 * (github.com/mongodb/specifications, source/message/OP_MSG.md) and the
 * server's wire protocol reference; no driver code was copied.
 *
 * <p>The reply parser is strict and is fuzzed: whatever arrives, it either
 * returns a document or throws {@link MongoInternalException} - never another
 * exception, never a buffer read past what was announced.
 */
public final class OpMsg {

    public static final int HEADER = 16;
    static final int OP_MSG = 2013;
    public static final int OP_COMPRESSED = 2012;
    static final int OP_REPLY = 1;

    static final int CHECKSUM_PRESENT = 1;
    public static final int MORE_TO_COME = 1 << 1;
    /**
     * Bits 0 to 15 are required: a receiver that does not know one must
     * refuse the message. 0 and 1 are the two known; 16 and up are optional.
     */
    private static final int REQUIRED_BITS = 0xFFFF;
    private static final int KNOWN_REQUIRED = CHECKSUM_PRESENT | MORE_TO_COME;

    /** The smallest message: header, flags, one kind-0 section of an empty document. */
    private static final int SMALLEST = HEADER + 4 + 1 + 5;

    private static final BsonDocumentCodec CODEC = new BsonDocumentCodec();

    private OpMsg() {
    }

    /**
     * A command as one OP_MSG, with {@code $db} added to its body.
     *
     * @param sequenceId the field the documents of {@code sequence} belong to,
     *                   or {@code null} for none
     * @param maxMessageSize the server's {@code maxMessageSizeBytes}
     */
    public static ByteBuffer encode(int requestId, BsonDocument command, String db,
            String sequenceId, List<? extends BsonDocument> sequence, int maxMessageSize) {
        return encode(requestId, command, db, sequenceId, sequence, maxMessageSize, 0);
    }

    /**
     * The same with flag bits: {@link #MORE_TO_COME} on a request means the
     * server sends no reply - an unacknowledged write.
     */
    public static ByteBuffer encode(int requestId, BsonDocument command, String db,
            String sequenceId, List<? extends BsonDocument> sequence, int maxMessageSize,
            int flags) {
        if (command.containsKey("$db")) {
            throw new IllegalArgumentException("the command names its database itself ($db)");
        }
        if (sequenceId != null && command.containsKey(sequenceId)) {
            throw new IllegalArgumentException("the command has a field " + sequenceId
                    + " and a document sequence of the same name");
        }
        BsonDocument body = new BsonDocument();
        body.putAll(command);
        body.put("$db", new BsonString(db));

        BasicOutputBuffer out = new BasicOutputBuffer(256);
        out.writeInt32(0);                                   // length, set below
        out.writeInt32(requestId);
        out.writeInt32(0);                                   // responseTo
        out.writeInt32(OP_MSG);
        out.writeInt32(flags);
        out.writeByte(0);
        writeDocument(out, body);
        if (sequenceId != null) {
            out.writeByte(1);
            int sizeAt = out.getPosition();
            out.writeInt32(0);
            out.writeCString(sequenceId);
            for (BsonDocument document : sequence) {
                writeDocument(out, document);
            }
            out.writeInt32(sizeAt, out.getPosition() - sizeAt);
        }
        int length = out.getPosition();
        if (length > maxMessageSize) {
            throw new BsonMaximumSizeExceededException("the command is " + length
                    + " bytes; the server takes messages of at most " + maxMessageSize);
        }
        out.writeInt32(0, length);
        return ByteBuffer.wrap(out.getInternalBuffer(), 0, length);
    }

    private static void writeDocument(BasicOutputBuffer out, BsonDocument document) {
        try (BsonBinaryWriter writer = new BsonBinaryWriter(out)) {
            CODEC.encode(writer, document, EncoderContext.builder().build());
        }
    }

    /** The compressors of OP_COMPRESSED and their ids (the compression specification). */
    public enum Compressor {
        NOOP(0), SNAPPY(1), ZLIB(2), ZSTD(3);

        final int id;

        Compressor(int id) {
            this.id = id;
        }

        /** The name in a URL's {@code compressors} and in {@code hello}. */
        public String wireName() {
            return name().toLowerCase(java.util.Locale.ROOT);
        }

        static Compressor byId(int id) {
            for (Compressor compressor : values()) {
                if (compressor.id == id) {
                    return compressor;
                }
            }
            return null;
        }

        /** {@code null} for a name that is none of them. */
        public static Compressor byName(String name) {
            for (Compressor compressor : values()) {
                if (compressor != NOOP && compressor.wireName().equalsIgnoreCase(name.trim())) {
                    return compressor;
                }
            }
            return null;
        }
    }

    /** An OP_MSG as OP_COMPRESSED with zlib; see {@link #compress(ByteBuffer, Compressor, int)}. */
    public static ByteBuffer compress(ByteBuffer message, int level) {
        return compress(message, Compressor.ZLIB, level);
    }

    /**
     * An OP_MSG as OP_COMPRESSED: the header stays, the rest is compressed
     * behind the original opcode, its size and the compressor id.
     *
     * @param level zlib's level; the others have none
     */
    public static ByteBuffer compress(ByteBuffer message, Compressor compressor, int level) {
        ByteBuffer in = message.duplicate().order(ByteOrder.LITTLE_ENDIAN);
        int start = in.position();
        int length = in.remaining();
        byte[] body = new byte[length - HEADER];
        in.duplicate().position(start + HEADER).get(body);
        byte[] packed = compressor == Compressor.ZLIB ? deflate(body, level)
                : Airlift.compress(compressor, body);
        ByteBuffer out = ByteBuffer.allocate(HEADER + 9 + packed.length) // seclume-allow: a command, compressed; the login is never compressed
                .order(ByteOrder.LITTLE_ENDIAN);
        out.putInt(HEADER + 9 + packed.length)
                .putInt(in.getInt(start + 4))
                .putInt(in.getInt(start + 8))
                .putInt(OP_COMPRESSED)
                .putInt(in.getInt(start + 12))
                .putInt(body.length)
                .put((byte) compressor.id)
                .put(packed);
        return out.flip();
    }

    private static byte[] deflate(byte[] body, int level) {
        java.util.zip.Deflater deflater = new java.util.zip.Deflater(level);
        try {
            deflater.setInput(body);
            deflater.finish();
            java.io.ByteArrayOutputStream deflated = new java.io.ByteArrayOutputStream(
                    body.length / 2 + 64);
            byte[] chunk = new byte[8192];
            while (!deflater.finished()) {
                int n = deflater.deflate(chunk);
                deflated.write(chunk, 0, n);
            }
            return deflated.toByteArray();
        } finally {
            deflater.end();
        }
    }

    /**
     * An OP_COMPRESSED reply as the message it carries. Strict, as the
     * parser is: the compressor has to be the one agreed, the size it
     * announces within the agreed limit, and inflating has to give exactly
     * that many bytes - a reply that inflates to more is refused when the
     * limit is reached, not after it has filled the memory.
     */
    public static ByteBuffer decompress(ByteBuffer message, int maxMessageSize) {
        return decompress(message, maxMessageSize, java.util.Set.of(Compressor.ZLIB));
    }

    /**
     * The same for the compressors agreed in {@code hello}: a reply may come
     * with any of them, or uncompressed ({@code noop}), but with no other.
     */
    public static ByteBuffer decompress(ByteBuffer message, int maxMessageSize,
            java.util.Set<Compressor> agreed) {
        ByteBuffer in = message.duplicate().order(ByteOrder.LITTLE_ENDIAN);
        int start = in.position();
        int length = in.remaining();
        if (length < HEADER + 9) {
            throw refused("a compressed reply of " + length + " bytes");
        }
        int original = in.getInt(start + HEADER);
        int size = in.getInt(start + HEADER + 4);
        int compressor = in.get(start + HEADER + 8) & 0xFF;
        if (original != OP_MSG) {
            throw refused("a compressed reply of opcode " + original + ", not OP_MSG");
        }
        Compressor used = Compressor.byId(compressor);
        if (used == null || (used != Compressor.NOOP && !agreed.contains(used))) {
            throw refused("a reply compressed with compressor " + compressor
                    + ", though " + agreed + " were agreed");
        }
        if (size < SMALLEST - HEADER || size > maxMessageSize - HEADER) {
            throw refused("a compressed reply announcing " + size + " bytes; at most "
                    + (maxMessageSize - HEADER) + " were agreed");
        }
        byte[] packed = new byte[length - HEADER - 9];
        in.duplicate().position(start + HEADER + 9).get(packed);
        byte[] body = new byte[size];
        if (used == Compressor.NOOP) {
            if (packed.length != size) {
                throw refused("an uncompressed reply of " + packed.length + " bytes where "
                        + size + " were announced");
            }
            System.arraycopy(packed, 0, body, 0, size);
        } else if (used != Compressor.ZLIB) {
            if (Airlift.decompress(used, packed, body) != size) {
                throw refused("a " + used.wireName() + " reply that is malformed or does not "
                        + "decompress to the " + size + " bytes it announced");
            }
        } else {
            inflate(packed, body);
        }
        ByteBuffer out = ByteBuffer.allocate(HEADER + size).order(ByteOrder.LITTLE_ENDIAN); // seclume-allow: a command reply, as readMessage holds it
        out.putInt(HEADER + size).putInt(in.getInt(start + 4)).putInt(in.getInt(start + 8))
                .putInt(OP_MSG).put(body);
        return out.flip();
    }

    private static void inflate(byte[] packed, byte[] body) {
        int size = body.length;
        java.util.zip.Inflater inflater = new java.util.zip.Inflater();
        try {
            inflater.setInput(packed);
            int at = 0;
            while (at < size) {
                int n = inflater.inflate(body, at, size - at);
                if (n == 0) {
                    if (inflater.finished() || inflater.needsInput() || inflater.needsDictionary()) {
                        throw refused("a compressed reply that inflates to " + at
                                + " bytes where " + size + " were announced");
                    }
                }
                at += n;
            }
            byte[] probe = new byte[1];
            if (!inflater.finished() && inflater.inflate(probe) > 0) {
                throw refused("a compressed reply that inflates to more than the " + size
                        + " bytes it announced");
            }
            if (inflater.getRemaining() > 0) {
                throw refused("a compressed reply with bytes after its compressed data");
            }
        } catch (java.util.zip.DataFormatException e) {
            throw new MongoInternalException("the server sent a compressed reply that is not "
                    + "zlib: " + e.getMessage(), e);
        } finally {
            inflater.end();
        }
    }

    /** The message's length from its header - checked by {@link #parse}, not here. */
    public static int length(ByteBuffer header) {
        return header.order(ByteOrder.LITTLE_ENDIAN).getInt(0);
    }

    /**
     * The body of a reply, with any document sequences as array fields of it.
     *
     * @param message the whole message, header included, and nothing after it
     */
    public static BsonDocument parse(ByteBuffer message, int requestId) {
        ByteBuffer in = message.duplicate().order(ByteOrder.LITTLE_ENDIAN);
        int start = in.position();
        int available = in.remaining();
        if (available < SMALLEST) {
            throw refused("a reply of " + available + " bytes is shorter than any OP_MSG");
        }
        int length = in.getInt(start);
        if (length != available) {
            throw refused("the reply announces " + length + " bytes and is " + available);
        }
        int responseTo = in.getInt(start + 8);
        if (responseTo != requestId) {
            throw refused("a reply to request " + responseTo + " where " + requestId
                    + " was due");
        }
        int opCode = in.getInt(start + 12);
        if (opCode != OP_MSG) {
            throw refused(switch (opCode) {
                case OP_COMPRESSED -> "a compressed reply, though no compression was agreed";
                case OP_REPLY -> "a legacy OP_REPLY, which this client never asks for";
                default -> "a reply of opcode " + opCode + ", not OP_MSG";
            });
        }
        int flags = in.getInt(start + HEADER);
        if ((flags & REQUIRED_BITS & ~KNOWN_REQUIRED) != 0) {
            throw refused("a reply with required flag bits this client does not know: 0x"
                    + Integer.toHexString(flags & REQUIRED_BITS & ~KNOWN_REQUIRED));
        }
        if ((flags & MORE_TO_COME) != 0) {
            // Only an exhaust cursor's replies come unasked, and only if
            // exhaustAllowed was sent - which this client never does.
            throw refused("a reply with moreToCome, though no further replies were allowed");
        }
        int end = start + length;
        if ((flags & CHECKSUM_PRESENT) != 0) {
            end -= 4;
            if (end < start + SMALLEST) {
                throw refused("a reply too short for its checksum");
            }
            CRC32C crc = new CRC32C();
            crc.update(in.duplicate().position(start).limit(end));
            if ((int) crc.getValue() != in.getInt(end)) {
                throw refused("a reply whose checksum does not match");
            }
        }

        BsonDocument body = null;
        BsonDocument sequences = new BsonDocument();
        int at = start + HEADER + 4;
        while (at < end) {
            byte kind = in.get(at++);
            if (kind == 0) {
                if (body != null) {
                    throw refused("a reply with two body sections");
                }
                int size = documentSize(in, at, end);
                body = document(in, at, size);
                at += size;
            } else if (kind == 1) {
                if (end - at < 4) {
                    throw refused("a document sequence cut short");
                }
                int size = in.getInt(at);
                if (size < 5 || size > end - at) {
                    throw refused("a document sequence of " + size + " bytes where "
                            + (end - at) + " are left");
                }
                int sequenceEnd = at + size;
                int nameAt = at + 4;
                int nameEnd = nameAt;
                while (nameEnd < sequenceEnd && in.get(nameEnd) != 0) {
                    nameEnd++;
                }
                if (nameEnd >= sequenceEnd) {
                    throw refused("a document sequence without the end of its name");
                }
                byte[] nameBytes = new byte[nameEnd - nameAt];
                in.get(nameAt, nameBytes);
                String name = new String(nameBytes, StandardCharsets.UTF_8); // seclume-allow: a field name of a reply
                if (sequences.containsKey(name)) {
                    throw refused("two document sequences named " + name);
                }
                BsonArray documents = new BsonArray();
                int documentAt = nameEnd + 1;
                while (documentAt < sequenceEnd) {
                    int documentSize = documentSize(in, documentAt, sequenceEnd);
                    documents.add(document(in, documentAt, documentSize));
                    documentAt += documentSize;
                }
                sequences.put(name, documents);
                at = sequenceEnd;
            } else {
                throw refused("a section of kind " + kind);
            }
        }
        if (body == null) {
            throw refused("a reply without a body");
        }
        for (String name : sequences.keySet()) {
            if (body.containsKey(name)) {
                throw refused("a document sequence " + name + " that the body has as well");
            }
            body.put(name, sequences.get(name));
        }
        return body;
    }

    private static int documentSize(ByteBuffer in, int at, int end) {
        if (end - at < 5) {
            throw refused("a document cut short: " + (end - at) + " bytes left");
        }
        int size = in.getInt(at);
        if (size < 5 || size > end - at) {
            throw refused("a document of " + size + " bytes where " + (end - at) + " are left");
        }
        if (in.get(at + size - 1) != 0) {
            throw refused("a document that does not end in 0");
        }
        return size;
    }

    private static BsonDocument document(ByteBuffer in, int at, int size) {
        checkBounds(in, at, size, 0);
        ByteBuffer slice = in.duplicate().position(at).limit(at + size).slice()
                .order(ByteOrder.LITTLE_ENDIAN);
        try (BsonBinaryReader reader = new BsonBinaryReader(slice)) {
            BsonDocument document = new ReplyReader(reader, slice).document(false);
            if (reader.getBsonInput().getPosition() != size) {
                throw refused("a document of " + size + " bytes that ends after "
                        + reader.getBsonInput().getPosition());
            }
            return document;
        } catch (BSONException
                 | IllegalArgumentException | IllegalStateException
                 | IndexOutOfBoundsException | java.nio.BufferUnderflowException e) {
            throw new MongoInternalException("the server's reply holds a malformed document: "
                    + e.getMessage(), e);
        }
    }

    /**
     * A reply read into documents, except a cursor's batch: the documents in
     * {@code cursor.firstBatch} and {@code cursor.nextBatch} stay their bytes,
     * a {@link RawBsonDocument} each, and are decoded once - straight into
     * what the application asked for - when the cursor hands them out. Read
     * into documents here, they were read twice, and a find of many documents
     * paid for it (24 % behind the official driver, which reads them once).
     * {@link #checkBounds} has walked every length of them before.
     */
    private static final class ReplyReader {

        private final BsonBinaryReader reader;
        private final ByteBuffer bytes;

        ReplyReader(BsonBinaryReader reader, ByteBuffer bytes) {
            this.reader = reader;
            this.bytes = bytes;
        }

        BsonDocument document(boolean cursor) {
            BsonDocument document = new BsonDocument();
            reader.readStartDocument();
            while (reader.readBsonType() != BsonType.END_OF_DOCUMENT) {
                String name = reader.readName();
                BsonType type = reader.getCurrentBsonType();
                if (cursor && type == BsonType.ARRAY
                        && (name.equals("firstBatch") || name.equals("nextBatch"))) {
                    document.put(name, batch());
                } else if (type == BsonType.DOCUMENT) {
                    document.put(name, document(!cursor && name.equals("cursor")));
                } else {
                    document.put(name, CODEC_VALUES.decode(reader, CONTEXT));
                }
            }
            reader.readEndDocument();
            return document;
        }

        private BsonArray batch() {
            BsonArray batch = new BsonArray();
            reader.readStartArray();
            while (reader.readBsonType() != BsonType.END_OF_DOCUMENT) {   // skips an array's names
                if (reader.getCurrentBsonType() != BsonType.DOCUMENT) {
                    batch.add(CODEC_VALUES.decode(reader, CONTEXT));
                    continue;
                }
                int start = reader.getBsonInput().getPosition();
                reader.skipValue();
                int size = reader.getBsonInput().getPosition() - start;
                if (bytes.hasArray()) {
                    // The reply's own array: no copy per document.
                    batch.add(new RawBsonDocument(bytes.array(), bytes.arrayOffset() + start,
                            size));
                } else {
                    byte[] document = new byte[size];
                    bytes.get(start, document);
                    batch.add(new RawBsonDocument(document));
                }
            }
            reader.readEndArray();
            return batch;
        }
    }

    private static final org.bson.codecs.BsonValueCodec CODEC_VALUES =
            new org.bson.codecs.BsonValueCodec();
    private static final DecoderContext CONTEXT = DecoderContext.builder().build();

    /** Deeper than the server nests (100 levels); bounds the recursion here and in the codec. */
    private static final int MAX_DEPTH = 200;

    /**
     * Walks a document and checks every length in it against the bytes that
     * are there, before the bson library reads it: its reader allocates what
     * a length announces before it looks whether that many bytes follow, so a
     * binary or string of 2^31 - 1 bytes in a reply of 200 was an
     * {@link OutOfMemoryError} (found by {@code OpMsgFuzzTest}).
     */
    private static void checkBounds(ByteBuffer in, int at, int size, int depth) {
        if (depth > MAX_DEPTH) {
            throw refused("a document nested deeper than " + MAX_DEPTH + " levels");
        }
        int end = at + size - 1;                              // the closing 0
        int p = at + 4;
        while (p < end) {
            byte type = in.get(p++);
            p = cstringEnd(in, p, end) + 1;                   // the field's name
            p = switch (type) {
                case 0x01, 0x09, 0x11, 0x12 -> fixed(p, 8, end);
                case 0x07 -> fixed(p, 12, end);
                case 0x08 -> {
                    int q = fixed(p, 1, end);
                    if ((in.get(p) & 0xFF) > 1) {
                        throw refused("a boolean of value " + in.get(p));
                    }
                    yield q;
                }
                case 0x10 -> fixed(p, 4, end);
                case 0x13 -> fixed(p, 16, end);
                case 0x06, 0x0A, (byte) 0xFF, 0x7F -> p;
                case 0x02, 0x0D, 0x0E -> string(in, p, end);
                case 0x0C -> fixed(string(in, p, end), 12, end);
                case 0x03, 0x04 -> {
                    int nested = documentSize(in, p, end);
                    checkBounds(in, p, nested, depth + 1);
                    yield p + nested;
                }
                case 0x05 -> {
                    int length = int32(in, p, end);
                    if (length < 0) {
                        throw refused("a binary of " + length + " bytes");
                    }
                    yield fixed(p + 4, 1L + length, end);
                }
                case 0x0B -> cstringEnd(in, cstringEnd(in, p, end) + 1, end) + 1;
                case 0x0F -> {
                    int total = int32(in, p, end);
                    if (total < 14 || total > end - p) {
                        throw refused("code with scope of " + total + " bytes");
                    }
                    int codeEnd = string(in, p + 4, p + total);
                    int scope = documentSize(in, codeEnd, p + total);
                    if (codeEnd + scope != p + total) {
                        throw refused("code with scope whose parts do not add up");
                    }
                    checkBounds(in, codeEnd, scope, depth + 1);
                    yield p + total;
                }
                default -> throw refused("a field of BSON type 0x"
                        + Integer.toHexString(type & 0xFF));
            };
        }
        if (p != end) {
            throw refused("a document whose last field runs past its end");
        }
    }

    /** In long: a length near 2^31 plus the bytes before it must not wrap around. */
    private static int fixed(int p, long length, int end) {
        if (length < 0 || length > end - p) {
            throw refused("a field of " + length + " bytes where " + (end - p) + " are left");
        }
        return (int) (p + length);
    }

    private static int int32(ByteBuffer in, int p, int end) {
        fixed(p, 4, end);
        return in.getInt(p);
    }

    /** A length-prefixed string: the length counts its closing 0, which must be there. */
    private static int string(ByteBuffer in, int p, int end) {
        int length = int32(in, p, end);
        if (length < 1) {
            throw refused("a string of length " + length);
        }
        int after = fixed(p + 4, length, end);
        if (in.get(after - 1) != 0) {
            throw refused("a string that does not end in 0");
        }
        return after;
    }

    /** Where the 0 that ends a C string starting at {@code p} is. */
    private static int cstringEnd(ByteBuffer in, int p, int end) {
        for (int i = p; i < end; i++) {
            if (in.get(i) == 0) {
                return i;
            }
        }
        throw refused("a name or pattern without its end");
    }

    private static MongoInternalException refused(String what) {
        return new MongoInternalException("the server sent " + what);
    }
}
