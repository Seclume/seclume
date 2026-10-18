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
    static final int OP_COMPRESSED = 2012;
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
            BsonDocument document = CODEC.decode(reader, DecoderContext.builder().build());
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
