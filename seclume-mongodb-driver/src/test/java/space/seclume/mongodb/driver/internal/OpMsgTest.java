package space.seclume.mongodb.driver.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import java.util.zip.CRC32C;

import org.bson.BsonArray;
import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonMaximumSizeExceededException;
import org.bson.BsonString;
import org.junit.jupiter.api.Test;

import com.mongodb.MongoInternalException;

class OpMsgTest {

    private static final int MAX = 48_000_000;

    /** A request as the server would read it: everything after the header. */
    @Test
    void aCommandCarriesItsDatabaseAndItsSequence() {
        BsonDocument insert = new BsonDocument("insert", new BsonString("things"));
        List<BsonDocument> documents = List.of(new BsonDocument("_id", new BsonInt32(1)),
                new BsonDocument("_id", new BsonInt32(2)));
        ByteBuffer request = OpMsg.encode(7, insert, "shop", "documents", documents, MAX);

        // Read back with the reply parser: same layout, responseTo aside.
        ByteBuffer asReply = copy(request);
        asReply.order(ByteOrder.LITTLE_ENDIAN).putInt(8, 7);
        BsonDocument body = OpMsg.parse(asReply, 7);
        assertEquals("things", body.getString("insert").getValue());
        assertEquals("shop", body.getString("$db").getValue());
        assertEquals(2, body.getArray("documents").size());
        assertEquals(OpMsg.OP_MSG, request.order(ByteOrder.LITTLE_ENDIAN).getInt(12));
        assertEquals(7, request.getInt(4));
        assertEquals(request.remaining(), request.getInt(0));
    }

    @Test
    void aCommandThatNamesItsDatabaseIsRefused() {
        BsonDocument ping = new BsonDocument("ping", new BsonInt32(1))
                .append("$db", new BsonString("admin"));
        assertThrows(IllegalArgumentException.class,
                () -> OpMsg.encode(1, ping, "admin", null, null, MAX));
    }

    @Test
    void aSequenceNamedLikeABodyFieldIsRefused() {
        BsonDocument insert = new BsonDocument("insert", new BsonString("t"))
                .append("documents", new BsonArray());
        assertThrows(IllegalArgumentException.class, () -> OpMsg.encode(1, insert, "db",
                "documents", List.of(new BsonDocument()), MAX));
    }

    @Test
    void aCommandOverTheServersLimitIsNotSent() {
        BsonDocument big = new BsonDocument("x", new BsonString("y".repeat(2000)));
        assertThrows(BsonMaximumSizeExceededException.class,
                () -> OpMsg.encode(1, big, "db", null, null, 1000));
    }

    /**
     * A cursor's batch stays bytes, a RawBsonDocument per document, equal to
     * what was sent; the rest of the reply - the cursor document itself, an
     * array of the same name outside a cursor - is read as before and can be
     * changed.
     */
    @Test
    void aCursorsBatchStaysItsBytes() {
        BsonDocument first = new BsonDocument("_id", new BsonInt32(1))
                .append("nested", new BsonDocument("a", new BsonArray(List.of(new BsonInt32(2)))));
        BsonDocument second = new BsonDocument("_id", new BsonInt32(2));
        BsonDocument sent = new BsonDocument("cursor", new BsonDocument("id", new BsonInt32(0))
                .append("ns", new BsonString("db.c"))
                .append("firstBatch", new BsonArray(List.of(first, second))))
                .append("firstBatch", new BsonArray(List.of(new BsonDocument("x", new BsonInt32(3)))))
                .append("ok", new BsonInt32(1));
        BsonDocument body = OpMsg.parse(reply(9, 0, body(sent)), 9);

        assertEquals(sent, body);
        BsonArray batch = body.getDocument("cursor").getArray("firstBatch");
        assertTrue(batch.get(0) instanceof org.bson.RawBsonDocument, batch.get(0).getClass().getName());
        assertTrue(batch.get(1) instanceof org.bson.RawBsonDocument);
        assertEquals(first, batch.get(0));
        assertTrue(!(body.getArray("firstBatch").get(0) instanceof org.bson.RawBsonDocument),
                "an array named firstBatch outside the cursor");
        body.getDocument("cursor").put("changed", new BsonInt32(1));   // still a plain document
    }

    @Test
    void aPlainReplyIsItsBody() {
        BsonDocument body = OpMsg.parse(reply(9, 0, body(new BsonDocument("ok",
                new BsonInt32(1)))), 9);
        assertEquals(1, body.getInt32("ok").getValue());
    }

    @Test
    void aReplyToAnotherRequestIsRefused() {
        assertRefused("a reply to request 8 where 9 was due",
                reply(8, 0, body(new BsonDocument())), 9);
    }

    @Test
    void aCompressedReplyIsRefused() {
        ByteBuffer message = reply(9, 0, body(new BsonDocument()));
        message.putInt(12, OpMsg.OP_COMPRESSED);
        assertRefused("compressed", message, 9);
    }

    @Test
    void moreToComeIsRefused() {
        assertRefused("moreToCome", reply(9, OpMsg.MORE_TO_COME, body(new BsonDocument())), 9);
    }

    @Test
    void anUnknownRequiredFlagIsRefusedAndAnOptionalOneIsNot() {
        assertRefused("required flag bits", reply(9, 1 << 5, body(new BsonDocument())), 9);
        OpMsg.parse(reply(9, 1 << 16, body(new BsonDocument())), 9);
    }

    @Test
    void aChecksumIsChecked() {
        ByteBuffer good = withChecksum(reply(9, OpMsg.CHECKSUM_PRESENT,
                body(new BsonDocument("ok", new BsonInt32(1)))), false);
        assertEquals(1, OpMsg.parse(good, 9).getInt32("ok").getValue());
        ByteBuffer bad = withChecksum(reply(9, OpMsg.CHECKSUM_PRESENT,
                body(new BsonDocument("ok", new BsonInt32(1)))), true);
        assertRefused("checksum", bad, 9);
    }

    @Test
    void twoBodiesAreRefused() {
        assertRefused("two body sections", reply(9, 0,
                concat(body(new BsonDocument()), body(new BsonDocument()))), 9);
    }

    @Test
    void aSequenceBecomesAFieldOfTheBody() {
        BsonDocument body = OpMsg.parse(reply(9, 0, concat(body(new BsonDocument("ok",
                new BsonInt32(1))), sequence("cursor", new BsonDocument("n", new BsonInt32(1)),
                new BsonDocument("n", new BsonInt32(2))))), 9);
        assertEquals(2, body.getArray("cursor").size());
    }

    @Test
    void aSequenceThatTheBodyHasAsWellIsRefused() {
        assertRefused("that the body has as well", reply(9, 0, concat(
                body(new BsonDocument("cursor", new BsonInt32(1))),
                sequence("cursor", new BsonDocument()))), 9);
    }

    @Test
    void aLengthThatIsNotTheMessagesIsRefused() {
        ByteBuffer message = reply(9, 0, body(new BsonDocument()));
        message.putInt(0, message.remaining() + 1);
        assertRefused("announces", message, 9);
    }

    @Test
    void aDocumentLongerThanItsSectionIsRefused() {
        ByteBuffer message = reply(9, 0, body(new BsonDocument("a", new BsonInt32(1))));
        message.putInt(21, 400);
        assertRefused("a document of 400 bytes", message, 9);
    }

    /**
     * The bson library's reader allocates what a length announces before it
     * checks that the bytes are there: checked first, it is a refusal and not
     * an OutOfMemoryError.
     */
    @Test
    void aBinaryAnnouncingTwoGigabytesIsRefusedNotAllocated() {
        ByteBuffer message = reply(9, 0, body(new BsonDocument("b",
                new org.bson.BsonBinary(new byte[] {1, 2, 3}))));
        message.putInt(21 + 4 + 1 + 2, Integer.MAX_VALUE);
        assertRefused("a field of", message, 9);
    }

    @Test
    void aDocumentWhoseFieldsRunPastItsEndIsRefused() {
        // A string field claims more bytes than the document holds.
        ByteBuffer message = reply(9, 0, body(new BsonDocument("s", new BsonString("abc"))));
        message.putInt(21 + 4 + 1 + 2, 50);
        MongoInternalException refused = assertThrows(MongoInternalException.class,
                () -> OpMsg.parse(message, 9));
        assertTrue(refused.getMessage().contains("a field of 50 bytes"), refused.getMessage());
    }

    static void assertRefused(String why, ByteBuffer message, int requestId) {
        MongoInternalException refused = assertThrows(MongoInternalException.class,
                () -> OpMsg.parse(message, requestId));
        assertTrue(refused.getMessage().contains(why), refused.getMessage());
    }

    static byte[] body(BsonDocument document) {
        return concat(new byte[] {0}, bytes(document));
    }

    static byte[] sequence(String name, BsonDocument... documents) {
        byte[] nameBytes = (name + "\0").getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] all = nameBytes;
        for (BsonDocument document : documents) {
            all = concat(all, bytes(document));
        }
        ByteBuffer size = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(4 + all.length);
        return concat(new byte[] {1}, size.array(), all);
    }

    static byte[] bytes(BsonDocument document) {
        org.bson.io.BasicOutputBuffer out = new org.bson.io.BasicOutputBuffer();
        try (org.bson.BsonBinaryWriter writer = new org.bson.BsonBinaryWriter(out)) {
            new org.bson.codecs.BsonDocumentCodec().encode(writer, document,
                    org.bson.codecs.EncoderContext.builder().build());
        }
        return out.toByteArray();
    }

    static ByteBuffer reply(int responseTo, int flags, byte[] sections) {
        ByteBuffer message = ByteBuffer.allocate(OpMsg.HEADER + 4 + sections.length)
                .order(ByteOrder.LITTLE_ENDIAN);
        message.putInt(message.capacity()).putInt(1234).putInt(responseTo).putInt(OpMsg.OP_MSG)
                .putInt(flags).put(sections);
        return message.flip();
    }

    static ByteBuffer withChecksum(ByteBuffer message, boolean wrong) {
        ByteBuffer longer = ByteBuffer.allocate(message.remaining() + 4)
                .order(ByteOrder.LITTLE_ENDIAN);
        longer.put(message.duplicate());
        longer.putInt(0, longer.capacity());
        CRC32C crc = new CRC32C();
        crc.update(longer.array(), 0, longer.capacity() - 4);
        longer.putInt((int) crc.getValue() + (wrong ? 1 : 0));
        return longer.flip();
    }

    static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] all = new byte[length];
        int at = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, all, at, part.length);
            at += part.length;
        }
        return all;
    }

    private static ByteBuffer copy(ByteBuffer buffer) {
        ByteBuffer copy = ByteBuffer.allocate(buffer.remaining());
        copy.put(buffer.duplicate());
        return copy.flip();
    }
}
