package space.seclume.mongodb.driver.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonString;
import org.junit.jupiter.api.Test;

import com.mongodb.MongoConfigurationException;
import com.mongodb.MongoInternalException;

/** OP_COMPRESSED with zlib, snappy and zstd: the round trip, and every way a reply is refused. */
class CompressionTest {

    private static final int MAX = 48_000_000;

    private static ByteBuffer reply(BsonDocument body) {
        return OpMsgTest.reply(7, 0, OpMsgTest.body(body));
    }

    @Test
    void aMessageComesBackAsItWent() {
        BsonDocument body = new BsonDocument("ok", new BsonInt32(1))
                .append("text", new BsonString("x".repeat(5000)));
        ByteBuffer compressed = OpMsg.compress(reply(body), -1);
        assertEquals(OpMsg.OP_COMPRESSED, compressed.order(ByteOrder.LITTLE_ENDIAN).getInt(12));
        assertTrue(compressed.remaining() < 1000, "5000 of the same letter did not compress");
        BsonDocument back = OpMsg.parse(OpMsg.decompress(compressed, MAX), 7);
        assertEquals(body, back);
    }

    private static final java.util.Set<OpMsg.Compressor> ALL = java.util.EnumSet.of(
            OpMsg.Compressor.ZLIB, OpMsg.Compressor.SNAPPY, OpMsg.Compressor.ZSTD);

    @Test
    void snappyAndZstdComeBackAsTheyWent() {
        BsonDocument body = new BsonDocument("ok", new BsonInt32(1))
                .append("text", new BsonString("x".repeat(5000)));
        for (OpMsg.Compressor compressor : java.util.List.of(OpMsg.Compressor.SNAPPY,
                OpMsg.Compressor.ZSTD)) {
            ByteBuffer compressed = OpMsg.compress(reply(body), compressor, -1);
            assertEquals(compressor.id, compressed.get(OpMsg.HEADER + 8), compressor.name());
            assertTrue(compressed.remaining() < 1000, compressor + " did not compress");
            assertEquals(body, OpMsg.parse(OpMsg.decompress(compressed, MAX, ALL), 7));
        }
    }

    /** A size that is not the one in the stream: refused, by both. */
    @Test
    void snappyAndZstdRefuseASizeThatIsNotTheirs() {
        for (OpMsg.Compressor compressor : java.util.List.of(OpMsg.Compressor.SNAPPY,
                OpMsg.Compressor.ZSTD)) {
            for (int delta : new int[] {-1, 10}) {
                ByteBuffer compressed = OpMsg.compress(reply(new BsonDocument("a",
                        new BsonString("y".repeat(3000)))), compressor, -1);
                int size = compressed.order(ByteOrder.LITTLE_ENDIAN).getInt(OpMsg.HEADER + 4);
                compressed.putInt(OpMsg.HEADER + 4, size + delta);
                MongoInternalException refused = assertThrows(MongoInternalException.class,
                        () -> OpMsg.decompress(compressed, MAX, ALL), compressor + " " + delta);
                assertTrue(refused.getMessage().contains("does not decompress"),
                        refused.getMessage());
            }
        }
    }

    /** Agreed is agreed: a snappy reply on a zlib connection is refused. */
    @Test
    void aCompressorNotAgreedIsRefused() {
        ByteBuffer compressed = OpMsg.compress(reply(new BsonDocument()),
                OpMsg.Compressor.SNAPPY, -1);
        MongoInternalException refused = assertThrows(MongoInternalException.class,
                () -> OpMsg.decompress(compressed, MAX, java.util.Set.of(OpMsg.Compressor.ZLIB)));
        assertTrue(refused.getMessage().contains("compressor 1"), refused.getMessage());
    }

    /** noop: compressed in form only - the bytes as they are, their count checked. */
    @Test
    void noopIsTheBodyAsItIs() {
        BsonDocument body = new BsonDocument("ok", new BsonInt32(1));
        ByteBuffer plain = reply(body);
        int bodyLength = plain.remaining() - OpMsg.HEADER;
        ByteBuffer noop = ByteBuffer.allocate(OpMsg.HEADER + 9 + bodyLength)
                .order(ByteOrder.LITTLE_ENDIAN);
        noop.putInt(OpMsg.HEADER + 9 + bodyLength).putInt(plain.getInt(4)).putInt(plain.getInt(8))
                .putInt(OpMsg.OP_COMPRESSED).putInt(OpMsg.OP_MSG).putInt(bodyLength)
                .put((byte) 0).put(plain.duplicate().position(OpMsg.HEADER));
        noop.flip();
        assertEquals(body, OpMsg.parse(OpMsg.decompress(noop.duplicate(), MAX, ALL), 7));
        noop.putInt(OpMsg.HEADER + 4, bodyLength + 1);
        assertThrows(MongoInternalException.class, () -> OpMsg.decompress(noop, MAX, ALL));
    }

    @Test
    void anotherCompressorIsRefused() {
        ByteBuffer compressed = OpMsg.compress(reply(new BsonDocument()), -1);
        compressed.put(OpMsg.HEADER + 8, (byte) 1);                       // snappy
        assertRefused("compressor 1", compressed);
    }

    @Test
    void aSizeOverTheLimitIsRefusedBeforeInflating() {
        ByteBuffer compressed = OpMsg.compress(reply(new BsonDocument()), -1);
        compressed.order(ByteOrder.LITTLE_ENDIAN).putInt(OpMsg.HEADER + 4, Integer.MAX_VALUE);
        assertRefused("announcing", compressed);
    }

    /** A reply that inflates to more than it says: refused at the announced size. */
    @Test
    void moreThanAnnouncedIsRefused() {
        ByteBuffer compressed = OpMsg.compress(reply(new BsonDocument("a",
                new BsonString("y".repeat(10_000)))), -1);
        compressed.order(ByteOrder.LITTLE_ENDIAN).putInt(OpMsg.HEADER + 4, 100);
        assertRefused("more than the 100 bytes", compressed);
    }

    @Test
    void lessThanAnnouncedIsRefused() {
        ByteBuffer compressed = OpMsg.compress(reply(new BsonDocument()), -1);
        int size = compressed.order(ByteOrder.LITTLE_ENDIAN).getInt(OpMsg.HEADER + 4);
        compressed.putInt(OpMsg.HEADER + 4, size + 10);
        assertRefused("inflates to", compressed);
    }

    @Test
    void bytesAfterTheCompressedDataAreRefused() {
        ByteBuffer compressed = OpMsg.compress(reply(new BsonDocument()), -1);
        ByteBuffer longer = ByteBuffer.allocate(compressed.remaining() + 3)
                .order(ByteOrder.LITTLE_ENDIAN);
        longer.put(compressed.duplicate()).put(new byte[] {1, 2, 3});
        longer.putInt(0, longer.capacity());
        assertRefused("after its compressed data", longer.flip());
    }

    @Test
    void notZlibIsRefused() {
        ByteBuffer compressed = OpMsg.compress(reply(new BsonDocument()), -1);
        compressed.put(OpMsg.HEADER + 9, (byte) 0x00).put(OpMsg.HEADER + 10, (byte) 0x00);
        assertRefused("not zlib", compressed);
    }

    @Test
    void theUrlSaysWhetherAndHowMuch() {
        MongoSession.Compression none = MongoSession.Compression.of("mongodb://h/?w=1");
        assertFalse(none.zlib());
        MongoSession.Compression zlib = MongoSession.Compression.of(
                "mongodb://h/?compressors=snappy,zlib&zlibCompressionLevel=6");
        assertTrue(zlib.zlib());
        assertEquals(6, zlib.level());
        assertEquals(java.util.List.of(OpMsg.Compressor.SNAPPY, OpMsg.Compressor.ZLIB),
                zlib.compressors(), "the URL's order, which is the preference");
        assertEquals(java.util.List.of(OpMsg.Compressor.ZSTD), MongoSession.Compression.of(
                "mongodb://h/?compressors=zstd,lz4").compressors(), "an unknown one is left out");
    }

    private static void assertRefused(String why, ByteBuffer message) {
        MongoInternalException refused = assertThrows(MongoInternalException.class,
                () -> OpMsg.decompress(message, MAX));
        assertTrue(refused.getMessage().contains(why), refused.getMessage());
    }

    @Test
    void aLevelThatIsNoNumberIsAConfigurationError() {
        MongoConfigurationException refused = assertThrows(MongoConfigurationException.class,
                () -> MongoSession.Compression.of(
                        "mongodb://h/?compressors=zlib&zlibCompressionLevel=high"));
        assertTrue(refused.getMessage().contains("zlibCompressionLevel"), refused.getMessage());
    }
}
