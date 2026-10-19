package space.seclume.mongodb.driver.internal;

import static org.junit.jupiter.api.Assertions.fail;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import java.util.Random;

import org.bson.BsonArray;
import org.bson.BsonBinary;
import org.bson.BsonDateTime;
import org.bson.BsonDecimal128;
import org.bson.BsonDocument;
import org.bson.BsonDouble;
import org.bson.BsonInt32;
import org.bson.BsonInt64;
import org.bson.BsonNull;
import org.bson.BsonObjectId;
import org.bson.BsonRegularExpression;
import org.bson.BsonString;
import org.bson.BsonTimestamp;
import org.bson.types.Decimal128;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.mongodb.MongoInternalException;

/**
 * Whatever the server - or whoever sits between - sends, the reply parser
 * returns a document or throws {@link MongoInternalException}: never another
 * exception, which would escape the session's handling and leave the stream
 * where it was, and never a long loop or a large allocation.
 *
 * <p>Seeded, so a failure is reproducible: the message names the seed and
 * the mutation. {@code -Dseclume.mongo.fuzz.rounds=N} runs more,
 * {@code -Dseclume.mongo.fuzz.seed=S} others.
 */
@Timeout(120)
class OpMsgFuzzTest {

    private static final int ROUNDS = Integer.getInteger("seclume.mongo.fuzz.rounds", 40_000);

    @Test
    void theParserOnlyReturnsOrRefuses() {
        List<ByteBuffer> seeds = List.of(
                OpMsgTest.reply(5, 0, OpMsgTest.body(rich())),
                OpMsgTest.reply(5, 0, OpMsgTest.concat(OpMsgTest.body(new BsonDocument("ok",
                        new BsonInt32(1))), OpMsgTest.sequence("batch", rich(), rich()))),
                OpMsgTest.withChecksum(OpMsgTest.reply(5, OpMsg.CHECKSUM_PRESENT,
                        OpMsgTest.body(rich())), false),
                OpMsg.compress(OpMsgTest.reply(5, 0, OpMsgTest.body(rich())), -1),
                OpMsg.compress(OpMsgTest.reply(5, 0, OpMsgTest.body(rich())),
                        OpMsg.Compressor.SNAPPY, -1),
                OpMsg.compress(OpMsgTest.reply(5, 0, OpMsgTest.body(rich())),
                        OpMsg.Compressor.ZSTD, -1));
        long fuzzSeed = Long.getLong("seclume.mongo.fuzz.seed", 0x5EC1_0DB);
        Random random = new Random(fuzzSeed);
        for (int round = 0; round < ROUNDS; round++) {
            ByteBuffer seed = seeds.get(round % seeds.size());
            byte[] bytes = new byte[seed.remaining()];
            seed.duplicate().get(bytes);
            String mutation = mutate(bytes, random);
            ByteBuffer message = ByteBuffer.wrap(bytes);
            if (random.nextBoolean()) {
                // Mostly keep the header's length right, or every case ends there.
                message.order(ByteOrder.LITTLE_ENDIAN).putInt(0, bytes.length);
            }
            try {
                // A compressed one is inflated first, as the session does.
                if (message.order(ByteOrder.LITTLE_ENDIAN).getInt(12) == OpMsg.OP_COMPRESSED) {
                    message = OpMsg.decompress(message, 1 << 20, java.util.EnumSet.of(
                            OpMsg.Compressor.ZLIB, OpMsg.Compressor.SNAPPY,
                            OpMsg.Compressor.ZSTD));
                }
                OpMsg.parse(message, 5);
            } catch (MongoInternalException refused) {
                // what it should do with garbage
            } catch (RuntimeException | StackOverflowError | OutOfMemoryError other) {
                fail("seed " + fuzzSeed + " round " + round + " (" + mutation + "): "
                        + other, other);
            }
        }
    }

    private static String mutate(byte[] bytes, Random random) {
        switch (random.nextInt(5)) {
            case 0 -> {
                int at = random.nextInt(bytes.length);
                bytes[at] ^= (byte) (1 << random.nextInt(8));
                return "bit at " + at;
            }
            case 1 -> {
                int at = random.nextInt(bytes.length);
                bytes[at] = (byte) random.nextInt(256);
                return "byte at " + at;
            }
            case 2 -> {
                // An int32 anywhere set to an edge: a length that lies.
                int at = random.nextInt(Math.max(1, bytes.length - 4));
                int[] edges = {0, -1, 4, 5, Integer.MAX_VALUE, Integer.MIN_VALUE, bytes.length};
                int value = edges[random.nextInt(edges.length)];
                ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(at, value);
                return "int32 " + value + " at " + at;
            }
            case 3 -> {
                int n = 1 + random.nextInt(8);
                for (int i = 0; i < n; i++) {
                    bytes[random.nextInt(bytes.length)] = (byte) random.nextInt(256);
                }
                return n + " bytes";
            }
            default -> {
                // A field's type byte swapped for another.
                int at = OpMsg.HEADER + 4 + 1 + 4 + random.nextInt(Math.max(1,
                        bytes.length - OpMsg.HEADER - 10));
                if (at < bytes.length) {
                    bytes[at] = (byte) (random.nextInt(0x14) + (random.nextInt(10) == 0 ? 0x70 : 0));
                }
                return "type byte at " + at;
            }
        }
    }

    private static BsonDocument rich() {
        return new BsonDocument("ok", new BsonDouble(1))
                .append("s", new BsonString("text"))
                .append("i", new BsonInt32(42))
                .append("l", new BsonInt64(1L << 40))
                .append("d", new BsonDecimal128(Decimal128.parse("1.5")))
                .append("t", new BsonTimestamp(7, 1))
                .append("date", new BsonDateTime(0))
                .append("id", new BsonObjectId())
                .append("bin", new BsonBinary(new byte[] {1, 2, 3}))
                .append("re", new BsonRegularExpression("a.*", "i"))
                .append("nil", BsonNull.VALUE)
                .append("arr", new BsonArray(List.of(new BsonInt32(1), new BsonString("x"))))
                .append("doc", new BsonDocument("nested", new BsonDocument("deep",
                        new BsonInt32(1))));
    }
}
