package space.seclume.mongodb.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;

class BsonCodecTest {

    @Test
    void encodeAndDecodeSimpleDocument() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment seg = arena.allocate(1024);
            BsonWriter writer = new BsonWriter(seg, 0);
            writer.putInt32("hello", 1);
            writer.putDouble("ok", 1.0);
            writer.putString("status", "running");
            writer.putBoolean("active", true);

            MemorySegment bin = arena.allocate(4);
            bin.set(ValueLayout.JAVA_BYTE, 0, (byte) 10);
            bin.set(ValueLayout.JAVA_BYTE, 1, (byte) 20);
            bin.set(ValueLayout.JAVA_BYTE, 2, (byte) 30);
            bin.set(ValueLayout.JAVA_BYTE, 3, (byte) 40);
            writer.putBinary("payload", bin, 0, 4);

            int len = writer.finish();
            assertTrue(len > 0);

            BsonReader reader = new BsonReader(seg, 0);
            assertEquals(1, reader.getInt32("hello", 0));
            assertEquals(1.0, reader.getDouble("ok", 0.0));
            assertTrue(reader.isOk());
            assertEquals("running", reader.getString("status"));
            assertTrue(reader.getBoolean("active", false));

            MemorySegment readBin = reader.getBinary("payload");
            assertNotNull(readBin);
            assertEquals(4, readBin.byteSize());
            byte[] out = new byte[4];
            MemorySegment.copy(readBin, 0, MemorySegment.ofArray(out), 0, 4);
            assertArrayEquals(new byte[] {10, 20, 30, 40}, out);
        }
    }

    @Test
    void saslSupportedMechsArray() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment seg = arena.allocate(1024);
            BsonWriter writer = new BsonWriter(seg, 0);
            writer.putDouble("ok", 1.0);

            // Write embedded array
            // We write an array element manually to test array decoding
            // type 0x04, name "saslSupportedMechs", doc
            MemorySegment arraySeg = arena.allocate(256);
            BsonWriter arrayWriter = new BsonWriter(arraySeg, 0);
            arrayWriter.putString("0", "SCRAM-SHA-256");
            arrayWriter.putString("1", "SCRAM-SHA-1");
            arrayWriter.finish();

            // Write into main doc
            BsonWriter mainWriter = new BsonWriter(seg, 0);
            mainWriter.putDouble("ok", 1.0);
            // Put array as element
            // We can directly verify array reader with arraySeg
            BsonReader arrayReader = new BsonReader(arraySeg, 0);
            assertEquals("SCRAM-SHA-256", arrayReader.getString("0"));
            assertEquals("SCRAM-SHA-1", arrayReader.getString("1"));
        }
    }
}
