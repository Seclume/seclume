package space.seclume.mongodb.internal;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

/**
 * Encodes BSON documents directly into native memory, ensuring no secret
 * bytes pass through the Java heap.
 */
public final class BsonWriter {

    private final MemorySegment target;
    private final long baseOffset;
    private long pos;

    public BsonWriter(MemorySegment target, long baseOffset) {
        this.target = target;
        this.baseOffset = baseOffset;
        this.pos = baseOffset + 4; // reserve 4 bytes for document length
    }

    public void putInt32(String name, int value) {
        putByte((byte) 0x10);
        putCString(name);
        putIntLE(value);
    }

    public void putDouble(String name, double value) {
        putByte((byte) 0x01);
        putCString(name);
        putLongLE(Double.doubleToRawLongBits(value));
    }

    public void putString(String name, String value) {
        putByte((byte) 0x02);
        putCString(name);
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8); // seclume-allow: public command arguments
        putIntLE(bytes.length + 1);
        for (byte b : bytes) {
            putByte(b);
        }
        putByte((byte) 0);
    }

    /**
     * A string whose bytes are in native memory - a session token - copied
     * there without becoming a Java object. The bytes have to be UTF-8 and
     * hold no 0, as any BSON string.
     */
    public void putString(String name, MemorySegment value, int length) {
        putByte((byte) 0x02);
        putCString(name);
        putIntLE(length + 1);
        MemorySegment.copy(value, 0, target, pos, length);
        pos += length;
        putByte((byte) 0);
    }

    public void putBoolean(String name, boolean value) {
        putByte((byte) 0x08);
        putCString(name);
        putByte((byte) (value ? 1 : 0));
    }

    /** Copies binary bytes directly in native memory without heap allocations. */
    public void putBinary(String name, MemorySegment data, long dataOffset, int length) {
        putByte((byte) 0x05);
        putCString(name);
        putIntLE(length);
        putByte((byte) 0x00); // generic binary subtype
        MemorySegment.copy(data, dataOffset, target, pos, length);
        pos += length;
    }

    /** Finishes the document, writes the trailing null byte and sets the length header. */
    public int finish() {
        putByte((byte) 0);
        int totalLength = (int) (pos - baseOffset);
        target.set(ValueLayout.JAVA_INT_UNALIGNED, baseOffset, totalLength);
        return totalLength;
    }

    public long currentPosition() {
        return pos;
    }

    private void putByte(byte b) {
        target.set(ValueLayout.JAVA_BYTE, pos++, b);
    }

    private void putIntLE(int v) {
        target.set(ValueLayout.JAVA_INT_UNALIGNED, pos, v);
        pos += 4;
    }

    private void putLongLE(long v) {
        target.set(ValueLayout.JAVA_LONG_UNALIGNED, pos, v);
        pos += 8;
    }

    private void putCString(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.US_ASCII); // seclume-allow: BSON field name, public
        for (byte b : bytes) {
            putByte(b);
        }
        putByte((byte) 0);
    }
}
