package space.seclume.mongodb.internal;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads BSON documents directly from native memory without heap-allocating
 * sensitive values. Binary payloads are returned as zero-copy
 * {@link MemorySegment} slices.
 */
public final class BsonReader {

    private final MemorySegment segment;
    private final long baseOffset;
    private final int documentLength;
    private final Map<String, Element> elements = new LinkedHashMap<>();

    private record Element(byte type, long valueOffset, int valueLength) {}

    public BsonReader(MemorySegment segment, long baseOffset) {
        this.segment = segment;
        this.baseOffset = baseOffset;
        if (baseOffset + 4 > segment.byteSize()) {
            throw new IllegalArgumentException("truncated BSON document length header");
        }
        this.documentLength = segment.get(ValueLayout.JAVA_INT_UNALIGNED, baseOffset);
        if (documentLength < 5 || baseOffset + documentLength > segment.byteSize()) {
            throw new IllegalArgumentException("invalid or truncated BSON document of length "
                    + documentLength);
        }
        parseElements();
    }

    private void parseElements() {
        long pos = baseOffset + 4;
        long end = baseOffset + documentLength - 1; // before trailing 0x00
        while (pos < end) {
            byte type = segment.get(ValueLayout.JAVA_BYTE, pos++);
            if (type == 0) {
                break;
            }
            long nameStart = pos;
            while (pos < end && segment.get(ValueLayout.JAVA_BYTE, pos) != 0) {
                pos++;
            }
            if (pos >= end) {
                throw new IllegalArgumentException("unterminated BSON field name");
            }
            int nameLen = (int) (pos - nameStart);
            byte[] nameBytes = new byte[nameLen];
            MemorySegment.copy(segment, nameStart, MemorySegment.ofArray(nameBytes), 0, nameLen);
            String name = new String(nameBytes, StandardCharsets.US_ASCII); // seclume-allow: BSON field name, public
            pos++; // skip null byte

            long valueOffset = pos;
            int valueLength;
            switch (type) {
                case 0x01 -> { // Double
                    valueLength = 8;
                    pos += 8;
                }
                case 0x02 -> { // String
                    int strLen = segment.get(ValueLayout.JAVA_INT_UNALIGNED, pos);
                    valueLength = strLen;
                    pos += 4 + strLen;
                }
                case 0x03, 0x04 -> { // Embedded document or Array
                    int docLen = segment.get(ValueLayout.JAVA_INT_UNALIGNED, pos);
                    valueLength = docLen;
                    pos += docLen;
                }
                case 0x05 -> { // Binary
                    int binLen = segment.get(ValueLayout.JAVA_INT_UNALIGNED, pos);
                    valueLength = binLen;
                    pos += 4 + 1 + binLen; // int32 length + subtype byte + bytes
                }
                case 0x06, 0x0A -> { // Undefined, Null
                    valueLength = 0;
                }
                case 0x07 -> { // ObjectId (12 bytes)
                    valueLength = 12;
                    pos += 12;
                }
                case 0x08 -> { // Boolean
                    valueLength = 1;
                    pos += 1;
                }
                case 0x09, 0x11, 0x12 -> { // UTC datetime, Timestamp, Int64 (8 bytes)
                    valueLength = 8;
                    pos += 8;
                }
                case 0x0B -> { // Regex (two cstrings)
                    long startRegex = pos;
                    while (pos < end && segment.get(ValueLayout.JAVA_BYTE, pos) != 0) {
                        pos++;
                    }
                    pos++;
                    while (pos < end && segment.get(ValueLayout.JAVA_BYTE, pos) != 0) {
                        pos++;
                    }
                    pos++;
                    valueLength = (int) (pos - startRegex);
                }
                case 0x0C -> { // DBPointer (string + 12 bytes ObjectId)
                    int strLen = segment.get(ValueLayout.JAVA_INT_UNALIGNED, pos);
                    valueLength = 4 + strLen + 12;
                    pos += 4 + strLen + 12;
                }
                case 0x0D, 0x0E -> { // JS code, Symbol
                    int strLen = segment.get(ValueLayout.JAVA_INT_UNALIGNED, pos);
                    valueLength = strLen;
                    pos += 4 + strLen;
                }
                case 0x0F -> { // JS code with scope
                    int codeWLen = segment.get(ValueLayout.JAVA_INT_UNALIGNED, pos);
                    valueLength = codeWLen;
                    pos += codeWLen;
                }
                case 0x10 -> { // Int32
                    valueLength = 4;
                    pos += 4;
                }
                case 0x13 -> { // Decimal128
                    valueLength = 16;
                    pos += 16;
                }
                case -1, 0x7F -> { // Min key, Max key
                    valueLength = 0;
                }
                default -> throw new IllegalArgumentException("unsupported BSON element type "
                        + type + " for field " + name);
            }
            elements.put(name, new Element(type, valueOffset, valueLength));
        }
    }

    public boolean has(String name) {
        return elements.containsKey(name);
    }

    public double getDouble(String name, double defaultValue) {
        Element el = elements.get(name);
        if (el == null) {
            return defaultValue;
        }
        if (el.type == 0x01) {
            long bits = segment.get(ValueLayout.JAVA_LONG_UNALIGNED, el.valueOffset);
            return Double.longBitsToDouble(bits);
        }
        if (el.type == 0x10) {
            return segment.get(ValueLayout.JAVA_INT_UNALIGNED, el.valueOffset);
        }
        return defaultValue;
    }

    public int getInt32(String name, int defaultValue) {
        Element el = elements.get(name);
        if (el == null) {
            return defaultValue;
        }
        if (el.type == 0x10) {
            return segment.get(ValueLayout.JAVA_INT_UNALIGNED, el.valueOffset);
        }
        if (el.type == 0x01) {
            return (int) getDouble(name, defaultValue);
        }
        if (el.type == 0x12) {
            return (int) segment.get(ValueLayout.JAVA_LONG_UNALIGNED, el.valueOffset);
        }
        return defaultValue;
    }

    public boolean getBoolean(String name, boolean defaultValue) {
        Element el = elements.get(name);
        if (el == null || el.type != 0x08) {
            return defaultValue;
        }
        return segment.get(ValueLayout.JAVA_BYTE, el.valueOffset) != 0;
    }

    public String getString(String name) {
        Element el = elements.get(name);
        if (el == null || el.type != 0x02) {
            return null;
        }
        int len = el.valueLength - 1; // exclude null terminator
        if (len <= 0) {
            return "";
        }
        byte[] bytes = new byte[len];
        MemorySegment.copy(segment, el.valueOffset + 4, MemorySegment.ofArray(bytes), 0, len);
        return new String(bytes, StandardCharsets.UTF_8); // seclume-allow: server error or status string, public
    }

    /**
     * Returns a zero-copy {@link MemorySegment} slice of the binary field.
     */
    public MemorySegment getBinary(String name) {
        Element el = elements.get(name);
        if (el == null || el.type != 0x05) {
            return null;
        }
        // valueOffset points to int32 length; after 4 bytes is subtype, after 5 bytes is data
        return segment.asSlice(el.valueOffset + 5, el.valueLength);
    }

    public List<String> getStringArray(String name) {
        Element el = elements.get(name);
        if (el == null || el.type != 0x04) {
            return Collections.emptyList();
        }
        BsonReader arrayReader = new BsonReader(segment, el.valueOffset);
        List<String> list = new ArrayList<>();
        for (int i = 0; ; i++) {
            String val = arrayReader.getString(String.valueOf(i));
            if (val == null) {
                break;
            }
            list.add(val);
        }
        return Collections.unmodifiableList(list);
    }

    public boolean isOk() {
        return getDouble("ok", 0.0) == 1.0;
    }

    public String errmsg() {
        return getString("errmsg");
    }

    public int code() {
        return getInt32("code", 0);
    }

    public int conversationId() {
        return getInt32("conversationId", 0);
    }

    public boolean isDone() {
        return getBoolean("done", false);
    }

    public int documentLength() {
        return documentLength;
    }
}
