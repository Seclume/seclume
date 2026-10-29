package space.seclume.heapcheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The structure half of a finding, on dumps written byte by byte here: an
 * instance field, a static, an array element, a {@code String} in between,
 * a superclass's field, garbage - and an offset in no object at all. Written
 * by hand so that every layout rule is tested against what the HPROF format
 * says rather than against what one JDK happens to write;
 * {@link HeapCheckTest} adds a real dump.
 */
class AttributionTest {

    /** Writes an HPROF file record by record. */
    private static final class Hprof {
        final int idSize;
        final ByteArrayOutputStream file = new ByteArrayOutputStream();
        final ByteArrayOutputStream heap = new ByteArrayOutputStream();
        long nextSymbol = 0x1000;

        Hprof(int idSize) {
            this.idSize = idSize;
            file.writeBytes("JAVA PROFILE 1.0.2\0".getBytes(StandardCharsets.US_ASCII));
            u4(file, idSize);
            u8(file, 0);
        }

        static void u1(ByteArrayOutputStream out, int v) {
            out.write(v);
        }

        static void u2(ByteArrayOutputStream out, int v) {
            out.write(v >>> 8);
            out.write(v);
        }

        static void u4(ByteArrayOutputStream out, long v) {
            out.writeBytes(ByteBuffer.allocate(4).putInt((int) v).array());
        }

        static void u8(ByteArrayOutputStream out, long v) {
            out.writeBytes(ByteBuffer.allocate(8).putLong(v).array());
        }

        void id(ByteArrayOutputStream out, long v) {
            if (idSize == 8) {
                u8(out, v);
            } else {
                u4(out, v);
            }
        }

        void record(int tag, byte[] body) {
            u1(file, tag);
            u4(file, 0);
            u4(file, body.length);
            file.writeBytes(body);
        }

        long symbol(String text) {
            long id = nextSymbol++;
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            id(body, id);
            body.writeBytes(text.getBytes(StandardCharsets.UTF_8));
            record(0x01, body.toByteArray());
            return id;
        }

        void loadClass(long classId, String name) {
            long symbol = symbol(name);
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            u4(body, 1);
            id(body, classId);
            u4(body, 0);
            id(body, symbol);
            record(0x02, body.toByteArray());
        }

        /** A class dump: fields are {name, type} pairs, statics {name, type, value}. */
        void classDump(long classId, long superId, Object[][] statics, Object[][] fields) {
            u1(heap, 0x20);
            id(heap, classId);
            u4(heap, 0);
            id(heap, superId);
            for (int i = 0; i < 5; i++) {
                id(heap, 0);                              // loader, signers, domain, reserved
            }
            u4(heap, 0);                                  // instance size
            u2(heap, 0);                                  // constant pool
            u2(heap, statics.length);
            for (Object[] s : statics) {
                id(heap, symbol((String) s[0]));
                int type = (int) s[1];
                u1(heap, type);
                if (type == 2) {
                    id(heap, (long) s[2]);
                } else {
                    u4(heap, (long) s[2]);                // int
                }
            }
            u2(heap, fields.length);
            for (Object[] f : fields) {
                id(heap, symbol((String) f[0]));
                u1(heap, (int) f[1]);
            }
        }

        /** An instance: values as written, own class's fields first. */
        void instance(long id, long classId, long... referencesAndInts) {
            ByteArrayOutputStream data = new ByteArrayOutputStream();
            for (long value : referencesAndInts) {
                id(data, value);
            }
            u1(heap, 0x21);
            id(heap, id);
            u4(heap, 0);
            id(heap, classId);
            u4(heap, data.size());
            heap.writeBytes(data.toByteArray());
        }

        void objectArray(long id, long classId, long... elements) {
            u1(heap, 0x22);
            id(heap, id);
            u4(heap, 0);
            u4(heap, elements.length);
            id(heap, classId);
            for (long element : elements) {
                id(heap, element);
            }
        }

        /** A byte[]; returns the file offset of its first byte once written. */
        long byteArray(long id, byte[] content, long[] offsetOut) {
            u1(heap, 0x23);
            id(heap, id);
            u4(heap, 0);
            u4(heap, content.length);
            u1(heap, 8);
            offsetOut[0] = heap.size();
            heap.writeBytes(content);
            return offsetOut[0];
        }

        /** Closes the heap into one segment; returns where the segment's body starts. */
        long finish() {
            long bodyStart = file.size() + 9;
            record(0x1c, heap.toByteArray());
            return bodyStart;
        }
    }

    private static final long STRING = 0x100;
    private static final long CONFIG = 0x101;
    private static final long BASE = 0x102;
    private static final long HOLDER = 0x103;
    private static final long OBJECTS = 0x104;

    @ParameterizedTest
    @ValueSource(ints = {4, 8})
    void everyKindOfHolderIsNamed(int idSize, @TempDir Path directory) throws IOException {
        Hprof h = new Hprof(idSize);
        h.loadClass(STRING, "java/lang/String");
        h.loadClass(CONFIG, "com/acme/Config");
        h.loadClass(BASE, "com/acme/Base");
        h.loadClass(HOLDER, "com/acme/Holder");
        h.loadClass(OBJECTS, "[Ljava/lang/Object;");
        // String: a number first, then its value - a reference not at offset 0.
        // The number is as wide as an id (int or long), since instance() writes
        // every slot id-sized.
        h.classDump(STRING, 0, new Object[0][],
                new Object[][] {{"hash", idSize == 8 ? 11 : 10}, {"value", 2}});
        // Base has a field of its own; Config extends it and keeps a static too.
        h.classDump(BASE, 0, new Object[0][], new Object[][] {{"inherited", 2}});
        h.classDump(CONFIG, BASE, new Object[][] {{"TOKEN", 2, 0x501L}},
                new Object[][] {{"apiKey", 2}});
        h.classDump(HOLDER, 0, new Object[0][], new Object[][] {{"raw", 2}});
        h.classDump(OBJECTS, 0, new Object[0][], new Object[0][]);

        long[] at = new long[1];
        long apiKey = h.byteArray(0x401, "api-key-value".getBytes(StandardCharsets.US_ASCII), at);
        long token = h.byteArray(0x402, "static-token".getBytes(StandardCharsets.US_ASCII), at);
        long raw = h.byteArray(0x403, "raw-bytes-held".getBytes(StandardCharsets.US_ASCII), at);
        long listed = h.byteArray(0x404, "in-a-list".getBytes(StandardCharsets.US_ASCII), at);
        long garbage = h.byteArray(0x405, "nobody-holds".getBytes(StandardCharsets.US_ASCII), at);
        long inherited = h.byteArray(0x406, "inherited".getBytes(StandardCharsets.US_ASCII), at);

        h.instance(0x500, STRING, 0, 0x401);              // apiKey's String
        h.instance(0x501, STRING, 0, 0x402);              // TOKEN's String
        h.instance(0x502, STRING, 0, 0x404);              // the listed String
        h.instance(0x503, STRING, 0, 0x406);              // the inherited String
        // Config: own field apiKey first, then Base's field.
        h.instance(0x600, CONFIG, 0x500, 0x503);
        h.instance(0x601, HOLDER, 0x403);
        h.objectArray(0x700, OBJECTS, 0x502, 0);
        long segment = h.finish();

        Path dump = Files.write(directory.resolve("hand.hprof"), h.file.toByteArray());
        long outside = 20;                                // inside the file header
        Map<Long, String> held = Attribution.of(dump, new long[] {
                segment + apiKey + 3, segment + token, segment + raw, segment + listed,
                segment + garbage + 1, segment + inherited, outside});

        assertEquals("String in com.acme.Config.apiKey", held.get(segment + apiKey + 3));
        assertEquals("String in static com.acme.Config.TOKEN", held.get(segment + token));
        assertEquals("byte[] in com.acme.Holder.raw", held.get(segment + raw));
        assertEquals("String as element of java.lang.Object[]", held.get(segment + listed));
        assertEquals("byte[], unreferenced", held.get(segment + garbage + 1));
        assertEquals("String in com.acme.Config.inherited", held.get(segment + inherited));
        assertEquals("outside any object", held.get(outside));
    }

    /** A dump with a record of a kind the format does not have is refused, not guessed past. */
    @Test
    void anUnknownSubRecordIsRefused(@TempDir Path directory) throws IOException {
        Hprof h = new Hprof(8);
        Hprof.u1(h.heap, 0x77);
        h.finish();
        Path dump = Files.write(directory.resolve("bad.hprof"), h.file.toByteArray());
        IOException refused = assertThrows(IOException.class,
                () -> Attribution.of(dump, new long[] {40}));
        assertTrue(refused.getMessage().contains("refusing to guess"), refused.getMessage());
    }

    @Test
    void notAnHprofFileIsSaid(@TempDir Path directory) throws IOException {
        Path dump = Files.writeString(directory.resolve("x.hprof"), "not a dump at all");
        IOException refused = assertThrows(IOException.class,
                () -> Attribution.of(dump, new long[] {3}));
        assertTrue(refused.getMessage().contains("not an hprof file"), refused.getMessage());
    }

    /**
     * Records that straddle the read window: many arrays of a little over a
     * mebibyte each, the target in the last one.
     */
    @Test
    void recordsAcrossTheReadWindowAreReadWhole(@TempDir Path directory) throws IOException {
        Hprof h = new Hprof(8);
        h.loadClass(HOLDER, "com/acme/Holder");
        h.classDump(HOLDER, 0, new Object[0][], new Object[][] {{"last", 2}});
        long[] at = new long[1];
        byte[] filler = new byte[(1 << 20) + 17];
        for (int i = 0; i < 4; i++) {
            h.byteArray(0x900 + i, filler, at);
        }
        long last = h.byteArray(0x9ff, "the-last-one".getBytes(StandardCharsets.US_ASCII), at);
        h.instance(0x1000, HOLDER, 0x9ff);
        long segment = h.finish();
        Path dump = Files.write(directory.resolve("big.hprof"), h.file.toByteArray());
        assertEquals("byte[] in com.acme.Holder.last",
                Attribution.of(dump, new long[] {segment + last}).get(segment + last));
    }
}
