package space.seclume.heapdump;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/** Writes an HPROF file record by record - for tests that need every byte known. */
final class TestHprof {
    final int idSize;
    final ByteArrayOutputStream file = new ByteArrayOutputStream();
    final ByteArrayOutputStream heap = new ByteArrayOutputStream();
    long nextSymbol = 0x1000;

    TestHprof(int idSize) {
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

    /** A char[], as a String holds non-Latin-1 text and a dump writes it: UTF-16BE. */
    long charArray(long id, String content) {
        u1(heap, 0x23);
        id(heap, id);
        u4(heap, 0);
        u4(heap, content.length());
        u1(heap, 5);
        long at = heap.size();
        heap.writeBytes(content.getBytes(StandardCharsets.UTF_16BE));
        return at;
    }

    /** Closes the heap into one segment; returns where the segment's body starts. */
    long finish() {
        long bodyStart = file.size() + 9;
        record(0x1c, heap.toByteArray());
        return bodyStart;
    }
}
