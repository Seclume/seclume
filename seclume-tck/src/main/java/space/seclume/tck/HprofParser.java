package space.seclume.tck;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * An hprof parser, as small as possible and as exact as necessary.
 *
 * <p>It reads only what the proof needs: <b>primitive arrays</b>. That is where
 * every secret that ever made it onto the heap lives - since JDK 9 a
 * {@code String} is a {@code byte[]} (Latin-1) or a {@code char[]}, a password
 * from a file is a {@code byte[]}, a {@code char[]} from the Spring binder is a
 * {@code char[]}. This proof needs neither the object graph, nor the class
 * hierarchy, nor the roots.
 *
 * <p>All other record kinds are nevertheless <b>parsed in full</b>, because the
 * stream would otherwise fall out of step. On an unknown record kind the parser
 * aborts rather than guessing on: a silent misstep would mean the test finds
 * nothing and turns green - which would be the worst
 * denkbare Ausgang.
 *
 * <p>Every number in the hprof format is big-endian. A {@code char[]}
 * therefore sits in the file as UTF-16BE; anyone searching raw for a password
 * has to
 * genau danach suchen.
 */
public final class HprofParser {

    /** What the parser reports to the caller. */
    @FunctionalInterface
    public interface ArrayVisitor {
        /**
         * @param objectId the array's id in the dump
         * @param type     {@code byte} or {@code char}
         * @param data     the array content (a copy, big-endian as in the file)
         */
        void primitiveArray(long objectId, PrimitiveType type, ByteBuffer data);
    }

    public enum PrimitiveType {
        OBJECT(2, 0), BOOLEAN(4, 1), CHAR(5, 2), FLOAT(6, 4), DOUBLE(7, 8),
        BYTE(8, 1), SHORT(9, 2), INT(10, 4), LONG(11, 8);

        private final int tag;
        private final int size;

        PrimitiveType(int tag, int size) {
            this.tag = tag;
            this.size = size;
        }

        static PrimitiveType of(int tag, int idSize) {
            for (PrimitiveType type : values()) {
                if (type.tag == tag) {
                    return type;
                }
            }
            throw new IllegalStateException("unknown hprof basic type " + tag);
        }

        int size(int idSize) {
            return this == OBJECT ? idSize : size;
        }
    }

    private static final int TAG_HEAP_DUMP = 0x0c;
    private static final int TAG_HEAP_DUMP_SEGMENT = 0x1c;

    private final ByteBuffer buffer;
    private final int idSize;

    private HprofParser(ByteBuffer buffer, int idSize) {
        this.buffer = buffer;
        this.idSize = idSize;
    }

    /** Reads the dump and reports every {@code byte[]} and {@code char[]}. */
    public static void forEachPrimitiveArray(Path dump, ArrayVisitor visitor) throws IOException {
        try (FileChannel channel = FileChannel.open(dump, StandardOpenOption.READ)) {
            long size = channel.size();
            if (size > Integer.MAX_VALUE) {
                throw new IOException("heap dump larger than 2 GB is not supported: " + size);
            }
            ByteBuffer buffer = channel.map(FileChannel.MapMode.READ_ONLY, 0, size);
            new HprofParser(buffer, readHeader(buffer)).parse(visitor);
        }
    }

    /** @return the size of an object id in bytes */
    private static int readHeader(ByteBuffer buffer) throws IOException {
        StringBuilder format = new StringBuilder();
        byte b;
        while ((b = buffer.get()) != 0) {
            format.append((char) b);
        }
        if (!format.toString().startsWith("JAVA PROFILE")) {
            throw new IOException("not an hprof file: " + format);
        }
        int idSize = buffer.getInt();
        if (idSize != 4 && idSize != 8) {
            throw new IOException("unexpected identifier size " + idSize);
        }
        buffer.getLong();  // Zeitstempel
        return idSize;
    }

    private void parse(ArrayVisitor visitor) throws IOException {
        while (buffer.remaining() >= 9) {
            int tag = buffer.get() & 0xff;
            buffer.getInt();                                    // time since the header
            long length = buffer.getInt() & 0xffffffffL;
            int end = (int) (buffer.position() + length);
            if (end > buffer.limit()) {
                throw new IOException("truncated hprof record of tag 0x"
                        + Integer.toHexString(tag));
            }
            if (tag == TAG_HEAP_DUMP || tag == TAG_HEAP_DUMP_SEGMENT) {
                parseHeapDump(end, visitor);
                if (buffer.position() != end) {
                    throw new IOException("heap dump segment ended at " + buffer.position()
                            + " instead of " + end);
                }
            } else {
                buffer.position(end);
            }
        }
    }

    private void parseHeapDump(int end, ArrayVisitor visitor) throws IOException {
        while (buffer.position() < end) {
            int subTag = buffer.get() & 0xff;
            switch (subTag) {
                case 0xff -> skip(idSize);                                   // ROOT UNKNOWN
                case 0x01 -> skip(2L * idSize);                              // ROOT JNI GLOBAL
                case 0x02, 0x03 -> skip(idSize + 8L);                        // JNI LOCAL, JAVA FRAME
                case 0x04 -> skip(idSize + 4L);                              // ROOT NATIVE STACK
                case 0x05 -> skip(idSize);                                   // ROOT STICKY CLASS
                case 0x06 -> skip(idSize + 4L);                              // ROOT THREAD BLOCK
                case 0x07 -> skip(idSize);                                   // ROOT MONITOR USED
                case 0x08 -> skip(idSize + 8L);                              // ROOT THREAD OBJECT
                case 0x20 -> skipClassDump();
                case 0x21 -> skipInstanceDump();
                case 0x22 -> skipObjectArray();
                case 0x23 -> readPrimitiveArray(visitor);
                case 0xfe -> skip(4L + idSize);                              // HEAP DUMP INFO
                default -> throw new IOException(
                        "unknown heap dump sub record 0x" + Integer.toHexString(subTag)
                        + " at position " + (buffer.position() - 1)
                        + " - refusing to guess, the scan would silently miss data");
            }
        }
    }

    private void skipClassDump() {
        skip(7L * idSize + 8);                    // ids, stack trace, instance size
        int constants = buffer.getShort() & 0xffff;
        for (int i = 0; i < constants; i++) {
            buffer.getShort();                    // index into the constant pool
            PrimitiveType type = PrimitiveType.of(buffer.get() & 0xff, idSize);
            skip(type.size(idSize));
        }
        int statics = buffer.getShort() & 0xffff;
        for (int i = 0; i < statics; i++) {
            skip(idSize);                         // Name
            PrimitiveType type = PrimitiveType.of(buffer.get() & 0xff, idSize);
            skip(type.size(idSize));
        }
        int fields = buffer.getShort() & 0xffff;
        for (int i = 0; i < fields; i++) {
            skip(idSize);                         // Name
            buffer.get();                         // Typ
        }
    }

    private void skipInstanceDump() {
        skip(idSize + 4L + idSize);
        long bytes = buffer.getInt() & 0xffffffffL;
        skip(bytes);
    }

    private void skipObjectArray() {
        skip(idSize + 4L);
        long elements = buffer.getInt() & 0xffffffffL;
        skip(idSize);                             // Klasse des Arrays
        skip(elements * idSize);
    }

    private void readPrimitiveArray(ArrayVisitor visitor) {
        long objectId = readId();
        buffer.getInt();                          // Stacktrace
        long elements = buffer.getInt() & 0xffffffffL;
        PrimitiveType type = PrimitiveType.of(buffer.get() & 0xff, idSize);
        long bytes = elements * type.size(idSize);

        if (type == PrimitiveType.BYTE || type == PrimitiveType.CHAR) {
            ByteBuffer slice = buffer.slice(buffer.position(), (int) bytes)
                    .order(java.nio.ByteOrder.BIG_ENDIAN);
            visitor.primitiveArray(objectId, type, slice);
        }
        skip(bytes);
    }

    private long readId() {
        return idSize == 8 ? buffer.getLong() : buffer.getInt() & 0xffffffffL;
    }

    private void skip(long bytes) {
        buffer.position((int) (buffer.position() + bytes));
    }

    /** For messages only: the format name from the file header. */
    public static String formatName(Path dump) throws IOException {
        try (FileChannel channel = FileChannel.open(dump, StandardOpenOption.READ)) {
            // seclume-allow: 32 bytes of file header, read to name the format in a message
            ByteBuffer head = ByteBuffer.allocate(32);
            channel.read(head);
            head.flip();
            StringBuilder out = new StringBuilder();
            while (head.hasRemaining()) {
                byte b = head.get();
                if (b == 0) {
                    break;
                }
                out.append((char) b);
            }
            return out.toString();
        }
    }

    /** A helper for messages: bytes as printable text, shortened. */
    static String preview(ByteBuffer data, int limit) {
        ByteBuffer copy = data.duplicate();
        int length = Math.min(limit, copy.remaining());
        byte[] bytes = new byte[length];
        copy.get(bytes);
        StringBuilder out = new StringBuilder();
        for (byte b : bytes) {
            out.append(b >= 32 && b < 127 ? (char) b : '.');
        }
        return out.toString().trim() + (data.remaining() > limit ? "…" : "");
    }

    static byte[] utf8(String text) {
        // seclume-allow: field names out of the dump file, never a secret
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
