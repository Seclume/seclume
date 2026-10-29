package space.seclume.heapdump;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Who holds what was found: from an offset in the dump file to the field of
 * the object that keeps it.
 *
 * <p>An offset says that a credential is in the dump. An audit needs to know
 * <i>where in the application</i> - "a {@code String} in
 * {@code com.acme.Config.apiKey}" is a line of code to change; "byte 81234567"
 * is not. So this reads the dump's object structure:
 *
 * <ol>
 *   <li>the class names, their fields, and which {@code byte[]} or
 *       {@code char[]} contains each offset;
 *   <li>which objects, static fields and object arrays refer to those arrays;
 *   <li>and where an array is the value of a {@code String}, which ones refer
 *       to that {@code String} - the field that holds the text.
 * </ol>
 *
 * <p>Each step is a pass over the file, read in windows rather than mapped,
 * so a dump larger than 2 GB is no different from a small one. Only the
 * arrays that contain a finding, and the strings around them, are followed;
 * nothing else of the heap is kept.
 *
 * <p>What comes out are class and field names, which are no secret, and the
 * kinds {@code unreferenced} - garbage the collector had not reclaimed when
 * the dump was taken - and {@code outside any object} - a match in the dump's
 * own bookkeeping, or in memory no object owns.
 */
public final class Attribution {

    /** Holders named per finding; more are counted, not listed. */
    static final int HOLDERS_NAMED = 3;

    private static final int TAG_STRING = 0x01;
    private static final int TAG_LOAD_CLASS = 0x02;
    private static final int TAG_HEAP_DUMP = 0x0c;
    private static final int TAG_HEAP_DUMP_SEGMENT = 0x1c;

    private static final int OBJECT = 2;

    private final Path dump;
    private int idSize;

    /** Symbol ids to names: class and field names. */
    private final Map<Long, String> symbols = new HashMap<>();
    /** Class object ids to the symbol of their name. */
    private final Map<Long, Long> classNames = new HashMap<>();
    /** Class object ids to their layout. */
    private final Map<Long, ClassInfo> classes = new HashMap<>();
    /** For every instance class: where in an instance its references lie. */
    private final Map<Long, List<Reference>> referenceLayout = new HashMap<>();

    /** Arrays that contain a finding: id to kind. */
    private final Map<Long, String> targetArrays = new HashMap<>();
    /** Strings whose value is one of those arrays: String id to its array. */
    private final Map<Long, Long> stringOfArray = new HashMap<>();
    /** Holders of each target object - an array or a String. */
    private final Map<Long, Set<String>> holders = new HashMap<>();
    /** The array each finding offset falls into. */
    private final Map<Long, Long> arrayAt = new HashMap<>();

    private record Field(long name, int type) {
    }

    private record ClassInfo(long superClass, List<Field> instanceFields) {
    }

    /** A reference field: its offset in the instance data, and its name for people. */
    private record Reference(int offset, String name) {
    }

    private Attribution(Path dump) {
        this.dump = dump;
    }

    /**
     * What the structure says about a set of offsets.
     *
     * @param holders      per offset, what holds it - see {@link #of}
     * @param stringHashes where in the file the {@code hash} field of each
     *                     {@code String} lies whose value holds one of the
     *                     offsets: four bytes each, a hash of the very text
     *                     that was found, and as good as a dictionary
     *                     needs to confirm a guess
     */
    public record Result(Map<Long, String> holders, List<Long> stringHashes) {
    }

    /**
     * Names the holder of each offset - one line each, in the order given;
     * an offset without one is left out of the map.
     */
    public static Map<Long, String> of(Path dump, long[] offsets) throws IOException {
        return analyse(dump, offsets).holders();
    }

    /** The holders, and the {@code String} hash fields that go with them. */
    public static Result analyse(Path dump, long[] offsets) throws IOException {
        if (offsets.length == 0) {
            return new Result(Map.of(), List.of());
        }
        long[] sorted = offsets.clone();
        Arrays.sort(sorted);
        Attribution attribution = new Attribution(dump);
        attribution.passOne(sorted);
        if (!attribution.targetArrays.isEmpty()) {
            attribution.passReferences(attribution.targetArrays.keySet(), true);
            if (!attribution.stringOfArray.isEmpty()) {
                attribution.passReferences(attribution.stringOfArray.keySet(), false);
            }
        }
        Map<Long, String> named = new LinkedHashMap<>();
        for (long offset : offsets) {
            named.put(offset, attribution.describe(offset));
        }
        List<Long> hashes = new ArrayList<>(attribution.hashFields.values());
        hashes.sort(null);
        return new Result(named, List.copyOf(hashes));
    }

    /** String id to the file position of its {@code hash} field. */
    private final Map<Long, Long> hashFields = new HashMap<>();
    /** Per class: where its {@code hash} int lies in an instance, or -1. */
    private final Map<Long, Integer> hashOffsets = new HashMap<>();

    /** The offset of an {@code int hash} field in an instance of the class, or -1. */
    private int hashOffset(long classId) throws IOException {
        Integer known = hashOffsets.get(classId);
        if (known != null) {
            return known;
        }
        int found = -1;
        int offset = 0;
        Set<Long> seen = new HashSet<>();
        long current = classId;
        outer:
        while (current != 0 && seen.add(current)) {
            ClassInfo info = classes.get(current);
            if (info == null) {
                break;
            }
            for (Field field : info.instanceFields()) {
                if (field.type() == 10 && "hash".equals(symbol(field.name()))) {
                    found = offset;
                    break outer;
                }
                offset += size(field.type());
            }
            current = info.superClass();
        }
        hashOffsets.put(classId, found);
        return found;
    }

    // ------------------------------------------------------------ pass one --

    /** Names, classes, and the arrays the offsets fall into. */
    private void passOne(long[] offsets) throws IOException {
        try (Input in = new Input(dump)) {
            idSize = in.header();
            while (in.remaining() >= 9) {
                int tag = in.u1();
                in.u4();                                  // time
                long length = in.u4();
                long end = in.position() + length;
                switch (tag) {
                    case TAG_STRING -> {
                        long id = in.id(idSize);
                        int textLength = (int) (length - idSize);
                        symbols.put(id, in.utf8(textLength));
                    }
                    case TAG_LOAD_CLASS -> {
                        in.u4();                          // serial
                        long classId = in.id(idSize);
                        in.u4();                          // stack trace
                        classNames.put(classId, in.id(idSize));
                    }
                    case TAG_HEAP_DUMP, TAG_HEAP_DUMP_SEGMENT -> heapOne(in, end, offsets);
                    default -> in.skip(length);
                }
                if (in.position() != end) {
                    throw new IOException("an hprof record of tag 0x" + Integer.toHexString(tag)
                            + " ended at " + in.position() + " instead of " + end);
                }
            }
        }
    }

    private void heapOne(Input in, long end, long[] offsets) throws IOException {
        while (in.position() < end) {
            int sub = in.u1();
            switch (sub) {
                case 0x20 -> readClass(in);
                case 0x23 -> {
                    long id = in.id(idSize);
                    in.u4();                              // stack trace
                    long elements = in.u4();
                    int type = in.u1();
                    long bytes = elements * size(type);
                    long start = in.position();
                    if (type == 5 || type == 8) {         // char[], byte[]
                        int at = firstAtOrAfter(offsets, start);
                        while (at < offsets.length && offsets[at] < start + bytes) {
                            arrayAt.put(offsets[at], id);
                            targetArrays.put(id, type == 5 ? "char[]" : "byte[]");
                            at++;
                        }
                    }
                    in.skip(bytes);
                }
                default -> skipSub(in, sub);
            }
        }
    }

    private void readClass(Input in) throws IOException {
        long classId = in.id(idSize);
        in.u4();                                          // stack trace
        long superClass = in.id(idSize);
        in.skip(5L * idSize + 4);                         // loader, signers, domain, 2 reserved; size
        int constants = in.u2();
        for (int i = 0; i < constants; i++) {
            in.u2();
            in.skip(size(in.u1()));
        }
        int statics = in.u2();
        for (int i = 0; i < statics; i++) {
            in.id(idSize);
            in.skip(size(in.u1()));
        }
        int fields = in.u2();
        List<Field> instanceFields = new ArrayList<>(fields);
        for (int i = 0; i < fields; i++) {
            long name = in.id(idSize);
            instanceFields.add(new Field(name, in.u1()));
        }
        classes.put(classId, new ClassInfo(superClass, instanceFields));
    }

    // ------------------------------------------------- the reference passes --

    /**
     * Who refers to the targets: instances, static fields, object arrays.
     * In the first round a {@code String} referring to a target array is not
     * a holder but a step - its own holders come in the second.
     */
    private void passReferences(Set<Long> targets, boolean arrays) throws IOException {
        try (Input in = new Input(dump)) {
            in.header();
            while (in.remaining() >= 9) {
                int tag = in.u1();
                in.u4();
                long length = in.u4();
                long end = in.position() + length;
                if (tag == TAG_HEAP_DUMP || tag == TAG_HEAP_DUMP_SEGMENT) {
                    heapReferences(in, end, targets, arrays);
                } else {
                    in.skip(length);
                }
            }
        }
    }

    private void heapReferences(Input in, long end, Set<Long> targets, boolean arrays)
            throws IOException {
        while (in.position() < end) {
            int sub = in.u1();
            switch (sub) {
                case 0x20 -> staticReferences(in, targets);
                case 0x21 -> {
                    long id = in.id(idSize);
                    in.u4();
                    long classId = in.id(idSize);
                    long bytes = in.u4();
                    List<Reference> layout = layout(classId);
                    if (layout.isEmpty()) {
                        in.skip(bytes);
                        break;
                    }
                    long dataStart = in.position();
                    ByteBuffer data = in.bytes((int) bytes);
                    for (Reference reference : layout) {
                        if (reference.offset() + idSize > bytes) {
                            continue;
                        }
                        long value = idSize == 8 ? data.getLong(reference.offset())
                                : data.getInt(reference.offset()) & 0xffffffffL;
                        if (value != 0 && targets.contains(value)) {
                            boolean isString = "java.lang.String".equals(className(classId));
                            if (arrays && isString) {
                                stringOfArray.put(id, value);
                                int hash = hashOffset(classId);
                                if (hash >= 0 && hash + 4 <= bytes) {
                                    hashFields.put(id, dataStart + hash);
                                }
                            } else {
                                hold(value, (arrays ? targetArrays.get(value) + " in " : "String in ")
                                        + className(classId) + "." + reference.name());
                            }
                        }
                    }
                }
                case 0x22 -> {
                    in.id(idSize);
                    in.u4();
                    long elements = in.u4();
                    long arrayClass = in.id(idSize);
                    for (long i = 0; i < elements; i++) {
                        long value = in.id(idSize);
                        if (value != 0 && targets.contains(value)) {
                            hold(value, (arrays ? targetArrays.get(value) : "String")
                                    + " as element of " + arrayName(arrayClass));
                        }
                    }
                }
                default -> skipSub(in, sub);
            }
        }
    }

    private void staticReferences(Input in, Set<Long> targets) throws IOException {
        long classId = in.id(idSize);
        in.u4();
        in.id(idSize);
        in.skip(5L * idSize + 4);
        int constants = in.u2();
        for (int i = 0; i < constants; i++) {
            in.u2();
            in.skip(size(in.u1()));
        }
        int statics = in.u2();
        for (int i = 0; i < statics; i++) {
            long name = in.id(idSize);
            int type = in.u1();
            if (type == OBJECT) {
                long value = in.id(idSize);
                if (value != 0 && targets.contains(value)) {
                    String kind = targetArrays.containsKey(value) ? targetArrays.get(value)
                            : "String";
                    hold(value, kind + " in static " + className(classId) + "."
                            + symbol(name));
                }
            } else {
                in.skip(size(type));
            }
        }
        int fields = in.u2();
        in.skip((long) fields * (idSize + 1));
    }

    private void hold(long target, String holder) {
        holders.computeIfAbsent(target, t -> new LinkedHashSet<>()).add(holder);
    }

    /** Where the references of an instance of {@code classId} lie, own fields first, as HPROF writes them. */
    private List<Reference> layout(long classId) throws IOException {
        List<Reference> known = referenceLayout.get(classId);
        if (known != null) {
            return known;
        }
        List<Reference> references = new ArrayList<>();
        int offset = 0;
        Set<Long> seen = new HashSet<>();
        long current = classId;
        while (current != 0 && seen.add(current)) {
            ClassInfo info = classes.get(current);
            if (info == null) {
                break;
            }
            for (Field field : info.instanceFields()) {
                if (field.type() == OBJECT) {
                    references.add(new Reference(offset, symbol(field.name())));
                }
                offset += size(field.type());
            }
            current = info.superClass();
        }
        List<Reference> fixed = List.copyOf(references);
        referenceLayout.put(classId, fixed);
        return fixed;
    }

    // --------------------------------------------------------- the answers --

    private String describe(long offset) {
        Long array = arrayAt.get(offset);
        if (array == null) {
            return "outside any object";
        }
        String kind = targetArrays.get(array);
        Set<String> found = new LinkedHashSet<>(holders.getOrDefault(array, Set.of()));
        boolean viaString = false;
        for (Map.Entry<Long, Long> string : stringOfArray.entrySet()) {
            if (string.getValue() == (long) array) {
                viaString = true;
                found.addAll(holders.getOrDefault(string.getKey(), Set.of()));
            }
        }
        if (found.isEmpty()) {
            return viaString ? "String, unreferenced" : kind + ", unreferenced";
        }
        List<String> listed = new ArrayList<>(found);
        String text = String.join("; ", listed.subList(0, Math.min(HOLDERS_NAMED,
                listed.size())));
        return listed.size() > HOLDERS_NAMED
                ? text + " (and " + (listed.size() - HOLDERS_NAMED) + " more)" : text;
    }

    private String className(long classId) {
        Long name = classNames.get(classId);
        return name == null ? "class@" + Long.toHexString(classId)
                : symbol(name).replace('/', '.');
    }

    private String arrayName(long classId) {
        String name = className(classId);
        // [Ljava.lang.Object; -> java.lang.Object[]
        int dims = 0;
        while (dims < name.length() && name.charAt(dims) == '[') {
            dims++;
        }
        if (dims > 0 && name.length() > dims + 1 && name.charAt(dims) == 'L'
                && name.endsWith(";")) {
            name = name.substring(dims + 1, name.length() - 1) + "[]".repeat(dims);
        }
        return name;
    }

    private String symbol(long id) {
        String name = symbols.get(id);
        return name == null ? "?" : name;
    }

    // ----------------------------------------------------------- the format --

    private int size(int type) throws IOException {
        return switch (type) {
            case OBJECT -> idSize;
            case 4, 8 -> 1;                               // boolean, byte
            case 5, 9 -> 2;                               // char, short
            case 6, 10 -> 4;                              // float, int
            case 7, 11 -> 8;                              // double, long
            default -> throw new IOException("unknown hprof basic type " + type);
        };
    }

    private void skipSub(Input in, int sub) throws IOException {
        switch (sub) {
            case 0xff -> in.skip(idSize);                              // root unknown
            case 0x01 -> in.skip(2L * idSize);                         // JNI global
            case 0x02, 0x03 -> in.skip(idSize + 8L);                   // JNI local, Java frame
            case 0x04 -> in.skip(idSize + 4L);                         // native stack
            case 0x05 -> in.skip(idSize);                              // sticky class
            case 0x06 -> in.skip(idSize + 4L);                         // thread block
            case 0x07 -> in.skip(idSize);                              // monitor used
            case 0x08 -> in.skip(idSize + 8L);                         // thread object
            case 0x20 -> readClassSkipping(in);
            case 0x21 -> {
                in.skip(2L * idSize + 4);
                in.skip(in.u4());
            }
            case 0x22 -> {
                in.skip(idSize + 4L);
                long elements = in.u4();
                in.skip(idSize + elements * idSize);
            }
            case 0x23 -> {
                in.skip(idSize + 4L);
                long elements = in.u4();
                in.skip(elements * size(in.u1()));
            }
            case 0xfe -> in.skip(4L + idSize);                         // heap dump info
            default -> throw new IOException("unknown heap dump sub record 0x"
                    + Integer.toHexString(sub) + " at " + (in.position() - 1)
                    + " - refusing to guess");
        }
    }

    private void readClassSkipping(Input in) throws IOException {
        in.skip(7L * idSize + 8);
        int constants = in.u2();
        for (int i = 0; i < constants; i++) {
            in.u2();
            in.skip(size(in.u1()));
        }
        int statics = in.u2();
        for (int i = 0; i < statics; i++) {
            in.id(idSize);
            in.skip(size(in.u1()));
        }
        int fields = in.u2();
        in.skip((long) fields * (idSize + 1));
    }

    private static int firstAtOrAfter(long[] sorted, long value) {
        int at = Arrays.binarySearch(sorted, value);
        if (at < 0) {
            return -at - 1;
        }
        while (at > 0 && sorted[at - 1] == value) {
            at--;
        }
        return at;
    }

    /** The file, read forward through a window - big-endian, as HPROF is. */
    private static final class Input implements AutoCloseable {

        private static final int WINDOW = 1 << 20;

        private final FileChannel channel;
        private final long size;
        // seclume-allow: the searcher's own read window over a dump file, not a secret's path
        private final ByteBuffer window = ByteBuffer.allocate(WINDOW)
                .order(ByteOrder.BIG_ENDIAN);
        /** File offset of window[0]. */
        private long base;

        Input(Path file) throws IOException {
            this.channel = FileChannel.open(file, StandardOpenOption.READ);
            this.size = channel.size();
            window.limit(0);
        }

        /** Reads the header; returns the identifier size. */
        int header() throws IOException {
            StringBuilder format = new StringBuilder();
            int b;
            while (true) {
                if (remaining() == 0) {
                    throw new IOException("not an hprof file");
                }
                b = u1();
                if (b == 0) {
                    break;
                }
                format.append((char) b);
                if (format.length() > 64) {
                    throw new IOException("not an hprof file");
                }
            }
            // Not quoted: a file given as a dump by mistake may be anything,
            // a secret file among them.
            if (!format.toString().startsWith("JAVA PROFILE")) {
                throw new IOException("not an hprof file");
            }
            int idSize = (int) u4();
            if (idSize != 4 && idSize != 8) {
                throw new IOException("unexpected identifier size " + idSize);
            }
            skip(8);                                      // timestamp
            return idSize;
        }

        long position() {
            return base + window.position();
        }

        long remaining() {
            return size - position();
        }

        private void need(int bytes) throws IOException {
            if (window.remaining() >= bytes) {
                return;
            }
            long at = position();
            if (at + bytes > size) {
                throw new IOException("the dump ends in the middle of a record at " + at);
            }
            // What is left moves to the front: window[0] is now the byte at `at`.
            window.compact();
            base = at;
            while (window.position() < bytes) {
                int n = channel.read(window, base + window.position());
                if (n < 0) {
                    throw new IOException("the dump ends early at " + position());
                }
            }
            // Fill the rest of the window while the file has more.
            while (window.hasRemaining()) {
                int n = channel.read(window, base + window.position());
                if (n <= 0) {
                    break;
                }
            }
            window.flip();
        }

        int u1() throws IOException {
            need(1);
            return window.get() & 0xff;
        }

        int u2() throws IOException {
            need(2);
            return window.getShort() & 0xffff;
        }

        long u4() throws IOException {
            need(4);
            return window.getInt() & 0xffffffffL;
        }

        long id(int idSize) throws IOException {
            if (idSize == 8) {
                need(8);
                return window.getLong();
            }
            return u4();
        }

        /** The next {@code length} bytes; a view while it fits in the window, a copy otherwise. */
        ByteBuffer bytes(int length) throws IOException {
            if (length <= WINDOW) {
                need(length);
                ByteBuffer view = window.slice(window.position(), length)
                        .order(ByteOrder.BIG_ENDIAN);
                window.position(window.position() + length);
                return view;
            }
            // seclume-allow: an instance's field data larger than the window, read to find references
            ByteBuffer copy = ByteBuffer.allocate(length).order(ByteOrder.BIG_ENDIAN);
            while (copy.hasRemaining()) {
                int chunk = Math.min(copy.remaining(), WINDOW);
                need(chunk);
                ByteBuffer part = window.slice(window.position(), chunk);
                copy.put(part);
                window.position(window.position() + chunk);
            }
            return copy.flip();
        }

        /** A class or field name - a symbol of the class files, never a secret. */
        String utf8(int length) throws IOException {
            ByteBuffer bytes = bytes(length);
            return StandardCharsets.UTF_8.decode(bytes).toString();
        }

        void skip(long bytes) {
            long target = position() + bytes;
            if (target - base <= window.limit()) {
                window.position((int) (target - base));
            } else {
                base = target;
                window.clear().limit(0);
            }
        }

        @Override
        public void close() throws IOException {
            channel.close();
        }
    }
}
