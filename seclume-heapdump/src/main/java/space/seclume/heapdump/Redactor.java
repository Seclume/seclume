package space.seclume.heapdump;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64; // seclume-allow: the searcher encodes the pattern it hunts for
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Makes a heap dump safe to hand on: a copy in which every credential that
 * can be found is overwritten, checked again before it is let out.
 *
 * <p>A heap dump is needed - for a memory leak, for a vendor's support - and
 * it carries every secret the process held. Taking the secrets out by hand
 * means opening it in a tool, which is the exposure one wanted to avoid. This
 * does it in one pass over the file:
 *
 * <ol>
 *   <li>finds the secrets: the ones named ({@link Needle}, in every encoding
 *       they can lie in) and, if asked, the ones of a known shape
 *       ({@link Discovery}) - every occurrence, not the first few;
 *   <li>finds, for what discovery found, its echoes: the same value - and
 *       its parts, a JWT's segments, a key's lines, a token without its
 *       prefix - wherever else it lies, where it has no shape to be known by:
 *       the password of a URL in a configuration field of its own, the
 *       payload a JWT library split off;
 *   <li>writes a copy, readable by its owner only, and overwrites in it the
 *       value of each - the password of a URL rather than the URL, all of a
 *       PEM block - with {@code *} in the occurrence's own encoding, or zero
 *       bytes for a binary secret. Nothing moves: the dump stays a dump, the
 *       objects are where they were, a {@code String} keeps its length;
 *   <li>clears the {@code hash} field of every {@code String} whose text was
 *       overwritten, since a 32-bit hash of a password confirms a guess;
 *   <li>searches the copy again, the same way. If anything is still found
 *       the copy is deleted and the redaction fails: a half-redacted dump is
 *       worse than none, because it is trusted.
 * </ol>
 *
 * <p><b>What it does not reach.</b> A secret it cannot find - unnamed and of
 * no known shape, split across objects, compressed, encrypted with a key
 * that is also in the dump - stays. The check at the end proves that what
 * was looked for is gone, not that nothing else is there. Name what you know
 * ({@link Needle}); the shapes catch what you did not think of.
 */
public final class Redactor {

    private static final int WINDOW = 8 * 1024 * 1024;

    /** The most occurrences one redaction overwrites before it gives up as a sign of something wrong. */
    static final int MOST_REGIONS = 10_000_000;

    /**
     * A discovered value shorter than this is not looked for elsewhere: a
     * short password would match by chance - in the dump's own structure,
     * which overwriting would break.
     */
    static final int SHORTEST_ECHO = 8;

    /** Parts of a discovered value shorter than this are not looked for on their own. */
    static final int SHORTEST_PIECE = 16;

    /** The most echo patterns; past it the dump is mostly credentials. */
    static final int MOST_ECHOES = 1_000_000;

    private Redactor() {
    }

    /** How the bytes of an occurrence are replaced. */
    public enum Fill {
        /** One byte per character: {@code *}. */
        ASCII,
        /** {@code 00 2A} per character, as a {@code char[]} lies in a dump. */
        UTF16_BE,
        /** {@code 2A 00} per character. */
        UTF16_LE,
        /** Zero bytes: a binary secret, a key. */
        ZERO;

        void write(byte[] out) {
            for (int i = 0; i < out.length; i++) {
                out[i] = switch (this) {
                    case ASCII -> (byte) '*';
                    case UTF16_BE -> (i % 2 == 0) ? 0 : (byte) '*';
                    case UTF16_LE -> (i % 2 == 0) ? (byte) '*' : 0;
                    case ZERO -> 0;
                };
            }
        }

        static Fill of(String encoding) {
            return switch (encoding) {
                case "UTF-16BE" -> UTF16_BE;
                case "UTF-16LE" -> UTF16_LE;
                default -> ASCII;
            };
        }
    }

    /**
     * A named secret, as the patterns it can lie in: text as UTF-8, UTF-16 in
     * both byte orders and Base64; bytes as they are and as Base64. Built by
     * the caller from wherever the secret is - in a process of its own, since
     * searching for a secret means holding it.
     *
     * @param label    what the secret is called in a report - a file name,
     *                 never the value
     * @param patterns the byte patterns, each with how it is overwritten
     */
    public record Needle(String label, List<Pattern> patterns) {

        /** One encoding of a secret. */
        public record Pattern(String encoding, byte[] bytes, Fill fill) {
        }

        /** A secret that is text. */
        public static Needle text(String label, String secret) {
            if (secret.isEmpty()) {
                throw new IllegalArgumentException("an empty secret matches everywhere");
            }
            // The searcher holds what it hunts for - in its own process, which
            // is why a Needle is built by a caller that is not the application.
            byte[] utf8 = secret.getBytes(StandardCharsets.UTF_8); // seclume-allow: the searcher needs the pattern it hunts for
            List<Pattern> patterns = new ArrayList<>();
            patterns.add(new Pattern("UTF-8", utf8, Fill.ASCII));
            // seclume-allow: the searcher needs the pattern it hunts for
            patterns.add(new Pattern("UTF-16BE", secret.getBytes(StandardCharsets.UTF_16BE),
                    Fill.UTF16_BE));
            // seclume-allow: the searcher needs the pattern it hunts for
            patterns.add(new Pattern("UTF-16LE", secret.getBytes(StandardCharsets.UTF_16LE),
                    Fill.UTF16_LE));
            // seclume-allow: the searcher needs the pattern it hunts for
            patterns.add(new Pattern("Base64", Base64.getEncoder().encode(utf8), Fill.ASCII));
            return new Needle(label, List.copyOf(patterns));
        }

        /** A secret that is bytes - a key. */
        public static Needle bytes(String label, byte[] secret) {
            if (secret.length == 0) {
                throw new IllegalArgumentException("an empty secret matches everywhere");
            }
            return new Needle(label, List.of(new Pattern("bytes", secret.clone(), Fill.ZERO),
                    // seclume-allow: the searcher needs the pattern it hunts for
                    new Pattern("Base64", Base64.getEncoder().encode(secret), Fill.ASCII)));
        }
    }

    /**
     * What a redaction did. Counts and names, never values.
     *
     * @param named        per named secret: how many occurrences were overwritten
     * @param discovered   what discovery found in the original, or {@code null}
     * @param regions      byte ranges overwritten, in all
     * @param echoes       of those, copies or parts of a discovered value
     *                     found elsewhere, outside anything discovery matched
     * @param stringHashes {@code String} hash fields cleared
     */
    public record Report(Map<String, Long> named, Discovery.Result discovered, long regions,
            long echoes, long stringHashes) {

        /** Whether there was anything to overwrite. */
        public boolean changed() {
            return regions > 0;
        }
    }

    /** Thrown when the copy still held something after it was redacted; the copy is gone. */
    public static final class Incomplete extends IOException {
        private static final long serialVersionUID = 1L;

        Incomplete(String message) {
            super(message);
        }
    }

    record Region(long position, int length, Fill fill) {
    }

    /**
     * Redacts {@code dump} into {@code out}, which must not exist.
     *
     * @param needles  named secrets
     * @param discover whether to look for credentials of known shapes as well
     * @param ignore   detectors to leave out of that
     * @throws Incomplete when the check of the copy still finds something
     */
    public static Report redact(Path dump, Path out, List<Needle> needles, boolean discover,
            Set<String> ignore) throws IOException {
        RedactionEvent event = new RedactionEvent();
        event.begin();
        try {
            Report report = redactOnly(dump, out, needles, discover, ignore);
            event.end();
            if (event.shouldCommit()) {
                event.dump = String.valueOf(dump.getFileName());
                event.succeeded = true;
                event.places = report.regions();
                event.echoes = report.echoes();
                event.stringHashes = report.stringHashes();
                event.reason = "";
                event.commit();
            }
            return report;
        } catch (IOException | RuntimeException e) {
            event.end();
            if (event.shouldCommit()) {
                event.dump = String.valueOf(dump.getFileName());
                event.succeeded = false;
                event.reason = e.getMessage() == null ? e.getClass().getSimpleName()
                        : e.getMessage();
                event.commit();
            }
            throw e;
        }
    }

    private static Report redactOnly(Path dump, Path out, List<Needle> needles,
            boolean discover, Set<String> ignore) throws IOException {
        if (needles.isEmpty() && !discover) {
            throw new IllegalArgumentException("nothing to redact: name a secret or discover");
        }
        if (Files.exists(out)) {
            throw new IOException(out + " exists already; a redaction does not overwrite a file");
        }
        List<Region> regions = new ArrayList<>();
        Map<String, Long> named = new LinkedHashMap<>();
        for (Needle needle : needles) {
            named.put(needle.label(), find(dump, needle, regions));
        }
        Discovery.Result discovered = null;
        Echoes echoes = null;
        long echoed = 0;
        if (discover) {
            List<Region> found = new ArrayList<>();
            discovered = Discovery.scan(dump, ignore, at -> add(found,
                    new Region(at.valuePosition(), at.valueLength(), Fill.of(at.encoding()))));
            regions.addAll(found);
            echoes = Echoes.of(dump, found);
            if (echoes != null) {
                Covered covered = new Covered(found);
                List<Region> elsewhere = new ArrayList<>();
                echoes.find(dump, elsewhere, WINDOW);
                for (Region region : elsewhere) {
                    if (!covered.covers(region)) {
                        add(regions, region);
                        echoed++;
                    }
                }
            }
        }

        long[] starts = regions.stream().mapToLong(Region::position).distinct().toArray();
        List<Long> hashes = starts.length == 0 ? List.of()
                : Attribution.analyse(dump, starts).stringHashes();

        Path directory = out.toAbsolutePath().getParent();
        Path partial = Files.createTempFile(directory, ".seclume-redact-", ".hprof.part");
        boolean done = false;
        try {
            restrict(partial);
            // Into the file made above, not over it: replacing it would make
            // a new file with the default permissions.
            try (FileChannel from = FileChannel.open(dump, StandardOpenOption.READ);
                 FileChannel to = FileChannel.open(partial, StandardOpenOption.WRITE,
                         StandardOpenOption.TRUNCATE_EXISTING)) {
                long size = from.size();
                for (long at = 0; at < size; ) {
                    at += from.transferTo(at, size - at, to);
                }
            }
            try (FileChannel channel = FileChannel.open(partial, StandardOpenOption.WRITE)) {
                for (Region region : regions) {
                    byte[] fill = new byte[region.length()];
                    region.fill().write(fill);
                    write(channel, region.position(), fill);
                }
                for (long hash : hashes) {
                    write(channel, hash, new byte[4]);
                }
                channel.force(true);
            }
            check(partial, needles, discover, ignore, echoes);
            publish(partial, out);
            done = true;
            return new Report(Map.copyOf(named), discovered, regions.size(), echoed,
                    hashes.size());
        } finally {
            if (!done) {
                Files.deleteIfExists(partial);
            }
        }
    }

    /**
     * Gives the checked copy its name without replacing a file that appeared
     * there meanwhile: a link fails if the name is taken, where a rename on
     * POSIX would replace it. A file system without links gets the rename.
     */
    private static void publish(Path partial, Path out) throws IOException {
        try {
            Files.createLink(out, partial);
        } catch (java.nio.file.FileAlreadyExistsException taken) {
            throw new IOException(out + " exists already; a redaction does not overwrite a file",
                    taken);
        } catch (UnsupportedOperationException | java.nio.file.FileSystemException noLinks) {
            Files.move(partial, out, StandardCopyOption.ATOMIC_MOVE);
            return;
        }
        Files.delete(partial);
    }

    /** Owner only, where the file system has such a thing: the copy holds secrets until it is done. */
    private static void restrict(Path file) throws IOException {
        try {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException notPosix) {
            // Windows: the temporary file is in the owner's directory with the owner's ACL.
        }
    }

    private static void write(FileChannel channel, long position, byte[] bytes)
            throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        long at = position;
        while (buffer.hasRemaining()) {
            at += channel.write(buffer, at);
        }
    }

    private static void add(List<Region> regions, Region region) {
        if (regions.size() >= MOST_REGIONS) {
            throw new IllegalStateException("more than " + MOST_REGIONS + " places to "
                    + "overwrite - a dump that is mostly secret is not one to hand on");
        }
        regions.add(region);
    }

    /** The redacted copy, searched as the original was. Anything found is a failure. */
    static void check(Path copy, List<Needle> needles, boolean discover,
            Set<String> ignore) throws IOException {
        check(copy, needles, discover, ignore, null);
    }

    private static void check(Path copy, List<Needle> needles, boolean discover,
            Set<String> ignore, Echoes echoes) throws IOException {
        List<Region> left = new ArrayList<>();
        List<String> where = new ArrayList<>();
        for (Needle needle : needles) {
            if (find(copy, needle, left) > 0) {
                where.add(needle.label());
            }
        }
        if (echoes != null && echoes.find(copy, left, WINDOW) > 0) {
            where.add("copies or parts of a discovered credential");
        }
        if (discover) {
            Discovery.Result again = Discovery.scan(copy, ignore);
            if (!again.clean()) {
                where.add("discovered: " + String.join(", ",
                        again.valuesByDetector().keySet()));
            }
        }
        if (!where.isEmpty()) {
            throw new Incomplete("the redacted copy still holds what was looked for ("
                    + String.join("; ", where) + ") - it was deleted, not handed out");
        }
    }

    /**
     * Every occurrence of every pattern of {@code needle}, added to
     * {@code regions}; how many there were.
     */
    static long find(Path dump, Needle needle, List<Region> regions) throws IOException {
        return find(dump, needle, regions, WINDOW);
    }

    /** The same in windows of {@code windowSize} - small ones for the tests. */
    static long find(Path dump, Needle needle, List<Region> regions, int windowSize)
            throws IOException {
        int longest = needle.patterns().stream().mapToInt(p -> p.bytes().length).max()
                .orElse(1);
        long[] count = new long[1];
        windows(dump, longest, windowSize, (window, length, acceptBelow, start) -> {
            for (Needle.Pattern pattern : needle.patterns()) {
                byte[] p = pattern.bytes();
                for (int i = indexOf(window, length, p, 0); i >= 0 && i < acceptBelow;
                        i = indexOf(window, length, p, i + 1)) {
                    add(regions, new Region(start + i, p.length, pattern.fill()));
                    count[0]++;
                }
            }
        });
        return count[0];
    }

    /** What is done with one window of the file. */
    private interface Window {
        /**
         * @param acceptBelow a match is taken only if it begins below this:
         *                    the rest is repeated at the start of the next window
         * @param start       where the window begins in the file
         */
        void search(byte[] window, int length, int acceptBelow, long start);
    }

    /**
     * The file in windows that overlap by {@code longest - 1} bytes, so that a
     * match of up to {@code longest} bytes is whole in the window it begins in
     * and taken from that one only.
     */
    private static void windows(Path file, int longest, int windowSize, Window each)
            throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            long size = channel.size();
            byte[] window = new byte[(int) Math.min((long) windowSize + longest,
                    Math.max(size, 1))];
            long start = 0;
            while (start < size) {
                int length = read(channel, window, start,
                        (int) Math.min(window.length, size - start));
                boolean last = start + length >= size;
                int acceptBelow = last ? length : length - longest + 1;
                each.search(window, length, acceptBelow, start);
                if (last) {
                    break;
                }
                start += acceptBelow;
            }
        }
    }

    private static int read(FileChannel channel, byte[] into, long from, int length)
            throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(into, 0, length);
        int total = 0;
        while (buffer.hasRemaining()) {
            int n = channel.read(buffer, from + total);
            if (n < 0) {
                break;
            }
            total += n;
        }
        return total;
    }

    private static int indexOf(byte[] data, int length, byte[] needle, int from) {
        byte first = needle[0];
        int last = length - needle.length;
        outer:
        for (int i = from; i <= last; i++) {
            if (data[i] != first) {
                continue;
            }
            for (int j = 1; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /**
     * What discovery found, as patterns to find it again where it has no
     * shape: the whole value (as text in each encoding and as Base64) and its
     * parts - split where a credential's structure splits it, at dots and
     * line breaks, and once more without a prefix such as {@code ghp_} or
     * {@code xoxb-}. All of it is ASCII: discovery matches nothing else.
     *
     * <p>Searched for in one pass however many there are: a two-byte prefix
     * filter, then the four-byte prefix, then the whole pattern.
     */
    static final class Echoes {

        private final long[] firstTwo = new long[65536 / 64];
        private final Map<Integer, List<Needle.Pattern>> byPrefix = new HashMap<>();
        private final int longest;

        private Echoes(Set<ByteBuffer> wholes, Set<ByteBuffer> pieces) {
            int most = 0;
            for (ByteBuffer value : wholes) {
                byte[] ascii = bytes(value);
                // seclume-allow: the searcher needs the pattern it hunts for
                byte[] base64 = Base64.getEncoder().encode(ascii);
                most = Math.max(most, register(new Needle.Pattern("Base64", base64,
                        Fill.ASCII)));
                most = Math.max(most, addText(ascii));
            }
            for (ByteBuffer piece : pieces) {
                if (!wholes.contains(piece)) {
                    most = Math.max(most, addText(bytes(piece)));
                }
            }
            longest = most;
        }

        /** The echoes of {@code found} in {@code dump}, or {@code null} if there are none to look for. */
        static Echoes of(Path dump, List<Region> found) throws IOException {
            Set<ByteBuffer> wholes = new LinkedHashSet<>();
            Set<ByteBuffer> pieces = new LinkedHashSet<>();
            try (FileChannel channel = FileChannel.open(dump, StandardOpenOption.READ)) {
                for (Region region : found) {
                    byte[] raw = new byte[region.length()];
                    if (read(channel, raw, region.position(), raw.length) != raw.length) {
                        continue;
                    }
                    byte[] ascii = narrow(raw, region.fill());
                    if (ascii.length >= SHORTEST_ECHO) {
                        wholes.add(ByteBuffer.wrap(ascii));
                    }
                    pieces(ascii, pieces);
                    if (3 * (wholes.size() + pieces.size()) > MOST_ECHOES) {
                        throw new IllegalStateException("more than " + MOST_ECHOES / 3
                                + " distinct credentials and parts of them - a dump that is "
                                + "mostly credentials is not one to hand on");
                    }
                }
            }
            return wholes.isEmpty() && pieces.isEmpty() ? null : new Echoes(wholes, pieces);
        }

        /** One byte per character, from however the occurrence lay. */
        static byte[] narrow(byte[] raw, Fill fill) {
            if (fill != Fill.UTF16_BE && fill != Fill.UTF16_LE) {
                return raw;
            }
            byte[] out = new byte[raw.length / 2];
            for (int i = 0; i < out.length; i++) {
                out[i] = raw[2 * i + (fill == Fill.UTF16_BE ? 1 : 0)];
            }
            return out;
        }

        /**
         * The parts of a value as a library would hold them apart: split at
         * dots and white space, and each part once more without a prefix of
         * letters and an underscore or dash.
         */
        static void pieces(byte[] ascii, Set<ByteBuffer> into) {
            int from = 0;
            for (int i = 0; i <= ascii.length; i++) {
                if (i == ascii.length || splits(ascii[i])) {
                    byte[] part = Arrays.copyOfRange(ascii, from, i);
                    if (part.length < ascii.length) {
                        piece(part, into);
                    }
                    int body = prefix(part);
                    if (body > 0) {
                        piece(Arrays.copyOfRange(part, body, part.length), into);
                    }
                    from = i + 1;
                }
            }
            int body = prefix(ascii);
            if (body > 0) {
                piece(Arrays.copyOfRange(ascii, body, ascii.length), into);
            }
        }

        private static void piece(byte[] part, Set<ByteBuffer> into) {
            if (part.length >= SHORTEST_PIECE) {
                into.add(ByteBuffer.wrap(part));
            }
        }

        private static boolean splits(byte b) {
            return b == '.' || b == ' ' || b == '\t' || b == '\r' || b == '\n';
        }

        /** Where the body begins after up to two prefixes such as {@code sk_live_}; 0 if there is none. */
        static int prefix(byte[] part) {
            int at = 0;
            for (int round = 0; round < 2; round++) {
                int letters = 0;
                while (at + letters < part.length && letters <= 6
                        && letter(part[at + letters])) {
                    letters++;
                }
                if (letters < 2 || letters > 6 || at + letters + 1 >= part.length
                        || (part[at + letters] != '_' && part[at + letters] != '-')) {
                    break;
                }
                at += letters + 1;
            }
            return at;
        }

        private static boolean letter(byte b) {
            return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z');
        }

        private static byte[] bytes(ByteBuffer value) {
            byte[] out = new byte[value.remaining()];
            value.duplicate().get(out);
            return out;
        }

        private int addText(byte[] ascii) {
            byte[] be = new byte[2 * ascii.length];
            byte[] le = new byte[2 * ascii.length];
            for (int i = 0; i < ascii.length; i++) {
                be[2 * i + 1] = ascii[i];
                le[2 * i] = ascii[i];
            }
            register(new Needle.Pattern("ASCII", ascii, Fill.ASCII));
            register(new Needle.Pattern("UTF-16BE", be, Fill.UTF16_BE));
            return register(new Needle.Pattern("UTF-16LE", le, Fill.UTF16_LE));
        }

        private int register(Needle.Pattern pattern) {
            byte[] p = pattern.bytes();
            int two = ((p[0] & 0xff) << 8) | (p[1] & 0xff);
            firstTwo[two >>> 6] |= 1L << (two & 63);
            byPrefix.computeIfAbsent(prefix4(p, 0), k -> new ArrayList<>()).add(pattern);
            return p.length;
        }

        private static int prefix4(byte[] data, int at) {
            return ((data[at] & 0xff) << 24) | ((data[at + 1] & 0xff) << 16)
                    | ((data[at + 2] & 0xff) << 8) | (data[at + 3] & 0xff);
        }

        /** Every occurrence of every echo in {@code file}, added to {@code regions}; how many. */
        long find(Path file, List<Region> regions, int windowSize) throws IOException {
            long[] count = new long[1];
            windows(file, longest, windowSize, (window, length, acceptBelow, start) -> {
                for (int i = 0; i < acceptBelow && i + 3 < length; i++) {
                    int two = ((window[i] & 0xff) << 8) | (window[i + 1] & 0xff);
                    if ((firstTwo[two >>> 6] & (1L << (two & 63))) == 0) {
                        continue;
                    }
                    List<Needle.Pattern> candidates = byPrefix.get(prefix4(window, i));
                    if (candidates == null) {
                        continue;
                    }
                    for (Needle.Pattern pattern : candidates) {
                        byte[] p = pattern.bytes();
                        if (i + p.length <= length
                                && Arrays.equals(window, i, i + p.length, p, 0, p.length)) {
                            add(regions, new Region(start + i, p.length, pattern.fill()));
                            count[0]++;
                        }
                    }
                }
            });
            return count[0];
        }
    }

    /** The byte ranges discovery matched, to tell an echo elsewhere from the match itself. */
    static final class Covered {

        private final long[] starts;
        private final long[] ends;

        Covered(List<Region> regions) {
            long[][] sorted = regions.stream()
                    .map(r -> new long[] {r.position(), r.position() + r.length()})
                    .sorted((a, b) -> Long.compare(a[0], b[0])).toArray(long[][]::new);
            List<long[]> merged = new ArrayList<>();
            for (long[] range : sorted) {
                long[] last = merged.isEmpty() ? null : merged.get(merged.size() - 1);
                if (last != null && range[0] <= last[1]) {
                    last[1] = Math.max(last[1], range[1]);
                } else {
                    merged.add(range.clone());
                }
            }
            starts = merged.stream().mapToLong(r -> r[0]).toArray();
            ends = merged.stream().mapToLong(r -> r[1]).toArray();
        }

        boolean covers(Region region) {
            int at = Arrays.binarySearch(starts, region.position());
            int index = at >= 0 ? at : -at - 2;
            return index >= 0 && region.position() + region.length() <= ends[index];
        }
    }
}
