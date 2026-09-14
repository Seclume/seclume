package space.seclume.tck;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Base64; // seclume-allow: the searcher encodes the pattern it hunts for
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Searches a heap dump for a secret - on both routes an
 * Angreifer nehmen wuerde.
 *
 * <ol>
 *   <li><b>Raw</b>, byte by byte over the whole file: this is
 *       {@code strings | grep} and finds what no longer belongs to any live
 *       object.</li>
 *   <li><b>Structured</b>, over every primitive array: this is MAT or OQL and
 *       finds what the raw scan misses because of an encoding.</li>
 * </ol>
 *
 * <p>The search covers every form a password can end up in on the heap: UTF-8
 * (how a Latin-1 {@code String} has been stored since JDK 9, and every
 * {@code byte[]} read from a file), UTF-16BE (how a {@code char[]} sits in the
 * file, since hprof is big-endian throughout), UTF-16LE (how it would arrive
 * from Windows) and Base64 (how secrets travel through configuration).
 *
 * <p>A finding <b>never</b> names the content it found, only its kind, place
 * and length. A test report gets passed around; the secret does not belong in
 * it.
 */
public final class HeapDumpScanner {

    /** A finding: where, and in which encoding. */
    public record Finding(String source, String encoding, long position, int length) {
        @Override
        public String toString() {
            return source + ": " + encoding + " match of " + length
                    + " bytes at " + position;
        }
    }

    private HeapDumpScanner() {
    }

    /** Both searches; an empty list means the secret is not in the dump. */
    public static List<Finding> scan(Path dump, String secret) throws IOException {
        List<Finding> findings = new ArrayList<>();
        findings.addAll(scanRaw(dump, secret));
        findings.addAll(scanStructured(dump, secret));
        return findings;
    }

    /** The raw scan over the whole file. */
    public static List<Finding> scanRaw(Path dump, String secret) throws IOException {
        List<Finding> findings = new ArrayList<>();
        try (FileChannel channel = FileChannel.open(dump, StandardOpenOption.READ)) {
            ByteBuffer buffer = channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size());
            for (Map.Entry<String, byte[]> needle : needles(secret).entrySet()) {
                long position = indexOf(buffer, needle.getValue(), 0);
                while (position >= 0) {
                    findings.add(new Finding("raw file", needle.getKey(), position,
                            needle.getValue().length));
                    if (findings.size() > 50) {
                        return findings;
                    }
                    position = indexOf(buffer, needle.getValue(), (int) position + 1);
                }
            }
        }
        return findings;
    }

    /** The structured scan over every {@code byte[]} and {@code char[]}. */
    public static List<Finding> scanStructured(Path dump, String secret) throws IOException {
        List<Finding> findings = new ArrayList<>();
        Map<String, byte[]> needles = needles(secret);
        byte[] utf8 = needles.get("UTF-8");
        byte[] utf16be = needles.get("UTF-16BE");
        byte[] base64 = needles.get("Base64");

        HprofParser.forEachPrimitiveArray(dump, (objectId, type, data) -> {
            if (findings.size() > 50) {
                return;
            }
            switch (type) {
                case BYTE -> {
                    check(findings, data, utf8, "byte[] " + objectId, "UTF-8", objectId);
                    check(findings, data, base64, "byte[] " + objectId, "Base64", objectId);
                }
                case CHAR -> check(findings, data, utf16be, "char[] " + objectId,
                        "UTF-16BE", objectId);
                default -> {
                    // The other types cannot carry a password.
                }
            }
        });
        return findings;
    }

    private static void check(List<Finding> findings, ByteBuffer data, byte[] needle,
                              String source, String encoding, long objectId) {
        long position = indexOf(data, needle, 0);
        if (position >= 0) {
            findings.add(new Finding(source, encoding, position, needle.length));
        }
    }

    /**
     * Every encoding the same secret can appear in.
     *
     * <p>The one place in this repository where a secret is deliberately put
     * into heap objects: this is the <b>searcher</b>, and it has to build the
     * very byte patterns it looks for. It runs in the test JVM and never in
     * the one being examined - the probe under the microscope is a child
     * process, and its heap is what the dump is of.
     */
    private static Map<String, byte[]> needles(String secret) {
        Map<String, byte[]> needles = new LinkedHashMap<>();
        // seclume-allow: the searcher builds the pattern it hunts for; see the comment above
        needles.put("UTF-8", secret.getBytes(StandardCharsets.UTF_8));
        // seclume-allow: the searcher builds the pattern it hunts for; see the comment above
        needles.put("UTF-16BE", secret.getBytes(StandardCharsets.UTF_16BE));
        // seclume-allow: the searcher builds the pattern it hunts for; see the comment above
        needles.put("UTF-16LE", secret.getBytes(StandardCharsets.UTF_16LE));
        // seclume-allow: the searcher builds the pattern it hunts for; see the comment above
        needles.put("Base64", Base64.getEncoder()
                .encodeToString(secret.getBytes(StandardCharsets.UTF_8)) // seclume-allow: the searcher builds the pattern it hunts for
                .getBytes(StandardCharsets.US_ASCII)); // seclume-allow: the searcher builds the pattern it hunts for
        return needles;
    }

    /** Naive search jumping on the first byte - fast enough for a few needles. */
    private static long indexOf(ByteBuffer haystack, byte[] needle, int from) {
        if (needle.length == 0) {
            return -1;
        }
        int limit = haystack.limit() - needle.length;
        byte first = needle[0];
        outer:
        for (int i = Math.max(from, 0); i <= limit; i++) {
            if (haystack.get(i) != first) {
                continue;
            }
            for (int j = 1; j < needle.length; j++) {
                if (haystack.get(i + j) != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
