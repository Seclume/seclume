package space.seclume;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * Pins the core property down in the source.
 *
 * <p>The library stands or falls on no secret passing through a heap object.
 * That is a property one loses while writing a single line - {@code new
 * String(bytes)} is quickly typed and shows up in no functional test, because
 * everything keeps working. This test therefore checks the production source
 * against a list of forbidden constructs.
 *
 * <p>Where one of them demonstrably touches <b>no</b> secret - a configuration
 * name, an application salt - the line, or the one directly above it, carries
 * {@code // seclume-allow: <reason>}. That makes every exception visible and
 * justified instead of watering down the rule.
 *
 * <p>Comments and string literals are stripped before the check: the JavaDoc
 * deliberately spells out what is forbidden.
 */
class ForbiddenApiTest {

    private static final Map<String, String> FORBIDDEN = Map.ofEntries(
            Map.entry("new String(", "a String keeps the secret on the heap forever"),
            Map.entry(".getBytes(", "String.getBytes copies the secret into a heap array"),
            Map.entry("System.getenv", "the environment map is filled before our code runs"),
            Map.entry("Files.readAllBytes", "reads the secret into a heap array"),
            Map.entry("Files.readString", "reads the secret into a String"),
            Map.entry("Files.lines", "reads the file into Strings"),
            Map.entry("BufferedReader", "readers produce Strings"),
            Map.entry("InputStreamReader", "readers produce Strings"),
            Map.entry("readAllBytes()", "reads into a heap array"),
            Map.entry("javax.crypto", "JCA takes key material as byte[]"),
            Map.entry("java.security.MessageDigest", "JCA takes input as byte[]"),
            Map.entry("BigInteger", "immutable and heap resident, cannot be zeroed"),
            Map.entry("HexFormat", "decodes from and to Strings"),
            // Aimed at the call, not at the word: our own class is called
            // Base64Off, and that name is not going to change.
            Map.entry("java.util.Base64", "the JDK decoder works on Strings and heap arrays"),
            Map.entry("Base64.get", "the JDK decoder works on Strings and heap arrays"),
            Map.entry("ByteBuffer.allocate(", "a heap buffer defeats the direct read path"),
            Map.entry("char[]", "a char array is heap and shows up in a heap dump"));

    /**
     * Every module, not only this one.
     *
     * <p>The rule was checked in the core alone for a while, which is the one
     * place where it matters least: the core knows about secrets and is
     * written accordingly. The passwords actually travel through the
     * <b>drivers</b> - that is where a {@code new String(...)} would put one
     * on the heap, and that is what nobody was looking at. Proven by putting
     * one there on purpose and watching this test go red.
     */
    @Test
    void productionSourcesAvoidHeapPathsForSecrets() throws IOException {
        List<Path> modules = productionSources();
        assertTrue(modules.size() > 1,
                "expected the sources of every module, found " + modules);

        List<String> findings = new ArrayList<>();
        for (Path sources : modules) {
            try (Stream<Path> files = Files.walk(sources)) {
                for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                    check(file, findings);
                }
            }
        }
        assertTrue(findings.isEmpty(),
                "forbidden constructs in production code:\n" + String.join("\n", findings));
    }

    /**
     * The {@code src/main/java} of every module of the build.
     *
     * <p>Found by walking up to the directory that holds the modules - the
     * test runs with the module directory as its working directory, and a
     * hard-coded relative path would break the moment a module moves.
     */
    static List<Path> productionSources() throws IOException {
        Path root = Path.of("").toAbsolutePath();
        while (root != null && !Files.isDirectory(root.resolve("seclume-core"))) {
            root = root.getParent();
        }
        Assumptions.assumeTrue(root != null, "cannot find the root of the build");
        List<Path> sources = new ArrayList<>();
        try (Stream<Path> modules = Files.list(root)) {
            for (Path module : modules.sorted().toList()) {
                Path java = module.resolve("src").resolve("main").resolve("java");
                if (Files.isDirectory(java)) {
                    sources.add(java);
                }
            }
        }
        return sources;
    }

    /**
     * Shapes a substring cannot catch: a charset's {@code decode} - a String
     * out of whatever bytes it is given - a {@code Scanner}, and a heap copy
     * of an array handed to a buffer.
     */
    private static final Map<java.util.regex.Pattern, String> FORBIDDEN_SHAPES = Map.of(
            java.util.regex.Pattern.compile(
                    "(?:Charset|charset|UTF_8|US_ASCII|ISO_8859_1|UTF_16(?:BE|LE)?)\\.decode\\("),
            "a charset's decode makes a String of the bytes",
            java.util.regex.Pattern.compile("new (?:java\\.util\\.)?Scanner\\("),
            "a Scanner reads into Strings",
            java.util.regex.Pattern.compile("\\.wrap\\([^;]*?\\.clone\\(\\)\\)"),
            "a cloned array is one more heap copy, out of reach of the wipe");

    static void check(Path file, List<String> findings) throws IOException {
        check(file.toString(), Files.readString(file, StandardCharsets.UTF_8), findings);
    }

    /**
     * The rules against {@code source} as code: comments and literals out,
     * white space folded, {@code java.lang.} dropped - see {@link SourceScan}.
     * Read line by line, {@code new  String(}, {@code new java.lang.String(},
     * a line break before the parenthesis and an allow marker in a literal
     * all went by.
     */
    static void check(String name, String source, List<String> findings) {
        SourceScan scan = SourceScan.of(source);
        java.util.Set<Integer> reported = new java.util.TreeSet<>();
        for (Map.Entry<String, String> rule : FORBIDDEN.entrySet()) {
            for (int at = scan.code.indexOf(rule.getKey()); at >= 0;
                    at = scan.code.indexOf(rule.getKey(), at + 1)) {
                report(scan, name, at, rule.getKey(), rule.getValue(), findings, reported);
            }
        }
        for (Map.Entry<java.util.regex.Pattern, String> rule : FORBIDDEN_SHAPES.entrySet()) {
            java.util.regex.Matcher m = rule.getKey().matcher(scan.code);
            while (m.find()) {
                report(scan, name, m.start(), m.group(), rule.getValue(), findings, reported);
            }
        }
    }

    private static void report(SourceScan scan, String name, int at, String what, String why,
            List<String> findings, java.util.Set<Integer> reported) {
        int line = scan.line(at);
        if (scan.allowed(line)) {
            return;
        }
        findings.add(name + ":" + line + " uses " + what + " - " + why);
        reported.add(line);
    }
}
