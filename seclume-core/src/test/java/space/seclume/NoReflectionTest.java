package space.seclume;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * The native-image premise, checked - and it did not hold.
 *
 * <p>The plan says of GraalVM: <i>"No JNI, no reflection, pure FFM - it may
 * well be that seclume runs more cleanly there than the vendor drivers do. Try
 * it, do not assume it."</i> Whether an image builds can only be answered by
 * building one, which needs a toolchain this machine does not have. The
 * premise, though, is checkable here - and the first run of this test found
 * <b>two dynamic proxies</b>. So the claim was not true when it was written
 * down, and a native-image attempt would have run into them on its first
 * build.
 *
 * <p>That is the value of this test and the reason it exists as an inventory
 * rather than a prohibition. What it forbids outright is everything that is
 * not there; what is there is named, one entry each, with what it would cost
 * an image. A third proxy turns this red, which is the part that matters:
 * reflection does not arrive in a rewrite, it arrives in one convenient line
 * somebody adds two years from now.
 *
 * <p>Test sources are not looked at. A test may do as it likes; it is not
 * shipped, and no image is built from it.
 */
class NoReflectionTest {

    /**
     * The two places that would need an entry in a native image's
     * configuration, and what they are.
     *
     * <p>Both are proxies over a JDBC interface, both for the same reason:
     * the interface has around a hundred methods, every one of them has to
     * reach the wrapped object, and a hand-written delegate that forgets one
     * sends a call to a statement the caller believes is closed. GraalVM
     * supports dynamic proxies but has to be told which interfaces in
     * advance - so this is real work for an image and not a blocker.
     */
    private static final Set<String> PROXIES = Set.of(
            "seclume-core/src/main/java/space/seclume/internal/jdbc/"
                    + "DriverXaConnection.java",
            "seclume-pool/src/main/java/space/seclume/pool/"
                    + "CachedPreparedStatement.java");

    /**
     * Uses of {@code java.lang.reflect} that cost a native image nothing.
     *
     * <p>{@code PgArray} calls {@code java.lang.reflect.Array.newInstance} to
     * build an array of a component type it has just decided on. That is array
     * creation, not member lookup: nothing is named by string and nothing is
     * opened. {@code SeclumeDataSources} calls {@code Class.forName} with a
     * <b>constant</b> class name and {@code initialize = false}, purely so a
     * missing module produces "add this dependency" instead of a
     * {@code NoClassDefFoundError}; an image builder folds a constant name at
     * build time.
     */
    private static final Set<String> HARMLESS = Set.of(
            "seclume-postgresql/src/main/java/space/seclume/postgresql/jdbc/PgArray.java",
            "seclume-spring-boot-starter/src/main/java/space/seclume/spring/"
                    + "SeclumeDataSources.java");

    /** What a native image cannot see without being told, by name. */
    private record Refused(Pattern pattern, String why) {

        static Refused of(String regex, String why) {
            return new Refused(Pattern.compile(regex), why);
        }
    }

    private static final List<Refused> REFUSED = List.of(
            Refused.of("\\bsetAccessible\\s*\\(",
                    "opening a member reflectively needs a configuration entry, and is the "
                    + "one thing this project has no reason to do"),
            Refused.of("\\bgetDeclared(Method|Field|Constructor)s?\\s*\\(",
                    "reflective member lookup"),
            Refused.of("\\bget(Method|Field)\\s*\\(\\s*\"",
                    "reflective member lookup by name"),
            Refused.of("\\bSystem\\s*\\.\\s*(loadLibrary|load)\\s*\\(",
                    "a native library loaded at runtime - the FFM API is the way here"),
            Refused.of("(?m)^\\s*(public|protected|private|static|final|\\s)*native\\s+\\w",
                    "a native method means JNI, which is what FFM replaced"),
            Refused.of("\\bimport\\s+java\\.lang\\.reflect\\.",
                    "the reflection API, in a file that is not in the inventory above"));

    @Test
    void nothingOutsideTheInventoryNeedsReflection() throws IOException {
        Path root = root();
        List<Path> sources = mainSources(root);
        assertTrue(sources.size() > 200,
                "expected the main sources of every module, found " + sources.size());

        List<String> found = new ArrayList<>();
        for (Path source : sources) {
            String name = slash(root.relativize(source));
            if (PROXIES.contains(name) || HARMLESS.contains(name)) {
                continue;
            }
            String text = Files.readString(source, StandardCharsets.UTF_8);
            for (Refused refused : REFUSED) {
                if (refused.pattern().matcher(text).find()) {
                    found.add(name + ": " + refused.why());
                }
            }
        }

        assertEquals(List.of(), found,
                "reflection outside the inventory - each line is something a native image "
                + "would have to be told about by hand, and a claim in the plan that would "
                + "stop being true:\n  " + String.join("\n  ", found));
    }

    /**
     * And the inventory is the whole of it - no more, and no fewer.
     *
     * <p>The "no fewer" half is not pedantry. An entry that names a file which
     * has since been cleaned up is an entry nobody removes, and an inventory
     * that lists things that are not there stops being read. If one of these
     * proxies is ever written out by hand, this test says so.
     */
    @Test
    void theInventoryMatchesWhatIsActuallyThere() throws IOException {
        Path root = root();
        Pattern proxy = Pattern.compile("\\bProxy\\s*\\.\\s*newProxyInstance\\b");

        Set<String> actual = new TreeSet<>();
        for (Path source : mainSources(root)) {
            if (proxy.matcher(Files.readString(source, StandardCharsets.UTF_8)).find()) {
                actual.add(slash(root.relativize(source)));
            }
        }
        assertEquals(new TreeSet<>(PROXIES), actual,
                "the list of dynamic proxies has changed - a new one is work for a native "
                + "image, and one that has gone should leave the list with it");
    }

    /**
     * What it uses instead, so the premise is not merely an absence.
     *
     * <p>A test that only forbids passes on an empty project. This one says
     * what the project does: it finds its plug-ins through
     * {@code ServiceLoader} and reaches native memory through the FFM API,
     * both of which a native image supports without a configuration file.
     */
    @Test
    void whatItUsesInsteadIsThereToBeSeen() throws IOException {
        List<Path> sources = mainSources(root());
        assertTrue(anyMatch(sources, Pattern.compile("\\bServiceLoader\\b")),
                "no ServiceLoader anywhere - then the allowance for it describes a project "
                + "that does not exist");
        assertTrue(anyMatch(sources,
                        Pattern.compile("\\bjava\\.lang\\.foreign\\b|\\bMemorySegment\\b")),
                "no FFM anywhere - then this test is guarding the wrong premise");
    }

    private static boolean anyMatch(List<Path> sources, Pattern pattern) throws IOException {
        for (Path source : sources) {
            if (pattern.matcher(Files.readString(source, StandardCharsets.UTF_8)).find()) {
                return true;
            }
        }
        return false;
    }

    /** One spelling for a path, so the inventory reads the same on every machine. */
    private static String slash(Path path) {
        return path.toString().replace('\\', '/');
    }

    /** Every {@code src/main/java} of every module the build publishes. */
    private static List<Path> mainSources(Path root) throws IOException {
        List<Path> sources = new ArrayList<>();
        try (Stream<Path> modules = Files.list(root)) {
            for (Path module : modules.filter(Files::isDirectory).toList()) {
                Path main = module.resolve("src").resolve("main").resolve("java");
                if (!Files.isDirectory(main)) {
                    continue;
                }
                try (Stream<Path> files = Files.walk(main)) {
                    files.filter(path -> path.toString().endsWith(".java")).forEach(sources::add);
                }
            }
        }
        return sources;
    }

    private static Path root() {
        Path root = Path.of("").toAbsolutePath();
        while (root != null && !Files.isDirectory(root.resolve("seclume-bom"))) {
            root = root.getParent();
        }
        Assumptions.assumeTrue(root != null, "cannot find the root of the build");
        return root;
    }
}
