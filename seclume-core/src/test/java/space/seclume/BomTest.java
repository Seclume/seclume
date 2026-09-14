package space.seclume;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * The BOM has to list every module somebody can depend on.
 *
 * <p>A bill of materials exists for one sentence in a foreign project: write one
 * line, and all seclume versions fit together. A module missing from it breaks
 * exactly that promise, and it breaks it quietly - the application writes a
 * version by hand, everything works, and the mismatch shows up at the next
 * update. Nobody notices while writing the module, because the build here does
 * not use the BOM at all.
 *
 * <p>So this test does what no reader does: it compares the BOM against the
 * modules of the build. New module, no entry, red.
 *
 * <p>What counts as depend-able: everything that is installed. Modules that set
 * {@code maven.install.skip} - the benchmarks and the Spring integration test -
 * exist to measure and to prove, never to be pulled in, and have no business in
 * a BOM.
 */
class BomTest {

    private static final Pattern ARTIFACT = Pattern.compile("<artifactId>([^<]+)</artifactId>");

    @Test
    void theBomListsEveryModuleSomebodyCanDependOn() throws IOException {
        Path root = root();
        Set<String> published = publishedModules(root);
        assertTrue(published.size() > 5,
                "expected the modules of the build, found " + published);

        Set<String> listed = managedArtifacts(root.resolve("seclume-bom").resolve("pom.xml"));

        List<String> missing = new ArrayList<>(published);
        missing.removeAll(listed);
        assertEquals(List.of(), missing,
                "these modules are installed but not in the BOM - whoever depends on "
                + "them writes the version by hand and finds out at the next update");

        List<String> unknown = new ArrayList<>(listed);
        unknown.removeAll(published);
        assertEquals(List.of(), unknown,
                "the BOM manages modules that nobody gets: they are not installed, so "
                + "the entry points at something that is not there");
    }

    /** Every module directory whose pom is installed, by its artifact id. */
    private static Set<String> publishedModules(Path root) throws IOException {
        Set<String> published = new LinkedHashSet<>();
        try (Stream<Path> modules = Files.list(root)) {
            for (Path module : modules.sorted().toList()) {
                Path pom = module.resolve("pom.xml");
                if (!Files.isRegularFile(pom)) {
                    continue;
                }
                String text = Files.readString(pom, StandardCharsets.UTF_8);
                if (text.contains("<maven.install.skip>true</maven.install.skip>")) {
                    continue;
                }
                String name = module.getFileName().toString();
                // The BOM manages the others, not itself.
                if (!name.equals("seclume-bom")) {
                    published.add(name);
                }
            }
        }
        return published;
    }

    /** The artifact ids inside {@code dependencyManagement}, in order. */
    private static Set<String> managedArtifacts(Path bom) throws IOException {
        String text = Files.readString(bom, StandardCharsets.UTF_8);
        int start = text.indexOf("<dependencyManagement>");
        int end = text.indexOf("</dependencyManagement>");
        assertTrue(start >= 0 && end > start, bom + " manages no dependencies at all");
        Set<String> managed = new LinkedHashSet<>();
        Matcher artifacts = ARTIFACT.matcher(text.substring(start, end));
        while (artifacts.find()) {
            managed.add(artifacts.group(1));
        }
        return managed;
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
