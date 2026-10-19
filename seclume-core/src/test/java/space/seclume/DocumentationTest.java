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

import org.junit.jupiter.api.Test;

/**
 * What the documentation says against what the code is - where both can be
 * read by a machine, and only there.
 *
 * <p>A reader, or a model evaluating the project, checks the README against
 * the repository; a module the README does not name, a provider count that
 * is two behind, a quick start with last month's version read as a project
 * that does not know itself. Each check takes its facts from one exact place
 * (the BOM, the provider factory's own list, the CHANGELOG's headings) so that
 * it fails for a real gap and not for a turn of phrase.
 */
class DocumentationTest {

    private static final Pattern ARTIFACT = Pattern.compile("<artifactId>([^<]+)</artifactId>");

    private static Path root() {
        Path root = Path.of("").toAbsolutePath();
        while (root != null && !Files.isDirectory(root.resolve("seclume-bom"))) {
            root = root.getParent();
        }
        assertTrue(root != null, "not inside the seclume repository");
        return root;
    }

    private static String read(Path file) throws IOException {
        return Files.readString(file, StandardCharsets.UTF_8);
    }

    /** Every module somebody can depend on - the BOM, which BomTest holds to the build. */
    @Test
    void theReadmeNamesEveryPublishedModule() throws IOException {
        Path root = root();
        String bom = read(root.resolve("seclume-bom").resolve("pom.xml"));
        String managed = bom.substring(bom.indexOf("<dependencyManagement>"),
                bom.indexOf("</dependencyManagement>"));
        // Infrastructure, not something a reader chooses: named in TESTING.md.
        Set<String> notForTheReadme = Set.of("seclume-tck");
        String readme = read(root.resolve("README.md"));
        List<String> missing = new ArrayList<>();
        Matcher artifacts = ARTIFACT.matcher(managed);
        while (artifacts.find()) {
            String module = artifacts.group(1);
            if (!notForTheReadme.contains(module) && !module.startsWith("seclume-quarkus-")
                    && !readme.contains(module)) {
                missing.add(module);
            }
        }
        assertEquals(List.of(), missing, "published modules the README does not name");
    }

    /** The provider names the factory knows - from its own error message, which lists them. */
    private static Set<String> providerKinds(Path root) throws IOException {
        String factory = read(root.resolve(
                "seclume-core/src/main/java/space/seclume/secret/SecretProviders.java"));
        int from = factory.indexOf("\"unknown secret provider '\"");
        assertTrue(from > 0, "SecretProviders no longer lists its providers in its refusal");
        String list = factory.substring(factory.indexOf("known are", from),
                factory.indexOf(");", from)).replaceAll("\"\\s*\\+\\s*\"", "")
                .replace("known are", "").replace("\"", "");
        Set<String> kinds = new LinkedHashSet<>();
        for (String kind : list.split(",")) {
            if (!kind.isBlank()) {
                kinds.add(kind.trim());
            }
        }
        return kinds;
    }

    @Test
    void theProviderCountAndNamesAreTheFactorys() throws IOException {
        Path root = root();
        Set<String> kinds = providerKinds(root);
        assertTrue(kinds.contains("file") && kinds.contains("vault"), "parsed: " + kinds);
        kinds.remove("none");                        // the readme counts it apart
        Matcher count = Pattern.compile("\\| (\\d+) providers plus `none`")
                .matcher(read(root.resolve("README.md")));
        assertTrue(count.find(), "the README's feature table no longer says how many providers");
        assertEquals(kinds.size(), Integer.parseInt(count.group(1)),
                "the README counts the providers wrong: " + kinds);

        String providers = read(root.resolve("PROVIDERS.md"));
        List<String> undocumented = new ArrayList<>();
        for (String kind : kinds) {
            if (!providers.contains("`" + kind + "`")) {
                undocumented.add(kind);
            }
        }
        assertEquals(List.of(), undocumented, "providers PROVIDERS.md does not describe");
    }

    /** The quick start's version is the newest release, as the CHANGELOG records it. */
    @Test
    void theQuickStartUsesTheLatestRelease() throws IOException {
        Path root = root();
        Matcher release = Pattern.compile("(?m)^## \\[(\\d+\\.\\d+\\.\\d+)\\]")
                .matcher(read(root.resolve("CHANGELOG.md")));
        assertTrue(release.find(), "the CHANGELOG records no release");
        String latest = release.group(1);
        Matcher versions = Pattern.compile("<version>(\\d+\\.\\d+\\.\\d+)</version>")
                .matcher(read(root.resolve("README.md")));
        List<String> stale = new ArrayList<>();
        while (versions.find()) {
            if (!versions.group(1).equals(latest)) {
                stale.add(versions.group(1));
            }
        }
        assertEquals(List.of(), stale, "the README's dependencies are not the latest release "
                + latest);
    }
}
