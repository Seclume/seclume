package space.seclume;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * Every native function this library calls is registered for a native image.
 *
 * <p>A GraalVM image has to know each downcall's signature at build time. One
 * that is missing builds cleanly and fails when it is first called - with
 * {@code MissingForeignRegistrationError}, at runtime, on whatever path
 * reaches it. The metadata shipped in {@code seclume-core} named only
 * {@code mlock}, written down from the one path the first image exercised; the
 * TLS stack's P-256 through OpenSSL was not on it, and the first connection
 * with {@code tlsStack=seclume} in an image failed on 24.09.2026.
 *
 * <p>So the list is checked against the source rather than against what some
 * run happened to reach. Each {@code FunctionDescriptor} written with literal
 * layouts, and each {@code bind("name", ...)} of a class that binds through a
 * helper, is read as a signature and has to be in the metadata. The Windows
 * ones are there too: a signature costs nothing where it is not called, and an
 * image built for Windows needs them.
 */
class NativeDowncallMetadataTest {

    private static final String METADATA = "seclume-core/src/main/resources/META-INF/"
            + "native-image/space.seclume/seclume-core/reachability-metadata.json";

    private static final Map<String, String> LAYOUTS = Map.of(
            "ADDRESS", "void*",
            "JAVA_INT", "jint",
            "JAVA_LONG", "jlong",
            "JAVA_SHORT", "jshort",
            "JAVA_BYTE", "jbyte",
            "JAVA_CHAR", "jchar",
            "JAVA_DOUBLE", "jdouble",
            "JAVA_FLOAT", "jfloat");

    private static final Pattern DESCRIPTOR = Pattern.compile(
            "FunctionDescriptor\\.(of|ofVoid)\\(([^()]*)\\)");
    private static final Pattern BIND = Pattern.compile("\\bbind\\(\"\\w+\",([^()]*)\\)");
    private static final Pattern REGISTERED = Pattern.compile(
            "\"returnType\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"parameterTypes\"\\s*:\\s*\\[([^\\]]*)\\]");

    @Test
    void everyDowncallInTheSourceIsRegistered() throws IOException {
        Path root = root();
        Set<String> wanted = new TreeSet<>();
        for (Path source : mainSources(root)) {
            String text = Files.readString(source).replaceAll("\\s+", " ");
            if (!text.contains("downcallHandle")) {
                continue;
            }
            Matcher descriptor = DESCRIPTOR.matcher(text);
            while (descriptor.find()) {
                List<String> types = types(descriptor.group(2));
                if (types == null) {
                    continue;                    // built from variables - a bind helper
                }
                wanted.add(descriptor.group(1).equals("ofVoid")
                        ? signature("void", types) : signature(types.get(0), types.subList(1, types.size())));
            }
            boolean resultFirst = text.contains("bind(String name, ValueLayout result");
            Matcher bind = BIND.matcher(text);
            while (bind.find()) {
                String arguments = bind.group(1).trim();
                if (resultFirst) {
                    boolean isVoid = arguments.startsWith("null");
                    List<String> types = types(isVoid ? arguments.substring(4) : arguments);
                    assertTrue(types != null, "cannot read " + bind.group() + " in " + source);
                    wanted.add(isVoid ? signature("void", types)
                            : signature(types.get(0), types.subList(1, types.size())));
                } else {
                    List<String> types = types(arguments);
                    assertTrue(types != null, "cannot read " + bind.group() + " in " + source);
                    wanted.add(signature("jint", types));
                }
            }
        }
        assertFalse(wanted.isEmpty(), "no downcalls found - the scan is broken, not the source");

        Set<String> registered = new TreeSet<>();
        Matcher entry = REGISTERED.matcher(Files.readString(root.resolve(METADATA)));
        while (entry.find()) {
            List<String> parameters = new ArrayList<>();
            for (String parameter : entry.group(2).split(",")) {
                String type = parameter.trim().replace("\"", "");
                if (!type.isEmpty()) {
                    parameters.add(type);
                }
            }
            registered.add(entry.group(1) + " (" + String.join(", ", parameters) + ")");
        }

        Set<String> missing = new TreeSet<>(wanted);
        missing.removeAll(registered);
        assertTrue(missing.isEmpty(), "downcalls without a native-image registration - an "
                + "image builds and then fails where they are called:\n  "
                + String.join("\n  ", missing));
        Set<String> stale = new TreeSet<>(registered);
        stale.removeAll(wanted);
        assertTrue(stale.isEmpty(), "registrations no source asks for any more:\n  "
                + String.join("\n  ", stale));
    }

    /** The layouts of an argument list, or {@code null} when one is not a constant. */
    private static List<String> types(String arguments) {
        List<String> types = new ArrayList<>();
        for (String argument : arguments.split(",")) {
            String name = argument.trim();
            if (name.isEmpty()) {
                continue;
            }
            name = name.substring(name.lastIndexOf('.') + 1);
            String type = LAYOUTS.get(name);
            if (type == null) {
                return null;
            }
            types.add(type);
        }
        return types;
    }

    private static String signature(String result, List<String> parameters) {
        return result + " (" + String.join(", ", parameters) + ")";
    }

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
