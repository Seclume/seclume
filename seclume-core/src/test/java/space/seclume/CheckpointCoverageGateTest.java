package space.seclume;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

/**
 * A secret a class keeps in a field outlives the call that made it, and a
 * checkpoint writes it into the image unless the class wipes it first - by
 * registering with {@code Checkpoint.register}. #58 was such a class that did
 * not. This gate holds every class with a {@code SecretScope} field, or a
 * collection of them, to registering, or to a place on the list below with
 * the reason it needs none.
 */
class CheckpointCoverageGateTest {

    /** A field - a modifier first, so no local variable - whose type names SecretScope. */
    private static final Pattern FIELD = Pattern.compile(
            "(?m)^\\s+((private|protected|public|static|final|volatile|transient)\\s+)*"
                    + "(private|protected|public|static)\\s+((final|volatile|static|transient)\\s+)*"
                    + "[A-Za-z.<>, ]*\\bSecretScope\\b[A-Za-z.<>, ]*\\s+[a-zA-Z_]\\w*\\s*[=;]");

    /** Classes whose SecretScope fields need no registration, and why. */
    static final Map<String, String> NEEDS_NONE = Map.of(
            "KeySchedule.java", "per TLS connection; its keys go with the connection, and an "
                    + "open connection refuses the checkpoint (LiveTls)",
            "RecordProtection.java", "per direction of a TLS connection; closed with it, and an "
                    + "open connection refuses the checkpoint (LiveTls)",
            "DiffieHellman.java", "per handshake; closed when the handshake ends",
            "HttpFraming.java", "per request being rewritten; freed when the request is written",
            "MailWire.java", "per mail connection; closed with it",
            "EncryptedColumn.java", "its keys are derived from FieldKeys, which registers and "
                    + "wipes them for every column",
            "BlindIndex.java", "its keys are derived from FieldKeys, which registers and wipes them",
            "SaslPlaceholders.java", "per login; a placeholder's secret is taken by the login "
                    + "that registered it, an open one is counted by SecretScope.open()",
            "SecretScope.java", "the debug map of where scopes were opened - keys, no contents");

    @Test
    void everyClassKeepingASecretRegistersOrSaysWhyNot() throws IOException {
        List<String> findings = new ArrayList<>();
        for (Path sources : ForbiddenApiTest.productionSources()) {
            try (Stream<Path> files = Files.walk(sources)) {
                for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                    String finding = finding(file.getFileName().toString(),
                            Files.readString(file, StandardCharsets.UTF_8));
                    if (finding != null) {
                        findings.add(file + ": " + finding);
                    }
                }
            }
        }
        assertTrue(findings.isEmpty(), "a secret kept in a field, and no Checkpoint.register - "
                + "register a wipe, or add the class with its reason to NEEDS_NONE:\n"
                + String.join("\n", findings));
    }

    @Test
    void theListNamesOnlyClassesThatStillNeedIt() throws IOException {
        List<String> stale = new ArrayList<>(NEEDS_NONE.keySet());
        for (Path sources : ForbiddenApiTest.productionSources()) {
            try (Stream<Path> files = Files.walk(sources)) {
                for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                    if (stale.contains(file.getFileName().toString())
                            && FIELD.matcher(Files.readString(file, StandardCharsets.UTF_8)).find()) {
                        stale.remove(file.getFileName().toString());
                    }
                }
            }
        }
        assertTrue(stale.isEmpty(), "on the list, and no SecretScope field any more: " + stale);
    }

    /** What is wrong with {@code source}, or null. */
    static String finding(String file, String source) {
        var field = FIELD.matcher(source);
        if (!field.find() || source.contains("Checkpoint.register") || NEEDS_NONE.containsKey(file)) {
            return null;
        }
        return field.group().strip();
    }

    @Test
    void theScanFindsWhatItLooksFor() {
        String kept = "class A {\n    private SecretScope token;\n}\n";
        assertEquals("private SecretScope token;", finding("A.java", kept));
        assertEquals("private final Map<String, SecretScope> cache =",
                finding("B.java", "class B {\n    private final Map<String, SecretScope> cache"
                        + " = new HashMap<>();\n}\n"));
        assertEquals(null, finding("C.java", kept + "Checkpoint.register(this, C::wipe);"));
        assertEquals(null, finding("D.java",
                "void m() {\n        SecretScope local = SecretScope.allocate(8);\n}\n"),
                "a local variable is the call's, not the object's");
        assertEquals(null, finding("KeySchedule.java", kept), "on the list");
    }
}
