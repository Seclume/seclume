package space.seclume.heapdump;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import jdk.jfr.Label;
import jdk.jfr.Name;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

import space.seclume.tck.ChildJvm;

/**
 * A Flight Recorder recording of a real JVM - started with a password in its
 * environment, a token as a system property, a password as an argument and a
 * GitHub token in an event of its own - redacted like a heap dump: none of
 * them left, the settings that are not secret left as they were, and the
 * copy still a recording every tool reads.
 */
class RecordingRedactionTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String ENVIRONMENT = "env-" + alnum(24);
    private static final String PROPERTY = "prop-" + alnum(24);
    private static final String ARGUMENT = "arg-" + alnum(24);
    private static final String GITHUB = "ghp_" + alnum(36);
    private static final String VISIBLE_PROPERTY = "visible-" + alnum(12);
    private static final String VISIBLE_ENVIRONMENT = "plain-" + alnum(12);
    private static final String REFERENCE = "/run/secrets/keystore-" + alnum(8);

    @TempDir
    static Path shared;

    private static Path recording;

    private static String alnum(int length) {
        String letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < length; i++) {
            out.append(letters.charAt(RANDOM.nextInt(letters.length())));
        }
        return out.toString();
    }

    /** An event of the recorded application's own, carrying what it logged. */
    @Name("seclume.test.Note")
    @Label("Note")
    static final class Note extends jdk.jfr.Event {
        @Label("Text")
        String text;
    }

    /** The recorded process: one event, then gone - the recording is written at exit. */
    public static final class Recorded {
        public static void main(String[] arguments) {
            Note note = new Note();
            note.text = "deploying with " + System.getProperty("seclume.test.github");
            note.commit();
        }
    }

    @BeforeAll
    static void record() throws Exception {
        recording = shared.resolve("app.jfr");
        ChildJvm.Result result = ChildJvm.run(Recorded.class,
                List.of("-XX:StartFlightRecording:dumponexit=true,filename=" + recording,
                        "-Dapi.token=" + PROPERTY, "-Dapp.name=" + VISIBLE_PROPERTY,
                        "-Dseclume.test.github=" + GITHUB),
                List.of("--db.password=" + ARGUMENT),
                Map.of("DB_PASSWORD", ENVIRONMENT, "APP_MODE", VISIBLE_ENVIRONMENT,
                        "KEYSTORE_PASSWORD_FILE", REFERENCE),
                120);
        assertEquals(0, result.exitCode(), result.output());
        assertTrue(Files.size(recording) > 0, "no recording was written: " + result.output());
    }

    private static boolean contains(byte[] data, String text) {
        byte[] needle = text.getBytes(StandardCharsets.UTF_8);
        outer:
        for (int i = 0; i + needle.length <= data.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    /** Every event of {@code file} by type: the copy has to read as the original does. */
    private static Map<String, List<RecordedEvent>> events(Path file) throws IOException {
        Map<String, List<RecordedEvent>> events = new HashMap<>();
        for (RecordedEvent event : RecordingFile.readAllEvents(file)) {
            events.computeIfAbsent(event.getEventType().getName(), k -> new ArrayList<>())
                    .add(event);
        }
        return events;
    }

    private static String value(Map<String, List<RecordedEvent>> events, String type,
            String key) {
        return events.getOrDefault(type, List.of()).stream()
                .filter(e -> key.equals(e.getString("key")))
                .map(e -> e.getString("value"))
                .findFirst().orElseThrow(() -> new AssertionError(type + " " + key
                        + " is not in the recording any more"));
    }

    @Test
    void theRecordingItselfIsTheOriginalWithEverySecretInIt() throws IOException {
        byte[] raw = Files.readAllBytes(recording);
        for (String secret : List.of(ENVIRONMENT, PROPERTY, ARGUMENT, GITHUB)) {
            assertTrue(contains(raw, secret), "the recording does not hold what this test "
                    + "redacts, so the test would prove nothing");
        }
        assertTrue(Recordings.isRecording(recording));
        assertTrue(Recordings.complete(recording));
    }

    @Test
    void theSecretsARecordingNamesAreFoundByTheirNames() throws IOException {
        Map<String, String> settings = Recordings.secretSettings(recording);
        assertEquals(ENVIRONMENT, settings.get("environment variable DB_PASSWORD"),
                settings.keySet().toString());
        assertTrue(settings.containsValue(PROPERTY), settings.keySet().toString());
        assertEquals(ARGUMENT, settings.get("argument db.password"), settings.keySet().toString());
        assertFalse(settings.containsValue(VISIBLE_PROPERTY));
        assertFalse(settings.containsValue(VISIBLE_ENVIRONMENT));
        assertFalse(settings.containsValue(REFERENCE), "a path to a secret is no secret");
        assertFalse(settings.keySet().stream().anyMatch(k -> k.endsWith(" PWD")));
    }

    @Test
    void aRecordingIsRedactedAndStillReadsEventForEvent(@TempDir Path out) throws IOException {
        Path copy = out.resolve("app.redacted.jfr");

        Redactor.Report report = Redactor.redact(recording, copy, List.of(), true, Set.of());

        byte[] raw = Files.readAllBytes(copy);
        for (String secret : List.of(ENVIRONMENT, PROPERTY, ARGUMENT, GITHUB.substring(4))) {
            assertFalse(contains(raw, secret), "a secret is still in the redacted recording");
        }
        assertEquals(Files.size(recording), raw.length, "the copy is not as long as the original");
        assertTrue(contains(raw, VISIBLE_PROPERTY), "a setting that is no secret went too");
        assertTrue(contains(raw, VISIBLE_ENVIRONMENT), "a setting that is no secret went too");
        assertTrue(report.named().get("environment variable DB_PASSWORD") > 0,
                report.named().toString());
        assertFalse(report.discovered().clean(), "the GitHub token was not discovered");
        assertEquals(0, report.stringHashes());
        assertEquals(Map.of(), Recordings.secretSettings(copy),
                "the copy still names a secret of its own");

        // Read back by the JDK's own parser: the same events, the secrets masked.
        Map<String, List<RecordedEvent>> before = events(recording);
        Map<String, List<RecordedEvent>> after = events(copy);
        assertEquals(before.keySet(), after.keySet());
        for (String type : before.keySet()) {
            assertEquals(before.get(type).size(), after.get(type).size(), type);
        }
        assertEquals("*".repeat(ENVIRONMENT.length()),
                value(after, "jdk.InitialEnvironmentVariable", "DB_PASSWORD"));
        assertEquals("*".repeat(PROPERTY.length()),
                value(after, "jdk.InitialSystemProperty", "api.token"));
        assertEquals(VISIBLE_PROPERTY, value(after, "jdk.InitialSystemProperty", "app.name"));
        assertEquals(VISIBLE_ENVIRONMENT,
                value(after, "jdk.InitialEnvironmentVariable", "APP_MODE"));
        String arguments = after.get("jdk.JVMInformation").get(0).getString("javaArguments");
        assertTrue(arguments.contains("--db.password=" + "*".repeat(ARGUMENT.length())),
                "the argument was not masked in place");
        String note = after.get("seclume.test.Note").get(0).getString("text");
        assertTrue(note.startsWith("deploying with ") && !note.contains(GITHUB.substring(4)),
                "the token in the application's own event is still there");
    }

    @Test
    void aRecordingWithNothingNamedStillHasItsOwnSecretsRedacted(@TempDir Path out)
            throws IOException {
        Path copy = out.resolve("copy.jfr");
        Redactor.redact(recording, copy, List.of(), false, Set.of());
        byte[] raw = Files.readAllBytes(copy);
        assertFalse(contains(raw, ENVIRONMENT));
        assertFalse(contains(raw, ARGUMENT));
        assertTrue(contains(raw, GITHUB), "without discovery a token of no name stays - "
                + "that is what discovery is for");
    }

    @Test
    void aRecordingCutShortOrStillBeingWrittenIsNotFinished(@TempDir Path folder)
            throws IOException {
        byte[] whole = Files.readAllBytes(recording);
        Path cut = Files.write(folder.resolve("cut.jfr"), Arrays.copyOf(whole, whole.length - 1));
        assertTrue(Recordings.isRecording(cut));
        assertFalse(Recordings.complete(cut));

        byte[] writing = whole.clone();
        writing[64] = (byte) 255;                 // the chunk's state while it is written
        assertFalse(Recordings.complete(Files.write(folder.resolve("writing.jfr"), writing)));

        Path notes = Files.writeString(folder.resolve("notes.jfr"), "not a recording at all");
        assertFalse(Recordings.isRecording(notes));
        assertFalse(Recordings.complete(notes));
        assertFalse(Recordings.isRecording(Files.write(folder.resolve("empty.jfr"), new byte[0])));
    }

    @Test
    void aCopyThatCannotBeReadBackIsNotHandedOut(@TempDir Path folder) throws IOException {
        byte[] whole = Files.readAllBytes(recording);
        Path broken = Files.write(folder.resolve("broken.jfr"),
                Arrays.copyOf(whole, whole.length / 2));
        assertThrows(Redactor.Incomplete.class, () -> Recordings.readable(broken));
    }

    @Test
    void namesThatSaySecretAreToldFromNamesThatSayWhere() {
        for (String name : List.of("DB_PASSWORD", "api.token", "AWS_SECRET_ACCESS_KEY",
                "javax.net.ssl.trustStorePassword", "DB_PWD", "GITHUB_TOKEN", "apiKey",
                "spring.datasource.password", "client_secret", "MASTER_KEY", "redis.pass",
                "GOOGLE_APPLICATION_CREDENTIALS_JSON", "http.proxyPassword")) {
            assertTrue(Recordings.secretName(name), name);
        }
        for (String name : List.of("PWD", "OLDPWD", "KEYSTORE_PASSWORD_FILE", "BYPASS_PROXY",
                "user.name", "SSH_AUTH_SOCK", "java.home", "SECRET_NAME", "token.ttl",
                "PASSWORD_DIR", "compass.heading", "", "jdk.tls.keyLimits")) {
            assertFalse(Recordings.secretName(name), name);
        }
        assertFalse(Recordings.secretValue("true"));
        assertFalse(Recordings.secretValue("8080"));
        assertFalse(Recordings.secretValue("abc"));
        assertFalse(Recordings.secretValue(null));
        assertFalse(Recordings.secretValue("********"), "a masked value is no secret");
        assertTrue(Recordings.secretValue("hunter22"));
    }

    @Test
    void aRecordingInTheDumpFolderIsRedactedNextToItselfAndThenGone(@TempDir Path folder)
            throws IOException {
        Path left = Files.copy(recording, folder.resolve("hotspot-pid-1.jfr"));
        Files.setLastModifiedTime(left, FileTime.from(Instant.parse("2026-10-30T00:15:00Z")));
        Files.write(folder.resolve("still-writing.jfr"),
                Arrays.copyOf(Files.readAllBytes(recording), 200));

        List<DumpFolder.Outcome> outcomes = DumpFolder.redactAll(folder,
                DumpFolder.Settings.discovery(Set.of()));

        assertEquals(1, outcomes.size(), outcomes.toString());
        DumpFolder.Outcome outcome = outcomes.get(0);
        assertTrue(outcome.ok(), outcome.describe());
        try (Stream<Path> files = Files.list(folder)) {
            assertEquals(List.of("hotspot-pid-1-20261030T001500Z.redacted.jfr",
                    "still-writing.jfr"), files.map(f -> f.getFileName().toString())
                    .sorted().toList());
        }
        byte[] raw = Files.readAllBytes(outcome.redacted());
        assertFalse(contains(raw, ENVIRONMENT), "discovery alone, and the recording's own "
                + "secrets went all the same");
        assertFalse(contains(raw, GITHUB.substring(4)));
        assertTrue(DumpFolder.complete(outcome.redacted()));
        assertFalse(outcome.describe().contains(ENVIRONMENT), outcome.describe());
        assertEquals(List.of(), DumpFolder.redactAll(folder,
                DumpFolder.Settings.discovery(Set.of())), "a redacted copy was taken again");
    }
}
