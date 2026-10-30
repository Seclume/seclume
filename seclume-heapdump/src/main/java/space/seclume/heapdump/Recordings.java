package space.seclume.heapdump;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

/**
 * Flight Recorder files, which the redaction takes as it takes a heap dump.
 *
 * <p>A {@code .jfr} holds the process's environment
 * ({@code jdk.InitialEnvironmentVariable}), its system properties
 * ({@code jdk.InitialSystemProperty}) and its command line
 * ({@code jdk.JVMInformation}) - {@code DB_PASSWORD} and
 * {@code -Dspring.datasource.password=} among them - and every string an event
 * recorded, an exception's message included. A recording goes to a vendor's
 * support as readily as a heap dump does, and is opened in more tools.
 *
 * <p>A value under a name that says secret - password, secret, token, an API,
 * access or private key, credential - becomes a named secret of the
 * redaction ({@link #secretSettings}); discovery finds the shapes it knows
 * anywhere in the file. Every occurrence is overwritten in place with as many
 * bytes, so the chunks' sizes and offsets stay as they were, and the copy is
 * read back from the first event to the last before it is let out.
 */
public final class Recordings {

    /** {@code FLR\0}, which every chunk begins with. */
    private static final byte[] MAGIC = {'F', 'L', 'R', 0};
    /** A chunk header: magic, version, size, offsets, times, state, flags. */
    private static final int HEADER = 68;
    private static final int CHUNK_SIZE = 8;
    /** Zero once the chunk is written; something else while it is. */
    private static final int FILE_STATE = 64;

    /** The parts of a name that say it holds a secret. */
    private static final Pattern SECRET = Pattern.compile(
            "password|passwd|passphrase|secret|token|credential|authorization|bearer"
                    + "|api[_.-]?key|access[_.-]?key|private[_.-]?key|client[_.-]?key"
                    + "|signing[_.-]?key|encryption[_.-]?key|master[_.-]?key");
    /** {@code pass} and {@code pwd} only as words of their own: not {@code bypass}. */
    private static final Pattern SHORT = Pattern.compile("(^|[^a-z])(pass|pwd)($|[^a-z])");
    /** Where a secret is, or what kind it is - not the secret. */
    private static final Set<String> REFERENCE = Set.of("file", "files", "path", "dir",
            "directory", "url", "uri", "location", "type", "mode", "method", "enabled",
            "disabled", "required", "sock", "socket", "length", "size", "algorithm",
            "algorithms", "provider", "ttl", "expiry", "name", "header");
    /** The shell's working directories, which say {@code pwd} and are paths. */
    private static final Set<String> NOT_SECRETS = Set.of("pwd", "oldpwd");
    /** Values that are a setting's state, not a secret - and are found everywhere. */
    private static final Set<String> NOT_VALUES = Set.of("true", "false", "yes", "none",
            "null", "enabled", "disabled", "changeme");
    private static final Pattern NUMBER = Pattern.compile("[0-9]+");
    /** What a redaction leaves where a value was. */
    private static final Pattern MASKED = Pattern.compile("\\*+");
    private static final Pattern ARGUMENT = Pattern.compile("^-{0,2}(?:D)?([^=\\s]+)=(\\S+)$");

    /** The shortest value taken for a secret: shorter ones would be found everywhere. */
    static final int SHORTEST = 4;

    private Recordings() {
    }

    /** Whether {@code file} is a Flight Recorder recording - by its first bytes, not its name. */
    public static boolean isRecording(Path file) throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            ByteBuffer head = ByteBuffer.allocateDirect(MAGIC.length);
            return read(channel, head, 0) && magic(head);
        }
    }

    /**
     * Whether {@code file} is a recording that was written to its end: chunk
     * after chunk, each one finished, the last one ending where the file does.
     * A recording being copied out at {@code dumponexit} is not yet.
     */
    public static boolean complete(Path file) throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            long size = channel.size();
            ByteBuffer header = ByteBuffer.allocateDirect(HEADER);
            long at = 0;
            int chunks = 0;
            while (at < size) {
                header.clear();
                if (size - at < HEADER || !read(channel, header, at) || !magic(header)) {
                    return false;
                }
                long chunk = header.getLong(CHUNK_SIZE);
                if (header.get(FILE_STATE) != 0 || chunk < HEADER || chunk > size - at) {
                    return false;
                }
                at += chunk;
                chunks++;
            }
            return chunks > 0 && at == size;
        }
    }

    private static boolean read(FileChannel channel, ByteBuffer into, long position)
            throws IOException {
        long at = position;
        while (into.hasRemaining()) {
            int n = channel.read(into, at);
            if (n < 0) {
                return false;
            }
            at += n;
        }
        return true;
    }

    private static boolean magic(ByteBuffer head) {
        for (int i = 0; i < MAGIC.length; i++) {
            if (head.get(i) != MAGIC[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Whether a setting called {@code name} - an environment variable, a
     * system property, an argument - holds a secret, by its name:
     * {@code DB_PASSWORD}, {@code api.token}, {@code AWS_SECRET_ACCESS_KEY} do;
     * {@code KEYSTORE_PASSWORD_FILE}, {@code PWD} and {@code BYPASS_PROXY} do not.
     */
    public static boolean secretName(String name) {
        if (name == null || name.isBlank()) {
            return false;
        }
        // trustStorePassword reads as trust-store-password
        String lower = name.replaceAll("([a-z0-9])([A-Z])", "$1_$2").toLowerCase(Locale.ROOT);
        if (NOT_SECRETS.contains(lower)) {
            return false;
        }
        String[] words = lower.split("[^a-z0-9]+");
        if (words.length > 1 && REFERENCE.contains(words[words.length - 1])) {
            return false;
        }
        return SECRET.matcher(lower).find() || SHORT.matcher(lower).find();
    }

    /**
     * Whether {@code value} could be a secret at all, rather than a state, a
     * number or one masked already.
     */
    static boolean secretValue(String value) {
        if (value == null) {
            return false;
        }
        String stripped = value.strip();
        return stripped.length() >= SHORTEST
                && !NOT_VALUES.contains(stripped.toLowerCase(Locale.ROOT))
                && !NUMBER.matcher(stripped).matches()
                && !MASKED.matcher(stripped).matches();
    }

    /**
     * The values of the recording's environment, system properties and
     * arguments whose names say secret, by where they are -
     * {@code environment variable DB_PASSWORD}, {@code system property api.token},
     * {@code argument --db.password}. The values are the patterns a searcher
     * hunts for: this is for the process that searches, never the one recorded.
     */
    public static Map<String, String> secretSettings(Path recording) throws IOException {
        Map<String, String> found = new LinkedHashMap<>();
        try (RecordingFile file = new RecordingFile(recording)) {
            while (file.hasMoreEvents()) {
                RecordedEvent event = file.readEvent();
                switch (event.getEventType().getName()) {
                    case "jdk.InitialEnvironmentVariable" -> take(found,
                            "environment variable ", string(event, "key"),
                            string(event, "value"));
                    case "jdk.InitialSystemProperty" -> take(found, "system property ",
                            string(event, "key"), string(event, "value"));
                    case "jdk.JVMInformation" -> {
                        arguments(found, string(event, "jvmArguments"));
                        arguments(found, string(event, "javaArguments"));
                        arguments(found, string(event, "jvmFlags"));
                    }
                    default -> {
                        // the rest is what discovery finds by its shape
                    }
                }
            }
        }
        return found;
    }

    /** {@link #secretSettings} as needles of the redaction, labelled by where each was. */
    static List<Redactor.Needle> needles(Path recording) throws IOException {
        List<Redactor.Needle> needles = new ArrayList<>();
        secretSettings(recording).forEach((label, value) ->
                needles.add(Redactor.Needle.text(label, value.strip())));
        return needles;
    }

    private static String string(RecordedEvent event, String field) {
        return event.hasField(field) ? event.getString(field) : null;
    }

    private static void take(Map<String, String> found, String kind, String name,
            String value) {
        // -Dapi.token= is a system property and an argument: once is enough
        if (secretName(name) && secretValue(value) && !found.containsValue(value)) {
            found.putIfAbsent(kind + name, value);
        }
    }

    private static void arguments(Map<String, String> found, String line) {
        if (line == null) {
            return;
        }
        for (String argument : line.split("\\s+")) {
            Matcher setting = ARGUMENT.matcher(argument);
            if (setting.matches()) {
                take(found, "argument ", setting.group(1), setting.group(2));
            }
        }
    }

    /**
     * Reads every event of {@code recording}: a copy that cannot be read to
     * its end is no copy to hand on.
     *
     * @throws Redactor.Incomplete when it cannot
     */
    static void readable(Path recording) throws IOException {
        if (!complete(recording)) {
            throw new Redactor.Incomplete("the redacted recording does not end where its "
                    + "last chunk does - so it was deleted and not handed out");
        }
        try (RecordingFile file = new RecordingFile(recording)) {
            while (file.hasMoreEvents()) {
                file.readEvent();
            }
        } catch (IOException | RuntimeException e) {
            throw new Redactor.Incomplete("the redacted recording could not be read back - "
                    + e.getClass().getSimpleName() + ": " + e.getMessage()
                    + " - so it was deleted and not handed out");
        }
    }
}
