package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.Segments;

/**
 * The env-file reader against a model of its rules written with strings:
 * random files with comments, blank lines, {@code export}, spaces and tabs
 * around {@code =}, both quotes (closed and not), trailing spaces, CRLF,
 * names that only start like the wanted one, empty and over-long values, and
 * a last line without its newline. Both have to give the same value, or both
 * refuse. Only test values cross the heap here.
 */
class EnvFileModelTest {

    private static final String KEY = "DB_PASS";
    private static final int MAX = 12;
    private static final int ROUNDS = Integer.getInteger("seclume.envfile.rounds", 3_000);
    private static final String REFUSED = "<refused>";

    @TempDir
    Path directory;

    @Test
    void theReaderFollowsTheModel() throws Exception {
        long seed = Long.getLong("seclume.envfile.seed", 0xE7F11E);
        Random random = new Random(seed);
        Path file = directory.resolve("app.env");
        for (int round = 0; round < ROUNDS; round++) {
            String content = randomFile(random);
            Files.write(file, content.getBytes(StandardCharsets.US_ASCII));
            String expected = model(content);
            String actual;
            try (SecretScope scope = SecretScope.fromProvider(
                    new EnvFileSecretProvider(file, KEY, MAX))) {
                actual = new String(Segments.toBytes(scope.secret()), StandardCharsets.US_ASCII);
            } catch (SecretUnavailableException refused) {
                actual = REFUSED;
            }
            assertEquals(expected, actual, "seed " + seed + " round " + round + ", file:\n"
                    + content.replace("\r", "\\r").replace("\t", "\\t"));
        }
    }

    /** The rules, in strings: the first line that names the key decides. */
    static String model(String content) {
        if (content.isEmpty()) {
            return REFUSED;
        }
        String[] lines = content.split("\n", -1);
        for (String raw : lines) {
            String line = raw.endsWith("\r") ? raw.substring(0, raw.length() - 1) : raw;
            int at = skip(line, 0);
            if (at >= line.length() || line.charAt(at) == '#') {
                continue;
            }
            if (line.length() - at > 7 && line.startsWith("export ", at)) {
                at = skip(line, at + 7);
            }
            if (!line.startsWith(KEY, at)) {
                continue;
            }
            at = skip(line, at + KEY.length());
            if (at >= line.length() || line.charAt(at) != '=') {
                continue;
            }
            at = skip(line, at + 1);
            String value;
            char quote = at < line.length() ? line.charAt(at) : 0;
            if (quote == '"' || quote == '\'') {
                int close = line.indexOf(quote, at + 1);
                value = line.substring(at + 1, close < 0 ? line.length() : close);
            } else {
                int end = line.length();
                while (end > at && (line.charAt(end - 1) == ' ' || line.charAt(end - 1) == '\t')) {
                    end--;
                }
                value = line.substring(at, end);
            }
            return value.isEmpty() || value.length() > MAX ? REFUSED : value;
        }
        return REFUSED;
    }

    private static int skip(String line, int at) {
        while (at < line.length() && (line.charAt(at) == ' ' || line.charAt(at) == '\t')) {
            at++;
        }
        return at;
    }

    private static String randomFile(Random random) {
        List<String> lines = new ArrayList<>();
        int count = random.nextInt(5);
        for (int i = 0; i < count; i++) {
            lines.add(randomLine(random));
        }
        if (random.nextInt(4) != 0) {
            lines.add(random.nextInt(lines.size() + 1), entry(random, KEY));
        }
        StringBuilder file = new StringBuilder();
        for (int i = 0; i < lines.size(); i++) {
            file.append(lines.get(i));
            boolean last = i == lines.size() - 1;
            if (!last || random.nextBoolean()) {
                file.append(random.nextInt(3) == 0 ? "\r\n" : "\n");
            }
        }
        return file.toString();
    }

    private static String randomLine(Random random) {
        return switch (random.nextInt(7)) {
            case 0 -> "# " + value(random);
            case 1 -> spaces(random);
            case 2 -> entry(random, "OTHER");
            case 3 -> entry(random, KEY + "X");
            case 4 -> entry(random, KEY.substring(0, 5));
            case 5 -> KEY + spaces(random) + value(random);      // no '='
            default -> entry(random, KEY);
        };
    }

    private static String entry(Random random, String name) {
        StringBuilder line = new StringBuilder(spaces(random));
        if (random.nextInt(3) == 0) {
            line.append(random.nextBoolean() ? "export " : "export\t");
            line.append(spaces(random));
        }
        line.append(name).append(spaces(random)).append('=').append(spaces(random));
        String value = random.nextInt(8) == 0 ? "" : value(random);
        switch (random.nextInt(4)) {
            case 0 -> line.append('"').append(value).append(random.nextInt(4) == 0 ? "" : "\"")
                    .append(spaces(random));
            case 1 -> line.append('\'').append(value).append(random.nextInt(4) == 0 ? "" : "'")
                    .append(spaces(random));
            default -> line.append(value).append(spaces(random));
        }
        return line.toString();
    }

    private static String value(Random random) {
        String alphabet = "abcXYZ019#=-_";
        StringBuilder value = new StringBuilder();
        int length = 1 + random.nextInt(MAX + 3);
        for (int i = 0; i < length; i++) {
            value.append(alphabet.charAt(random.nextInt(alphabet.length())));
            if (i > 0 && i < length - 1 && random.nextInt(8) == 0) {
                value.append(' ');
            }
        }
        return value.toString();
    }

    private static String spaces(Random random) {
        return switch (random.nextInt(5)) {
            case 0 -> " ";
            case 1 -> "\t";
            case 2 -> "  \t";
            default -> "";
        };
    }
}
