package space.seclume;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

/**
 * Error messages, held to the standard the rest of the code is written to.
 *
 * <p>A message is the surface at which a driver is actually used. Everything
 * else about it is read once, when it works; the message is read at three in
 * the morning, when it does not. The style in this repository is therefore:
 * say what happened <b>and</b> what to do about it.
 *
 * <p>That is a habit, and habits slip. This test makes the two halves of it
 * mechanical - a message that is one word, or a number, or the word "error"
 * again, does not get past here. What it cannot check is whether the advice is
 * any good; that stays a matter of writing it.
 *
 * <p>And one rule that is not about style at all: a message must never carry a
 * value that could be a secret. The whole library exists to keep passwords out
 * of the heap - putting one into a log line would be the same mistake through
 * a different door.
 */
class ErrorMessageTest {

    /**
     * Shorter than this and it cannot be saying much.
     *
     * <p>Two thresholds, because a message that names a value says more than
     * its literal part: {@code "cannot read " + path} is a good message with
     * twelve characters of text in the source.
     */
    private static final int SHORTEST_ALONE = 16;
    private static final int SHORTEST_WITH_A_VALUE = 10;

    /** A message that is only one of these says nothing at all. */
    private static final List<String> EMPTY_WORDS = List.of(
            "failed", "error", "invalid", "unsupported", "not supported",
            "bad state", "illegal state", "unknown", "unexpected", "wrong");

    /**
     * Names whose value has no business in a message, compared without case:
     * {@code apiKey}, {@code PW} and {@code bearer} are as much a secret as
     * {@code password}, and were let through. {@code key} and {@code auth}
     * are not here: they name option keys and login methods far more often
     * than a secret, and a rule that cries wolf is switched off.
     */
    private static final List<String> SECRET_NAMES = List.of(
            "password", "passwd", "pw", "secret", "passphrase", "credential", "credentials",
            "token", "apikey", "bearer");

    @Test
    void everyThrownMessageSaysSomething() throws IOException {
        List<String> findings = new ArrayList<>();
        for (Path sources : ForbiddenApiTest.productionSources()) {
            try (Stream<Path> files = Files.walk(sources)) {
                for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                    check(file, findings);
                }
            }
        }
        assertTrue(findings.isEmpty(),
                "messages that would not help anybody:\n" + String.join("\n", findings));
    }

    private static void check(Path file, List<String> findings) throws IOException {
        check(file.toString(), Files.readString(file, StandardCharsets.UTF_8), findings);
    }

    static void check(Object file, String source, List<String> findings) {
        int at = 0;
        while ((at = source.indexOf("throw new ", at)) >= 0) {
            int end = source.indexOf(';', at);
            if (end < 0) {
                break;
            }
            String statement = source.substring(at, end);
            at = end;
            if (!statement.contains("(")) {
                continue;
            }
            int line = lineOf(source, statement, at);
            // Before anything else: a message built in a local variable is
            // what the checks below skip as built elsewhere.
            String carried = allowed(source, line) ? null
                    : builtFromASecret(source, at - statement.length(), statement);
            if (carried != null) {
                findings.add(file + ":" + line + " puts " + carried
                        + " into the message, through a local variable");
                continue;
            }
            if (carriesTheCausesWords(statement) || messageIsBuiltElsewhere(statement)) {
                // The message is the one the cause already wrote; repeating it
                // here would say the same thing twice.
                continue;
            }
            String message = literalsOf(statement);
            if (message.isEmpty()) {
                // No words of its own is fine when something is handed in -
                // a cause, or a message another method built. Only a throw
                // with empty parentheses says nothing at all.
                if (argumentsOf(statement).isBlank()) {
                    findings.add(file + ":" + line + " throws without a message");
                }
                continue;
            }
            String plain = message.strip().toLowerCase(Locale.ROOT);
            int shortest = namesAValue(statement) ? SHORTEST_WITH_A_VALUE : SHORTEST_ALONE;
            if (plain.length() < shortest || !plain.contains(" ")) {
                findings.add(file + ":" + line + " says only \"" + message.strip() + "\"");
            } else if (EMPTY_WORDS.contains(plain.replace(".", ""))) {
                findings.add(file + ":" + line + " says only \"" + message.strip() + "\"");
            }
            if (allowed(source, line)) {
                continue;
            }
            for (String name : SECRET_NAMES) {
                if (concatenates(statement, name)) {
                    findings.add(file + ":" + line + " puts " + name + " into the message");
                }
            }
        }
    }

    /**
     * Whether the words come from somewhere else - a method that builds them.
     *
     * <p>{@code new SQLException(timedOut(), "08003")} carries one literal,
     * and it is the SQLState, not the message. Judging that as the message
     * would mean pushing the text back into the throw, which is exactly the
     * wrong direction for a message worth reading.
     */
    private static boolean messageIsBuiltElsewhere(String statement) {
        String arguments = argumentsOf(statement).strip();
        if (arguments.isEmpty()) {
            return false;
        }
        int comma = -1;
        int depth = 0;
        boolean inString = false;
        for (int i = 0; i < arguments.length() && comma < 0; i++) {
            char c = arguments.charAt(i);
            if (inString) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    inString = false;
                }
            } else if (c == '"') {
                inString = true;
            } else if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
            } else if (c == ',' && depth == 0) {
                comma = i;
            }
        }
        String first = comma < 0 ? arguments : arguments.substring(0, comma);
        return !first.contains("\"");
    }

    /** What stands between the parentheses of the throw. */
    private static String argumentsOf(String statement) {
        int open = statement.indexOf('(');
        int close = statement.lastIndexOf(')');
        return open < 0 || close < open ? "" : statement.substring(open + 1, close);
    }

    /**
     * Whether the message is the one the cause already wrote.
     *
     * <p>{@code new SQLException(e.getMessage(), "08001", e)} says everything
     * the cause said; the only literal in it is the SQLState, which is not the
     * message and must not be judged as one.
     */
    private static boolean carriesTheCausesWords(String statement) {
        return withoutLiterals(statement).contains("getMessage()");
    }

    /** Whether the message carries a value along with its words. */
    private static boolean namesAValue(String statement) {
        return withoutLiterals(statement).contains("+");
    }

    /** All string literals of the statement, joined - that is the message. */
    private static String literalsOf(String statement) {
        StringBuilder message = new StringBuilder();
        boolean inString = false;
        for (int i = 0; i < statement.length(); i++) {
            char c = statement.charAt(i);
            if (inString) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    inString = false;
                } else {
                    message.append(c);
                }
            } else if (c == '"') {
                inString = true;
            }
        }
        return message.toString();
    }

    /**
     * Whether the statement puts a variable of that name into the text -
     * {@code "..." + password} and not the word "password" inside a literal,
     * which is exactly what a good message about a password says.
     */
    private static boolean concatenates(String statement, String name) {
        String code = withoutLiterals(statement).toLowerCase(Locale.ROOT);
        for (String shape : new String[] {"+ " + name, "+" + name}) {
            int at = code.indexOf(shape);
            while (at >= 0) {
                int after = at + shape.length();
                // "+ passwordFile" is a path and says something useful; only
                // the value itself is refused.
                // The underscore counts as part of the name: SECRET_PROPERTY
                // is a constant holding the name of a setting, not a secret.
                char next = after >= code.length() ? ' ' : code.charAt(after);
                // "+ credentials.status()" is what a response said, not the
                // value: a name followed by an access is something of it.
                boolean whole = !Character.isLetterOrDigit(next) && next != '_' && next != '.';
                if (whole) {
                    return true;
                }
                at = code.indexOf(shape, at + 1);
            }
        }
        return false;
    }

    /** A {@code seclume-allow:} comment on the throw's line or the one above. */
    private static boolean allowed(String source, int line) {
        String[] lines = source.split("\n", -1);
        return (line - 1 < lines.length && line >= 1 && lines[line - 1].contains("seclume-allow:"))
                || (line >= 2 && lines[line - 2].contains("seclume-allow:"));
    }

    /**
     * A secret's name concatenated into a local variable the throw then hands
     * over: {@code String why = "..." + password; throw new X(why)} went by,
     * because only the throw's own text was read. The variable is looked for
     * in the forty lines before the throw - a method's reach.
     */
    private static String builtFromASecret(String source, int throwAt, String statement) {
        java.util.regex.Matcher identifiers = java.util.regex.Pattern
                .compile("[A-Za-z_][A-Za-z0-9_]*").matcher(withoutLiterals(argumentsOf(statement)));
        int from = throwAt;
        for (int lines = 0; from > 0 && lines < 40; from--) {
            if (source.charAt(from - 1) == '\n') {
                lines++;
            }
        }
        String before = withoutLiterals(source.substring(Math.max(0, from), Math.max(0, throwAt)))
                .toLowerCase(Locale.ROOT);
        while (identifiers.find()) {
            String variable = identifiers.group().toLowerCase(Locale.ROOT);
            java.util.regex.Matcher assigned = java.util.regex.Pattern
                    .compile("\\b" + java.util.regex.Pattern.quote(variable) + "\\s*=[^=;][^;]*;")
                    .matcher(before);
            while (assigned.find()) {
                for (String name : SECRET_NAMES) {
                    if (concatenates(assigned.group(), name)) {
                        return name;
                    }
                }
            }
        }
        return null;
    }

    private static String withoutLiterals(String statement) {
        StringBuilder code = new StringBuilder();
        boolean inString = false;
        for (int i = 0; i < statement.length(); i++) {
            char c = statement.charAt(i);
            if (inString) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    inString = false;
                }
            } else if (c == '"') {
                inString = true;
            } else {
                code.append(c);
            }
        }
        return code.toString();
    }

    private static int lineOf(String source, String statement, int at) {
        int line = 1;
        for (int i = 0; i < at && i < source.length(); i++) {
            if (source.charAt(i) == '\n') {
                line++;
            }
        }
        return line - countNewlines(statement);
    }

    private static int countNewlines(String text) {
        int count = 0;
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) == '\n') {
                count++;
            }
        }
        return count;
    }
}
