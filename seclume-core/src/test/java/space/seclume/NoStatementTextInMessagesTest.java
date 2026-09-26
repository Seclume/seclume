package space.seclume;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

/**
 * No statement text in an exception message, in any module.
 *
 * <p>{@link QueryFingerprint} exists because the SQL text is the one thing
 * that must not be recorded: a literal in it can be a password, a card number
 * or a person. The JFR events were written to that rule from the start. <b>The
 * exception messages were not</b>, and an exception message is more certain to
 * be logged than any event - it goes into the application's own log, into a
 * stack trace, into a ticket, into a screenshot.
 *
 * <p>Twenty-seven places across five modules read
 * {@code "... : " + sql}. Every one of them now reads {@code shape(sql)},
 * which is the same statement with its values taken out. What is lost is a
 * literal nobody should have had; what is kept is which statement it was,
 * which is the whole reason the text was in the message.
 *
 * <p>The check is on the source and not on behaviour, for the same reason
 * {@code ForbiddenApiTest} is: this is a property one loses while writing a
 * single line, and every functional test keeps passing while it is lost.
 *
 * <p>Where a message demonstrably carries no statement - a table name from the
 * catalogue, a driver-built fragment with no user text in it - the line, or
 * the one above it, carries {@code // seclume-allow: <reason>}, the same
 * marker and the same rule as the forbidden-API list.
 */
class NoStatementTextInMessagesTest {

    private static final String ALLOW_MARKER = "seclume-allow:";

    /**
     * A concatenation with something whose name ends in {@code sql}.
     *
     * <p>Named by convention rather than by type, and that is a limitation
     * worth writing down: a variable called {@code text} holding a statement
     * would pass. It catches what is actually there and what anybody writing
     * the next one will call it.
     */
    private static final Pattern CONCATENATED_SQL =
            Pattern.compile("[+]\\s*(this[.])?[A-Za-z0-9_]*[sS]ql\\b(?![.])");

    /**
     * A concatenation with something whose name ends in {@code url}.
     *
     * <p>A seclume URL carries a provider and a path and no credential - that
     * is the design, and it is why this was not thought about. The message
     * that names a <b>wrong</b> URL is the one that gets handed a vendor's,
     * and those routinely read {@code ...?user=app&password=...}. Echoing it
     * back puts the password in the log at the moment somebody is already
     * confused and reading logs. {@code JdbcUrl.redact} keeps the shape and
     * drops every value.
     */
    private static final Pattern CONCATENATED_URL =
            Pattern.compile("[+]\\s*(this[.])?[A-Za-z0-9_]*[uU]rl\\b(?![.])");

    /** How many lines after {@code Exception(} still count as its arguments. */
    private static final int ARGUMENT_LINES = 4;

    @Test
    void noExceptionMessageCarriesAStatement() throws IOException {
        List<Path> modules = ForbiddenApiTest.productionSources();
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
                "statement text in exception messages - use shape(sql):\n"
                + String.join("\n", findings));
    }

    /** The control: the rule has to be able to fail. */
    @Test
    void theRuleWouldCatchIt() {
        assertTrue(matches("throw new SQLException(\"no rows: \" + sql);"));
        assertTrue(matches("        + \" in: \" + originalSql);"));
        assertTrue(matches("new SQLException(x + this.sql)"));
        assertTrue(matches("throw new IllegalArgumentException(\"not ours: \" + url);"));
        assertTrue(!matches("throw new IllegalArgumentException(\"x\" + redact(url));"));
        // And what it must not catch: the fix itself, and anything else.
        assertTrue(!matches("throw new SQLException(\"no rows: \" + shape(sql));"));
        assertTrue(!matches("int n = a + b;"));
        // A method call on something whose name happens to end in url is not
        // a URL going into a message - the caught exception below is called
        // notAUrl, which is exactly what it is.
        assertTrue(!matches("throw new SQLException(\"x\" + notAUrl.getMessage());"));
    }

    private static boolean matches(String line) {
        return CONCATENATED_SQL.matcher(codeOnly(line)).find()
                || CONCATENATED_URL.matcher(codeOnly(line)).find();
    }

    private static void check(Path file, List<String> findings) throws IOException {
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        int argumentsLeft = 0;
        for (int i = 0; i < lines.size(); i++) {
            String raw = lines.get(i);
            String code = codeOnly(raw);
            if (code.contains("Exception(")) {
                argumentsLeft = ARGUMENT_LINES;
            }
            boolean allowed = raw.contains(ALLOW_MARKER)
                    || (i > 0 && lines.get(i - 1).contains(ALLOW_MARKER));
            if (argumentsLeft > 0 && !allowed) {
                Matcher statement = CONCATENATED_SQL.matcher(code);
                if (statement.find()) {
                    findings.add(file + ":" + (i + 1) + " puts " + statement.group().trim()
                            + " into an exception message - use shape(sql)");
                }
                Matcher address = CONCATENATED_URL.matcher(code);
                if (address.find()) {
                    findings.add(file + ":" + (i + 1) + " puts " + address.group().trim()
                            + " into an exception message - use JdbcUrl.redact(url)");
                }
            }
            if (argumentsLeft > 0) {
                argumentsLeft--;
            }
        }
    }

    /**
     * The line with its string literals and comments removed.
     *
     * <p>Without this the javadoc above - which spells out the pattern on
     * purpose - would report itself.
     */
    private static String codeOnly(String line) {
        StringBuilder out = new StringBuilder(line.length());
        boolean inString = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (inString) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    inString = false;
                }
            } else if (c == '"') {
                inString = true;
            } else if (c == '/' && i + 1 < line.length() && line.charAt(i + 1) == '/') {
                break;
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
}
