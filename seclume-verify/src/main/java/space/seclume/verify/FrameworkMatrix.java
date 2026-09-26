package space.seclume.verify;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Which framework has been run against which database - taken from the test
 * run, never from a belief.
 *
 * <p>{@link Compatibility} answers what a <b>connection</b> can do by making
 * one. This answers a different question that no connection can: has anybody
 * ever actually run Hibernate against this driver on that server. There is
 * only one honest source for that, and it is the test report.
 *
 * <p>So this reads surefire's own output and says what it found. Four
 * outcomes, and the last is the one the whole class exists for:
 *
 * <table border="1">
 *   <caption>What a cell can say</caption>
 *   <tr><th>verified</th><td>the tests ran and passed, with the count</td></tr>
 *   <tr><th>failed</th><td>they ran and did not pass. A generated table that
 *       hides this would be worse than no table</td></tr>
 *   <tr><th>not verified</th><td>the tests exist and were skipped, which in
 *       this project means the server was not running</td></tr>
 *   <tr><th><b>unsupported</b></th><td>no test exists. Not "probably works",
 *       not "should be fine" - nobody has tried it, and that is what the cell
 *       says</td></tr>
 * </table>
 *
 * <p><b>Why the evidence is a class name.</b> A framework could declare
 * itself supported and be believed, which is how every compatibility table
 * turns into folklore. Here a framework has to name a test class per database
 * and that class has to appear in a report with tests in it. A row that claims
 * something nobody wrote a test for comes out as {@code unsupported}, and the
 * only way to change a cell is to write the test.
 *
 * <pre>
 * java -cp seclume-verify.jar space.seclume.verify.FrameworkMatrix \
 *      FRAMEWORKS.md .
 * </pre>
 *
 * <p>The second argument is the directory to search for
 * {@code target/surefire-reports}; it is the repository root in practice.
 */
public final class FrameworkMatrix {

    /** A database column, and the part of a test class name that names it. */
    private record Server(String label, String inClassName) {
    }

    /**
     * A framework row.
     *
     * @param label   what the row is called
     * @param prefix  the start of the test class name that would prove it, or
     *                {@code null} where nobody has written one. A framework
     *                with no prefix is {@code unsupported} everywhere by
     *                construction, and saying so out loud in this table is the
     *                point of listing it at all
     * @param note    what a reader should know about the row
     */
    private record Framework(String label, String prefix, String note) {
    }

    private static final List<Server> SERVERS = List.of(
            new Server("PostgreSQL", "Postgres"),
            new Server("MySQL", "MySql"),
            new Server("SQL Server", "SqlServer"),
            new Server("Oracle", "Oracle"));

    /**
     * The frameworks worth a row, whether or not they have been tried.
     *
     * <p>The ones with no prefix are here <b>because</b> they have not been
     * tried. A table that only lists what works answers the wrong question:
     * somebody choosing a driver wants to know what happens to their Liquibase
     * migration, and "the table does not mention Liquibase" is not an answer.
     */
    private static final List<Framework> FRAMEWORKS = List.of(
            new Framework("Spring Data JPA", "SpringDataOn",
                    "repositories, derived queries, pagination, stored procedures"),
            new Framework("Hibernate", "EntityShapesOn",
                    "every entity shape JPA allows, and every mapped Java type"),
            new Framework("Flyway", "SpringDataOn",
                    "the schema under each test is migrated by Flyway before it runs"),
            new Framework("Hibernate, the edges", "HibernateEdgesOn",
                    "a JSON column, LOBs as values and as streams, @Formula, bulk HQL - "
                    + "the skipped cases are open gaps, named in the CHANGELOG"),
            new Framework("Spring JDBC and transactions", "SpringJdbcOn",
                    "REQUIRES_NEW, NESTED, readOnly, isolation, a timeout; batchUpdate, "
                    + "named parameters, generated keys, scripts, JDBC escapes"),
            new Framework("Spring Data JDBC", "SpringDataJdbcOn",
                    "an aggregate over two tables, optimistic locking, paging"),
            new Framework("Liquibase", "LiquibaseOn",
                    "update, rollback, update again, and the history it keeps"),
            new Framework("jOOQ", "JooqOn",
                    "inserts, a batch, a typed read, a rolled-back transaction, a lazy "
                    + "cursor - SQL Server and Oracle with SQLDialect.DEFAULT, because "
                    + "jOOQ's free edition has no dialect for either"),
            new Framework("MyBatis", "MyBatisOn",
                    "generated keys, dynamic SQL, the batch executor, a typed null"));

    private static final Pattern SET = Pattern.compile("Test set: (\\S+)");
    private static final Pattern COUNTS = Pattern.compile(
            "Tests run: (\\d+), Failures: (\\d+), Errors: (\\d+), Skipped: (\\d+)");

    private FrameworkMatrix() {
    }

    /** What one test class reported. */
    record Outcome(int run, int bad, int skipped) {

        boolean everythingSkipped() {
            return run > 0 && skipped == run;
        }
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("usage: FrameworkMatrix <file.md> [root]");
            System.exit(2);
            return;
        }
        Path out = Path.of(args[0]);
        Path root = Path.of(args.length > 1 ? args[1] : ".");
        Map<String, Outcome> reports = read(root);
        Files.writeString(out, render(reports), StandardCharsets.UTF_8);
        System.out.println("wrote " + out + " from " + reports.size() + " test classes");
    }

    /**
     * Package-private so a test can hand in reports it wrote itself.
     *
     * <p>Needed for the control, which is the part of this class worth more
     * than the class: a generator that always prints {@code verified} would
     * produce a table that looks exactly like a correct one. It is also the
     * only way to exercise the outcomes a healthy run never produces.
     */
    static String renderFrom(Map<String, Outcome> reports) {
        return render(reports);
    }

    /** The same, for a test that wants to state one report rather than find it. */
    static Outcome outcome(int run, int bad, int skipped) {
        return new Outcome(run, bad, skipped);
    }

    /** Every surefire report under the root, by simple class name. */
    private static Map<String, Outcome> read(Path root) throws IOException {
        Map<String, Outcome> found = new LinkedHashMap<>();
        try (Stream<Path> tree = Files.walk(root)) {
            tree.filter(path -> path.getFileName().toString().endsWith(".txt"))
                .filter(path -> path.getParent() != null
                        && path.getParent().getFileName().toString().equals("surefire-reports"))
                .forEach(path -> {
                    try {
                        // seclume-allow: a surefire report - test class names and pass counts, written by the build a moment ago, and the one file in this project that certainly holds no credential
                        String text = Files.readString(path, StandardCharsets.UTF_8);
                        Matcher set = SET.matcher(text);
                        Matcher counts = COUNTS.matcher(text);
                        if (set.find() && counts.find()) {
                            String name = set.group(1);
                            found.put(name.substring(name.lastIndexOf('.') + 1), new Outcome(
                                    Integer.parseInt(counts.group(1)),
                                    Integer.parseInt(counts.group(2))
                                            + Integer.parseInt(counts.group(3)),
                                    Integer.parseInt(counts.group(4))));
                        }
                    } catch (IOException unreadable) {
                        throw new UncheckedIOException(unreadable);
                    }
                });
        }
        return found;
    }

    private static String render(Map<String, Outcome> reports) {
        StringBuilder page = new StringBuilder();
        page.append("# Frameworks\n\n")
            .append("Produced by `space.seclume.verify.FrameworkMatrix` on ")
            .append(LocalDate.now())
            .append(" by reading the test reports of the run that made it, not by hand.\n\n")
            .append("**`unsupported` means nobody has run it**, not that it fails. ")
            .append("The only way to change a cell is to write the test: a framework has to ")
            .append("name a test class per server, and that class has to appear in a report ")
            .append("with tests in it.\n\n");

        page.append('|');
        for (Server server : SERVERS) {
            page.append(" | ").append(server.label());
        }
        page.append(" |\n|---|");
        page.append("---|".repeat(SERVERS.size()));
        page.append('\n');

        List<String> notes = new ArrayList<>();
        for (Framework framework : FRAMEWORKS) {
            page.append("| **").append(framework.label()).append("** |");
            for (Server server : SERVERS) {
                page.append(' ').append(cell(framework, server, reports)).append(" |");
            }
            page.append('\n');
            notes.add("- **" + framework.label() + "** - " + framework.note());
        }

        page.append("\n").append(String.join("\n", notes)).append('\n');
        page.append("\n## What this table does not say\n\n")
            .append("That a verified cell covers everything the framework can do. It covers ")
            .append("what its test class asks of it, which is written down beside each row ")
            .append("above and is less than the whole of any of these libraries.\n");
        return page.toString();
    }

    private static String cell(Framework framework, Server server, Map<String, Outcome> reports) {
        if (framework.prefix() == null) {
            return "unsupported";
        }
        Outcome outcome = reports.get(framework.prefix() + server.inClassName() + "Test");
        if (outcome == null) {
            // The prefix was declared and the class was not in any report:
            // either nobody wrote it, or the module did not run. Both are
            // "not shown to work", and the table says the weaker thing.
            return "unsupported";
        }
        if (outcome.bad() > 0) {
            return "**failed** (" + outcome.bad() + " of " + outcome.run() + ")";
        }
        if (outcome.everythingSkipped()) {
            return "not verified - server absent";
        }
        if (outcome.skipped() > 0) {
            // Partly skipped is not quietly verified: a case skipped on one
            // server names a gap there, and the cell has to show that it is.
            return "verified (" + (outcome.run() - outcome.skipped()) + "), "
                    + outcome.skipped() + " skipped";
        }
        return "verified (" + (outcome.run() - outcome.skipped()) + ")";
    }
}
