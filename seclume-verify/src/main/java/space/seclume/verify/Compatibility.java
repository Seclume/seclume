package space.seclume.verify;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * What works against which server, written by the run rather than by hand.
 *
 * <p>Every compatibility table in every project starts accurate and ends as
 * folklore: somebody adds a feature, somebody else adds a server, and the
 * table says what was true a year ago. This one is produced by connecting -
 * the same connection {@link Verify} makes, against every server it is given -
 * so it cannot claim anything that was not asked of a running database.
 *
 * <pre>
 * java -cp seclume-verify.jar space.seclume.verify.Compatibility \
 *      COMPATIBILITY.md \
 *      "PostgreSQL 18=jdbc:seclume:postgresql://..." \
 *      "MySQL 8.4=jdbc:seclume:mysql://..."
 * </pre>
 *
 * <p>Each argument after the file is {@code label=url}. The label is what
 * appears as the column heading, because "PostgreSQL 18" and "CockroachDB"
 * both answer a {@code postgresql} URL and only the person running it knows
 * which is which.
 *
 * <p><b>A server that cannot be reached becomes a column saying so</b> rather
 * than stopping the run. A table with one honest gap in it is worth more than
 * no table, and a build that fails because a container was not started teaches
 * everybody to skip the step.
 *
 * <p><b>No secret and no local path reach the file.</b> The lines that
 * describe where this was run from rather than what it was run against are
 * left out - see {@code SKIPPED}.
 */
public final class Compatibility {

    /**
     * Lines that belong in a report and not in a table.
     *
     * <p>{@code url} and {@code secret} describe the machine this was run
     * from, not the server it was run against - and the secret line carries
     * the path of the password file, which has no business in a document that
     * gets committed. {@code connect} is a measurement in milliseconds: it
     * differs on every run, so a generated file containing it would show a
     * change every time and teach everybody to ignore its diffs. The round
     * trip counts stay, because they do not move.
     */
    private static final Set<String> SKIPPED = Set.of("url", "secret", "connect");

    private Compatibility() {
    }

    public static void main(String[] arguments) throws IOException {
        if (arguments.length < 2) {
            System.err.println("""
                    usage: java -cp seclume-verify.jar space.seclume.verify.Compatibility \\
                          <file> "<label>=<jdbc url>" ["<label>=<jdbc url>" ...]

                    Produces a table of what each server answered. The label is the column
                    heading; the URL is the one the application would use.""");
            System.exit(2);
            return;
        }
        Path file = Path.of(arguments[0]);
        Map<String, String> servers = new LinkedHashMap<>();
        for (int i = 1; i < arguments.length; i++) {
            int equals = arguments[i].indexOf('=');
            if (equals <= 0) {
                System.err.println("not a label=url pair: " + arguments[i]);
                System.exit(2);
                return;
            }
            servers.put(arguments[i].substring(0, equals), arguments[i].substring(equals + 1));
        }
        String table = table(servers);
        Files.writeString(file, table, StandardCharsets.UTF_8);
        System.out.println("wrote " + file.toAbsolutePath() + " for " + servers.size()
                + " server(s)");
    }

    /** The table, as Markdown. */
    public static String table(Map<String, String> servers) {
        Map<String, Map<String, String>> byServer = new LinkedHashMap<>();
        Set<String> keys = new LinkedHashSet<>();

        for (Map.Entry<String, String> server : servers.entrySet()) {
            Report report = new Report();
            Verify.run(server.getValue(), report);
            Map<String, String> facts = new LinkedHashMap<>();
            for (String[] fact : report.facts()) {
                if (SKIPPED.contains(fact[0])) {
                    continue;
                }
                facts.put(fact[0], fact[1]);
                keys.add(fact[0]);
            }
            byServer.put(server.getKey(), facts);
        }

        List<String> labels = new ArrayList<>(byServer.keySet());
        StringBuilder out = new StringBuilder(2048); // seclume-allow: a table of capabilities
        out.append("# Compatibility\n\n")
                .append("Produced by `space.seclume.verify.Compatibility` on ")
                .append(LocalDate.now())
                .append(" by connecting to each server, not by hand.\n")
                .append("A blank cell means the server did not report that line at all.\n\n");

        out.append("| |");
        for (String label : labels) {
            out.append(' ').append(label).append(" |");
        }
        out.append("\n|---|");
        for (int i = 0; i < labels.size(); i++) {
            out.append("---|");
        }
        out.append('\n');

        for (String key : keys) {
            out.append("| **").append(key).append("** |");
            for (String label : labels) {
                String value = byServer.get(label).get(key);
                out.append(' ').append(value == null ? "" : escape(value)).append(" |");
            }
            out.append('\n');
        }
        return out.toString();
    }

    /** A pipe in a cell would end the column early. */
    private static String escape(String value) {
        return value.replace("|", "\\|");
    }
}
