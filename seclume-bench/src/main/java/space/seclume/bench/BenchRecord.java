package space.seclume.bench;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A benchmark figure with everything needed to disbelieve it.
 *
 * <p>The numbers in the README are the loudest thing in the project, and that
 * is exactly why they have to be boring to reproduce. A measurement without
 * the machine, the JDK, the server, the distance to it and the raw iterations
 * beside it is not a result; it is an assertion with a decimal point.
 *
 * <p>So this turns a JMH run into a record: the JSON JMH already writes, plus
 * the things JMH does not know - which server answered, what it says it is,
 * how far away it is, and which commit was measured. The one-liner that
 * produced it goes in the file too, because the second most useful thing after
 * a number is the command that makes it again.
 *
 * <pre>
 * java -cp seclume-bench.jar space.seclume.bench.BenchRecord \
 *      BENCHMARKS.md target/jmh-result.json "the command that made it"
 * </pre>
 *
 * <p><b>What this deliberately does not do</b> is decide whether a number is
 * good. A benchmark that judges itself is a benchmark that gets tuned until it
 * agrees, and the comparison that matters - against the vendor driver, on the
 * same machine, in the same run - is already how these are written.
 */
public final class BenchRecord {

    private BenchRecord() {
    }

    /** One measured line out of the JMH JSON. */
    record Measured(String benchmark, String mode, double score, double error,
                            String unit, int forks, int warmupIterations,
                            int measurementIterations, String params, List<Double> raw) {

        /**
         * The class, the method, and <b>the parameters</b>.
         *
         * <p>The parameters are not decoration: these benchmarks are written
         * as one method run twice, once with this driver and once with the
         * vendor's, and that is the whole comparison. Leaving them out
         * produced a first record with two rows both called
         * {@code QueryBenchmark.selectManyRows}, carrying different numbers
         * and no way to tell which was which.
         */
        String shortName() {
            String name = benchmark.substring(benchmark.lastIndexOf('.') + 1);
            String owner = benchmark.substring(0, benchmark.lastIndexOf('.'));
            String base = owner.substring(owner.lastIndexOf('.') + 1) + "." + name;
            return params.isEmpty() ? base : base + " [" + params + "]";
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: BenchRecord <file.md> <jmh-result.json> [command]");
            System.exit(2);
            return;
        }
        Path out = Path.of(args[0]);
        // seclume-allow: a JMH result file - timings and benchmark names, written by the run a moment ago, and holding no credential of any kind
        String json = Files.readString(Path.of(args[1]), StandardCharsets.UTF_8);
        String command = args.length > 2 ? args[2] : "not recorded";
        Files.writeString(out, render(parse(json), environment(), command),
                StandardCharsets.UTF_8);
        System.out.println("wrote " + out);
    }

    // ---- what the machine and the server are -------------------------------

    /**
     * Everything a reader needs in order to say "not on my machine".
     *
     * <p>The server half is the part a benchmark harness usually leaves out
     * and the part that most often explains a disagreement: a figure measured
     * against a container on loopback and one measured across a switch are not
     * the same measurement, and the round-trip time is the difference.
     */
    static Map<String, String> environment() {
        Map<String, String> facts = new LinkedHashMap<>();
        Runtime runtime = Runtime.getRuntime();
        facts.put("measured", Instant.now().toString());
        facts.put("commit", commit());
        facts.put("os", System.getProperty("os.name") + " " + System.getProperty("os.version")
                + " (" + System.getProperty("os.arch") + ")");
        facts.put("cpus", String.valueOf(runtime.availableProcessors()));
        facts.put("heap", (runtime.maxMemory() >> 20) + " MB max");
        facts.put("jdk", System.getProperty("java.vm.name") + " "
                + System.getProperty("java.version") + " ("
                + System.getProperty("java.vendor") + ")");
        facts.put("jvm arguments", safeArguments());

        String url = System.getProperty("bench.url");
        if (url == null) {
            facts.put("server", "not recorded - pass -Dbench.url to have it asked");
            return facts;
        }
        facts.put("server", server(url));
        facts.put("round trip", roundTrip(url));
        return facts;
    }

    /**
     * The JVM's arguments, with the ones that describe this machine left out.
     *
     * <p>The first version printed them all, and the first record it produced
     * carried {@code -Dbench.url=...&path=.local-mysql-password} - the host
     * this was run against and the <b>path of the password file</b>, into a
     * document meant to be committed. {@code Compatibility} had already learnt
     * this and skips its own url and secret lines for exactly the same reason;
     * writing a second generator taught me nothing until it had made the same
     * mistake.
     *
     * <p>Anything naming a url, a path, a password or a secret is dropped
     * rather than masked: a masked value still says how long it was and where
     * it lived.
     */
    private static String safeArguments() {
        List<String> kept = new ArrayList<>();
        for (String argument : ManagementFactory.getRuntimeMXBean().getInputArguments()) {
            String lower = argument.toLowerCase(java.util.Locale.ROOT);
            if (lower.contains("url") || lower.contains("path")
                    || lower.contains("password") || lower.contains("secret")
                    || lower.contains("host")
                    // The commit handed in is recorded as the commit - as an
                    // argument it would only say how it got there.
                    || lower.startsWith("-dbench.commit")) {
                continue;
            }
            kept.add(argument);
        }
        return kept.isEmpty() ? "none worth recording" : String.join(" ", kept);
    }

    /**
     * What the server says it is, asked rather than assumed.
     *
     * <p>"MySQL 8.4" in a table is somebody's memory of which container was
     * running. This is the server's own answer, on the connection that was
     * measured.
     */
    private static String server(String url) {
        try (Connection connection = DriverManager.getConnection(url)) {
            var meta = connection.getMetaData();
            return meta.getDatabaseProductName() + " " + meta.getDatabaseProductVersion();
        } catch (SQLException unreachable) {
            return "unreachable - " + oneLine(unreachable.getMessage());
        }
    }

    /**
     * How far away the server is, measured now and not guessed.
     *
     * <p>The single number that most changes a driver benchmark, and the one
     * most often missing from one. A batch that takes 18 ms across a network
     * and 3 ms on loopback is the same driver doing the same work; without
     * this line the two look like a regression.
     *
     * <p>Measured as the median of a hundred trivial statements, because a
     * mean over a network is a mean over one unlucky packet.
     */
    private static String roundTrip(String url) {
        try (Connection connection = DriverManager.getConnection(url)) {
            String probe = url.contains(":oracle:") ? "select 1 from dual" : "select 1";
            List<Long> samples = new ArrayList<>();
            for (int i = 0; i < 100; i++) {
                long started = System.nanoTime();
                try (var statement = connection.createStatement();
                        var rows = statement.executeQuery(probe)) {
                    rows.next();
                }
                long took = System.nanoTime() - started;
                if (i >= 20) {                       // the first few are warm-up
                    samples.add(took);
                }
            }
            samples.sort(Long::compare);
            long median = samples.get(samples.size() / 2);
            return String.format(java.util.Locale.ROOT, "%.0f µs median of %d round trips",
                    median / 1000.0, samples.size());
        } catch (SQLException unreachable) {
            return "not measured - " + oneLine(unreachable.getMessage());
        }
    }

    private static String commit() {
        // A run on a machine without the repository - the quiet Linux host the
        // figures are taken on - is told which commit it measured.
        String given = System.getProperty("bench.commit");
        if (given != null && !given.isBlank()) {
            return given;
        }
        try {
            // --dirty: a run measured on a working tree with changes nobody
            // committed is not the commit it names, and a hash without the
            // mark would say it was.
            Process git = new ProcessBuilder("git", "describe", "--always", "--dirty")
                    .redirectErrorStream(true).start();
            // seclume-allow: the output of git describe - a commit hash, and no part of this project's secrets
            String out = new String(git.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            return git.waitFor(5, java.util.concurrent.TimeUnit.SECONDS) && git.exitValue() == 0
                    ? out.trim() : "not a git checkout";
        } catch (IOException | InterruptedException notThere) {
            Thread.currentThread().interrupt();
            return "not recorded";
        }
    }

    // ---- reading what JMH wrote --------------------------------------------

    private static final Pattern BENCHMARK = Pattern.compile("\"benchmark\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern MODE = Pattern.compile("\"mode\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern FORKS = Pattern.compile("\"forks\"\\s*:\\s*(\\d+)");
    private static final Pattern WARMUP = Pattern.compile("\"warmupIterations\"\\s*:\\s*(\\d+)");
    private static final Pattern ITERATIONS =
            Pattern.compile("\"measurementIterations\"\\s*:\\s*(\\d+)");
    private static final Pattern SCORE = Pattern.compile("\"score\"\\s*:\\s*([0-9.eE+-]+)");
    private static final Pattern ERROR = Pattern.compile("\"scoreError\"\\s*:\\s*([0-9.eE+-]+)");
    private static final Pattern UNIT = Pattern.compile("\"scoreUnit\"\\s*:\\s*\"([^\"]+)\"");
    /**
     * JMH pretty-prints its JSON, so the two opening brackets are not
     * adjacent.
     *
     * <p>The first version matched {@code [[} and therefore found nothing, and
     * the record printed "no raw data in the JMH output" about a file that was
     * full of it. A reader would have believed the document and not doubted
     * the reader, which is exactly the failure a generated file makes easy.
     */
    private static final Pattern RAW = Pattern.compile(
            "\"rawData\"\\s*:\\s*\\[\\s*\\[(.*?)]\\s*]", Pattern.DOTALL);

    /**
     * A small reader rather than a JSON library, and on purpose.
     *
     * <p>This module already carries JMH and the four vendor drivers for
     * comparison; adding a parser so that a report can be written would be a
     * dependency for a paragraph. JMH's own output is a stable shape and the
     * five fields wanted here are not going to move.
     */
    static List<Measured> parse(String json) {
        List<Measured> measured = new ArrayList<>();
        for (String block : json.split("\\{\\s*\"jmhVersion\"")) {
            Matcher benchmark = BENCHMARK.matcher(block);
            if (!benchmark.find()) {
                continue;
            }
            measured.add(new Measured(
                    benchmark.group(1),
                    first(MODE, block, "?"),
                    number(SCORE, block),
                    number(ERROR, block),
                    first(UNIT, block, "?"),
                    (int) number(FORKS, block),
                    (int) number(WARMUP, block),
                    (int) number(ITERATIONS, block),
                    params(block),
                    raw(block)));
        }
        return measured;
    }

    private static final Pattern PARAMS = Pattern.compile(
            "\"params\"\\s*:\\s*\\{(.*?)}", Pattern.DOTALL);
    private static final Pattern ONE_PARAM = Pattern.compile(
            "\"([^\"]+)\"\\s*:\\s*\"([^\"]*)\"");

    /** The JMH parameters of one result, as {@code name=value} pairs. */
    private static String params(String block) {
        Matcher found = PARAMS.matcher(block);
        if (!found.find()) {
            return "";
        }
        List<String> pairs = new ArrayList<>();
        Matcher one = ONE_PARAM.matcher(found.group(1));
        while (one.find()) {
            pairs.add(one.group(1) + "=" + one.group(2));
        }
        return String.join(", ", pairs);
    }

    private static List<Double> raw(String block) {
        Matcher found = RAW.matcher(block);
        if (!found.find()) {
            return List.of();
        }
        List<Double> values = new ArrayList<>();
        for (String piece : found.group(1).split("[,\\s\\[\\]]+")) {
            if (!piece.isBlank()) {
                try {
                    values.add(Double.parseDouble(piece));
                } catch (NumberFormatException notANumber) {
                    // A nested shape this reader does not need. Skipped rather
                    // than guessed at.
                }
            }
        }
        return values;
    }

    private static String first(Pattern pattern, String block, String fallback) {
        Matcher found = pattern.matcher(block);
        return found.find() ? found.group(1) : fallback;
    }

    private static double number(Pattern pattern, String block) {
        Matcher found = pattern.matcher(block);
        return found.find() ? Double.parseDouble(found.group(1)) : 0;
    }

    // ---- the page ----------------------------------------------------------

    /**
     * The page, and every number on it in one locale.
     *
     * <p>{@code Locale.ROOT} at each format, not as decoration: the default
     * locale writes {@code 0,245} on a German machine and {@code 0.245} on an
     * English one, so a generated document would say something different
     * depending on who ran the generator - and the figures would stop being
     * numbers to anything that read them afterwards. A record whose content
     * depends on a machine setting is the opposite of a reproducible one, and
     * the control caught it on its first run.
     */
    static String render(List<Measured> measured, Map<String, String> environment,
            String command) {
        StringBuilder page = new StringBuilder();
        page.append("# Benchmarks\n\n")
            .append("Produced by `space.seclume.bench.BenchRecord` from a JMH run, ")
            .append("not written by hand.\n\n")
            .append("**Every figure in the README should be traceable to a block in this ")
            .append("file.** A measurement without the machine, the JDK, the server and the ")
            .append("distance to it beside it is an assertion with a decimal point.\n\n");

        page.append("## The run\n\n| | |\n|---|---|\n");
        environment.forEach((name, value) ->
                page.append("| **").append(name).append("** | ").append(value).append(" |\n"));
        page.append("\n## Reproducing it\n\n```\n").append(command).append("\n```\n");

        page.append("\n## What was measured\n\n")
            .append("| benchmark | mode | score | error | unit | forks | warmup | iterations |\n")
            .append("|---|---|---|---|---|---|---|---|\n");
        for (Measured one : measured) {
            page.append("| `").append(one.shortName()).append("` | ").append(one.mode())
                .append(" | ").append(String.format(java.util.Locale.ROOT, "%.3f", one.score()))
                .append(" | ± ").append(String.format(java.util.Locale.ROOT, "%.3f", one.error()))
                .append(" | ").append(one.unit())
                .append(" | ").append(one.forks())
                .append(" | ").append(one.warmupIterations())
                .append(" | ").append(one.measurementIterations())
                .append(" |\n");
        }

        page.append("\n## The iterations themselves\n\n")
            .append("Not a summary of them. An average with an error bar hides a bimodal ")
            .append("result, and a bimodal result is usually the interesting one.\n\n");
        for (Measured one : measured) {
            page.append("- `").append(one.shortName()).append("` — ");
            if (one.raw().isEmpty()) {
                page.append("no raw data in the JMH output");
            } else {
                List<String> printed = new ArrayList<>();
                for (double value : one.raw()) {
                    printed.add(String.format(java.util.Locale.ROOT, "%.3f", value));
                }
                page.append(String.join(", ", printed)).append(' ').append(one.unit());
            }
            page.append('\n');
        }

        page.append("\n## What these numbers do not say\n\n")
            .append("That they hold on another machine, another JDK, or another distance to ")
            .append("the server. They say what this run measured, which is the only thing a ")
            .append("benchmark can say.\n");
        return page.toString();
    }

    private static String oneLine(String text) {
        return text == null ? "" : text.replace('\n', ' ').replace('\r', ' ').trim();
    }
}
