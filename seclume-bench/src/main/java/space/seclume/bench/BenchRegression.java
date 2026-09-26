package space.seclume.bench;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Flags a benchmark regression without trusting a shared runner's clock.
 *
 * <pre>
 *   java -cp seclume-bench.jar space.seclume.bench.BenchRegression baseline.properties jmh.json
 *   java -cp seclume-bench.jar space.seclume.bench.BenchRegression --write baseline.properties jmh.json
 * </pre>
 *
 * <p>An absolute time from last night's runner says little about tonight's:
 * another machine, other neighbours, 20 % either way. What the README claims
 * is a <b>ratio</b> - seclume against the vendor driver - and both halves of a
 * ratio are measured in the same run, on the same runner, minutes apart, so
 * most of the runner's noise cancels. So the baseline keeps, per benchmark,
 * seclume's time divided by the vendor driver's, and a run fails when
 *
 * <ul>
 *   <li>a ratio has grown by more than the tolerance (15 % unless the baseline
 *       says otherwise) - seclume got slower relative to the vendor; or</li>
 *   <li>a ratio that was below 1 is now at or above it - a "faster than" in
 *       the README is no longer true, however small the step.</li>
 * </ul>
 *
 * <p>A pair the run did not measure is reported and not failed: the nightly
 * job runs a subset. A pair the baseline does not know is reported as new.
 */
public final class BenchRegression {

    /** Parameters that name the side of the comparison, not the workload. */
    private static final List<String> SIDE = List.of("driver", "combination");
    private static final List<String> SECLUME = List.of("seclume", "seclume-seclume");
    private static final List<String> VENDOR = List.of("vendor", "hikari-vendor");
    private static final double DEFAULT_TOLERANCE = 0.15;

    private BenchRegression() {
    }

    public static void main(String[] args) throws IOException {
        boolean write = args.length == 3 && "--write".equals(args[0]);
        if (!write && args.length != 2) {
            System.err.println("usage: BenchRegression [--write] <baseline.properties> <jmh.json>");
            System.exit(2);
        }
        Path baseline = Path.of(args[write ? 1 : 0]);
        String json = Files.readString(Path.of(args[write ? 2 : 1]), StandardCharsets.UTF_8); // seclume-allow: JMH results, no secret
        Map<String, Double> measured = ratios(BenchRecord.parse(json));
        if (write) {
            Files.writeString(baseline, render(measured), StandardCharsets.UTF_8);
            System.out.println("wrote " + measured.size() + " ratios to " + baseline);
            return;
        }
        Report report = compare(Files.readString(baseline, StandardCharsets.UTF_8), measured); // seclume-allow: benchmark ratios, no secret
        report.lines().forEach(System.out::println);
        System.exit(report.failed() ? 1 : 0);
    }

    /** What a comparison found, line by line, and whether the run fails. */
    record Report(List<String> lines, boolean failed) {
    }

    /**
     * seclume's score over the vendor's, per workload - for "average time"
     * results as they are, for throughput results the other way round, so
     * that below 1 always means seclume is ahead.
     */
    static Map<String, Double> ratios(List<BenchRecord.Measured> results) {
        Map<String, Double> seclume = new LinkedHashMap<>();
        Map<String, Double> vendor = new LinkedHashMap<>();
        Map<String, Boolean> throughput = new LinkedHashMap<>();
        for (BenchRecord.Measured result : results) {
            String side = null;
            List<String> workload = new ArrayList<>();
            for (String pair : result.params().split(",\\s*")) {
                if (pair.isEmpty()) {
                    continue;
                }
                String[] nameValue = pair.split("=", 2);
                if (SIDE.contains(nameValue[0])) {
                    side = nameValue.length > 1 ? nameValue[1] : "";
                } else {
                    workload.add(pair);
                }
            }
            if (side == null) {
                continue;
            }
            String key = shortName(result.benchmark())
                    + (workload.isEmpty() ? "" : " [" + String.join(", ", workload) + "]");
            if (SECLUME.contains(side)) {
                seclume.put(key, result.score());
            } else if (VENDOR.contains(side)) {
                vendor.put(key, result.score());
            }
            throughput.put(key, "thrpt".equals(result.mode()));
        }
        Map<String, Double> ratios = new LinkedHashMap<>();
        for (Map.Entry<String, Double> entry : seclume.entrySet()) {
            Double other = vendor.get(entry.getKey());
            if (other == null || other <= 0 || entry.getValue() <= 0) {
                continue;
            }
            ratios.put(entry.getKey(), throughput.get(entry.getKey())
                    ? other / entry.getValue() : entry.getValue() / other);
        }
        return ratios;
    }

    /** {@code space.seclume.bench.QueryBenchmark.selectOne} -> {@code QueryBenchmark.selectOne}. */
    private static String shortName(String benchmark) {
        int method = benchmark.lastIndexOf('.');
        int type = method > 0 ? benchmark.lastIndexOf('.', method - 1) : -1;
        return benchmark.substring(type + 1);
    }

    static Report compare(String baselineText, Map<String, Double> measured) {
        Map<String, Double> baseline = new LinkedHashMap<>();
        double tolerance = DEFAULT_TOLERANCE;
        for (String raw : baselineText.split("\\R")) {
            String line = raw.strip();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            int equals = line.lastIndexOf('=');
            if (equals < 0) {
                throw new IllegalArgumentException("not a baseline line: " + line);
            }
            String key = line.substring(0, equals).strip();
            double value = Double.parseDouble(line.substring(equals + 1).strip());
            if ("tolerance".equals(key)) {
                tolerance = value;
            } else {
                baseline.put(key, value);
            }
        }
        List<String> lines = new ArrayList<>();
        boolean failed = false;
        lines.add(String.format(Locale.ROOT, "seclume / vendor per benchmark (below 1: seclume "
                + "ahead); tolerance %.0f %%", tolerance * 100));
        for (Map.Entry<String, Double> entry : baseline.entrySet()) {
            Double now = measured.get(entry.getKey());
            double before = entry.getValue();
            if (now == null) {
                lines.add(String.format(Locale.ROOT, "  not measured  %-55s was %.3f",
                        entry.getKey(), before));
                continue;
            }
            String verdict;
            // A lead within the noise (a baseline of 0.99, say) is not a
            // claim anyone should make, and losing it is not news.
            if (before < 1 - tolerance / 3 && now >= 1) {
                verdict = "LOST LEAD";
                failed = true;
            } else if (now > before * (1 + tolerance)) {
                verdict = "REGRESSED";
                failed = true;
            } else {
                verdict = "ok";
            }
            lines.add(String.format(Locale.ROOT, "  %-12s  %-55s %.3f -> %.3f", verdict,
                    entry.getKey(), before, now));
        }
        for (Map.Entry<String, Double> entry : measured.entrySet()) {
            if (!baseline.containsKey(entry.getKey())) {
                lines.add(String.format(Locale.ROOT, "  new           %-55s %.3f",
                        entry.getKey(), entry.getValue()));
            }
        }
        lines.add(failed ? "REGRESSION - see the lines above" : "no regression");
        return new Report(lines, failed);
    }

    private static String render(Map<String, Double> ratios) {
        StringBuilder text = new StringBuilder(
                "# seclume's time over the vendor driver's, per benchmark (below 1: seclume ahead).\n"
                + "# Written by BenchRegression --write; read by the nightly benchmark job.\n"
                + "tolerance=" + DEFAULT_TOLERANCE + "\n");
        ratios.forEach((key, ratio) -> text.append(key).append('=')
                .append(String.format(Locale.ROOT, "%.4f", ratio)).append('\n'));
        return text.toString();
    }
}
