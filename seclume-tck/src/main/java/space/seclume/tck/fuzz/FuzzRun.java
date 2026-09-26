package space.seclume.tck.fuzz;

import java.util.Map;
import java.util.TreeMap;
import java.util.function.Supplier;

import space.seclume.internal.AnswerBoundary;

/**
 * One protocol's boundary against a whole corpus, reported as one result.
 *
 * <p>The four drivers differ in their seeds and in nothing else, so the loop,
 * the tally and the shape of the failure report live here rather than four
 * times over. A test then says only what its protocol accepts, which is the
 * part only that protocol knows.
 *
 * <p><b>Why one test and not one per case.</b> A corpus of a few thousand
 * blocks as JUnit cases would bury the report, and the interesting number is
 * not which block failed but whether any did - with the bytes to reproduce it.
 * So failures are collected, counted and printed together: the first one is
 * rarely the most instructive, and ten of them usually share one cause.
 */
public final class FuzzRun {

    private FuzzRun() {
    }

    /** How many failing cases are printed before the rest are only counted. */
    private static final int SHOWN = 8;

    /**
     * Runs every case the seeds generate and fails with all of it at once.
     *
     * @param what  the implementation's name, for the report
     * @param seeds byte streams this protocol would accept
     */
    public static void against(String what, Supplier<AnswerBoundary> boundary,
            Map<String, byte[]> seeds) {
        ByteCorpus corpus = ByteCorpus.from(seeds);
        Map<String, byte[]> chosen = corpus.selected();
        Map<String, String> failures = new TreeMap<>();
        Map<String, Integer> refusals = new TreeMap<>();
        int[] clean = {0};

        chosen.forEach((name, bytes) -> {
            try {
                BoundaryContract.Reading reading = BoundaryContract.check(what, boundary, bytes);
                if (reading.failure() == null) {
                    clean[0]++;
                    return;
                }
                refusals.merge(reading.failure().getClass().getSimpleName(), 1, Integer::sum);
                // Question 5: a refusal is fine, an unexplained one is not.
                // Somebody reading a log has to be able to act on it, and a
                // NullPointerException or a bare exception with no message says
                // only that the parser was surprised.
                if (reading.failure().getMessage() == null
                        || reading.failure() instanceof NullPointerException
                        || reading.failure() instanceof IndexOutOfBoundsException) {
                    failures.put(name, "refused in a way nobody can act on: "
                            + reading.failure().getClass().getName()
                            + ": " + reading.failure().getMessage()
                            + "\n  stream: " + BoundaryContract.hex(bytes));
                }
            } catch (AssertionError breach) {
                failures.put(name, breach.getMessage());
            }
        });

        System.err.println("[fuzz " + what + "] " + chosen.size() + " cases, "
                + clean[0] + " read cleanly, refusals " + refusals);

        if (failures.isEmpty()) {
            return;
        }
        StringBuilder report = new StringBuilder(failures.size() + " of "
                + chosen.size() + " cases broke the contract:\n");
        failures.entrySet().stream().limit(SHOWN).forEach(entry ->
                report.append("\n== ").append(entry.getKey()).append('\n')
                      .append(entry.getValue()).append('\n'));
        if (failures.size() > SHOWN) {
            report.append("\n... and ").append(failures.size() - SHOWN).append(" more");
        }
        throw new AssertionError(report.toString());
    }
}
