package space.seclume.verify;

import java.util.ArrayList;
import java.util.List;

/**
 * The report, as plain text that fits in a ticket.
 *
 * <p>No colours, no boxes, no progress bar. What this is pasted into is a
 * ticket or a chat window, and both of those ruin anything cleverer.
 */
final class Report {

    private final StringBuilder text = new StringBuilder(1024); // seclume-allow: a report, and the secret never goes in it
    private final List<String> problems = new ArrayList<>();

    void title(String name) {
        text.append(text.isEmpty() ? "" : "\n").append(name).append('\n');
    }

    void line(String key, String value) {
        text.append("  ").append(pad(key)).append(value).append('\n');
    }

    /** Something worth acting on - repeated at the end so it is not missed. */
    void problem(String what) {
        problems.add(what);
    }

    boolean hasProblems() {
        return !problems.isEmpty();
    }

    private static String pad(String key) {
        StringBuilder padded = new StringBuilder(key); // seclume-allow: a label
        while (padded.length() < 24) {
            padded.append(' ');
        }
        return padded.append("  ").toString();
    }

    @Override
    public String toString() {
        StringBuilder whole = new StringBuilder(text); // seclume-allow: a report
        if (!problems.isEmpty()) {
            whole.append("\nwhat to do\n");
            for (String problem : problems) {
                whole.append("  - ").append(problem).append('\n');
            }
        }
        return whole.toString();
    }
}
