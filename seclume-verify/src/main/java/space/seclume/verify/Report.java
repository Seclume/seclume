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
    /**
     * The same lines as facts, in the order they were written.
     *
     * <p>For {@link Compatibility}, which turns several of these reports into
     * one table. Kept beside the text rather than instead of it: the text is
     * what a person pastes into a ticket, and formatting it out of a map would
     * make the ordinary case serve the rare one.
     */
    private final List<String[]> facts = new ArrayList<>();
    /**
     * The same lines again, grouped the way the text groups them.
     *
     * <p>Only {@link #json(int)} needs this. The flat {@link #facts()} cannot
     * carry it: two sections may use the same key - {@code result} under
     * {@code verdict} and a future {@code result} anywhere else - and a flat
     * map would silently keep one of them.
     */
    private final List<Section> sections = new ArrayList<>();

    /** One titled block of the report. */
    private record Section(String name, List<String[]> lines) {

        Section(String name) {
            this(name, new ArrayList<>());
        }
    }

    void title(String name) {
        text.append(text.isEmpty() ? "" : "\n").append(name).append('\n');
        sections.add(new Section(name));
    }

    void line(String key, String value) {
        text.append("  ").append(pad(key)).append(value).append('\n');
        facts.add(new String[] {key, value});
        if (sections.isEmpty()) {
            // A line before any title. Nothing writes one today; a report
            // that dropped it from the JSON and kept it in the text would
            // be the sort of difference nobody finds.
            sections.add(new Section("seclume-verify"));
        }
        sections.get(sections.size() - 1).lines().add(new String[] {key, value});
    }

    /** What was reported, as key/value pairs in the order written. */
    List<String[]> facts() {
        return facts;
    }

    /** Something worth acting on - repeated at the end so it is not missed. */
    void problem(String what) {
        problems.add(what);
    }

    boolean hasProblems() {
        return !problems.isEmpty();
    }

    /**
     * The same report as JSON, for a pipeline rather than a person.
     *
     * <p>Written by hand and not by a library, for the reason the whole
     * project is written by hand: {@code seclume-verify} ships as one jar that
     * has to run in a strange environment, and a preflight check that first
     * needs a dependency tree is not a preflight check.
     *
     * <p><b>Keys are slugs, values are the text.</b> {@code round trips
     * counted} becomes {@code round_trips_counted} so the document can be
     * indexed without quoting, and the value stays the sentence a person would
     * have read. The alternative - typed fields per probe - would mean this
     * file changes shape every time a probe is added, and the consumer with
     * it.
     *
     * <p>{@code ok} is the one field a Kubernetes probe needs, and it is the
     * exit code said twice on purpose: a reader that only looks at the body
     * and a reader that only reads the status agree.
     *
     * <p>It is <b>not</b> {@code problems.isEmpty()}. A connection that stands
     * but has notes against it exits 0 and is reported {@code ok: true} with
     * its notes beside it, exactly as the text report says "reachable, with
     * the notes above". Turning a note into a red build would teach people to
     * stop reporting notes.
     *
     * @param status the exit code this run is about to end with
     */
    String json(int status) {
        StringBuilder out = new StringBuilder(1024); // seclume-allow: a report, and the secret never goes in it
        out.append("{\n  \"tool\": \"seclume-verify\",\n");
        out.append("  \"ok\": ").append(status == 0).append(",\n");
        out.append("  \"status\": ").append(status).append(",\n");
        out.append("  \"sections\": {");
        for (int i = 0; i < sections.size(); i++) {
            Section section = sections.get(i);
            out.append(i > 0 ? "," : "").append("\n    ");
            quote(out, slug(section.name())).append(": {");
            List<String[]> lines = section.lines();
            for (int line = 0; line < lines.size(); line++) {
                out.append(line > 0 ? "," : "").append("\n      ");
                quote(out, slug(lines.get(line)[0])).append(": ");
                quote(out, lines.get(line)[1]);
            }
            out.append(lines.isEmpty() ? "}" : "\n    }");
        }
        out.append(sections.isEmpty() ? "}," : "\n  },");
        out.append("\n  \"problems\": [");
        for (int i = 0; i < problems.size(); i++) {
            out.append(i > 0 ? "," : "").append("\n    ");
            quote(out, problems.get(i));
        }
        out.append(problems.isEmpty() ? "]" : "\n  ]").append("\n}\n");
        return out.toString();
    }

    /**
     * A key a consumer can index without quoting it.
     *
     * <p>Lower case, and everything that is not a letter or a digit becomes a
     * single underscore. Nothing here is reversible and nothing needs to be:
     * the human label is in the text report, which is the one people read.
     */
    static String slug(String key) {
        StringBuilder slug = new StringBuilder(key.length()); // seclume-allow: a label
        boolean underscore = false;
        for (int i = 0; i < key.length(); i++) {
            char c = Character.toLowerCase(key.charAt(i));
            if (Character.isLetterOrDigit(c)) {
                slug.append(c);
                underscore = false;
            } else if (!underscore && !slug.isEmpty()) {
                slug.append('_');
                underscore = true;
            }
        }
        while (!slug.isEmpty() && slug.charAt(slug.length() - 1) == '_') {
            slug.setLength(slug.length() - 1);
        }
        return slug.isEmpty() ? "_" : slug.toString();
    }

    /**
     * A JSON string, escaped as RFC 8259 requires.
     *
     * <p>The control characters matter more than they look: a server's message
     * arrives here verbatim, and one that contains a newline or a quote would
     * otherwise produce a document that parses into something else or not at
     * all.
     */
    private static StringBuilder quote(StringBuilder out, String value) {
        out.append('\"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append('\"');
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
