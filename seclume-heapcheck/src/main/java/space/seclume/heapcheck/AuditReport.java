package space.seclume.heapcheck;

import space.seclume.heapdump.Discovery;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import space.seclume.tck.HeapDumpScanner;

/**
 * What a check found, written down for somebody who was not there - an
 * auditor, a security team, the ticket for a PCI DSS or DORA control.
 *
 * <p>It names every secret by the file it came from and says where it was
 * found, in which encoding and how long the match was. It never holds the
 * secret, and not a hash of it either: a password's hash in a report is a
 * password waiting for a dictionary.
 *
 * @param checkedAt when the dump was searched
 * @param host      the machine the check ran on
 * @param target    what was examined - a process, or a dump file
 * @param dump      the dump that was searched
 * @param secrets   one result per secret, in the order given
 * @param discovery what {@code --discover} found without being told what to
 *                  look for, or {@code null} when it was not asked for
 * @param heldBy    for an offset in the dump file, what holds it - a field, a
 *                  static, an array, or "unreferenced" ({@link Attribution});
 *                  empty when that was not worked out
 */
record AuditReport(Instant checkedAt, String host, Target target, Dump dump,
                   List<SecretResult> secrets, Discovery.Result discovery,
                   Map<Long, String> heldBy) {

    AuditReport(Instant checkedAt, String host, Target target, Dump dump,
                List<SecretResult> secrets) {
        this(checkedAt, host, target, dump, secrets, null, Map.of());
    }

    AuditReport(Instant checkedAt, String host, Target target, Dump dump,
                List<SecretResult> secrets, Discovery.Result discovery) {
        this(checkedAt, host, target, dump, secrets, discovery, Map.of());
    }

    /** What holds the raw finding at {@code position}, or {@code null}. */
    String holderAt(long position) {
        return heldBy.get(position);
    }

    /** The distinct holders of a secret's raw findings, in the order met. */
    List<String> holders(SecretResult secret) {
        return secret.findings().stream()
                .filter(finding -> "raw file".equals(finding.source()))
                .map(finding -> holderAt(finding.position()))
                .filter(java.util.Objects::nonNull).distinct().toList();
    }

    /** The distinct holders of one discovered value, in the order met. */
    List<String> holders(Discovery.Found found) {
        return found.occurrences().stream().map(at -> holderAt(at.position()))
                .filter(java.util.Objects::nonNull).distinct().toList();
    }

    private static String heldText(List<String> holders) {
        return holders.isEmpty() ? "" : " Held by: " + String.join("; ", holders) + ".";
    }

    /** The version of this tool, as the jar says, or "development". */
    static String toolVersion() {
        String version = AuditReport.class.getPackage().getImplementationVersion();
        return version == null ? "development" : version;
    }

    /** A process that was dumped for the check, or a dump that was given. */
    record Target(String pid, ProcessHeap.Jvm jvm, String dumpFile) {
        String describe() {
            return pid != null ? "process " + pid
                    : (dumpFile.endsWith(".jfr") ? "recording " : "heap dump ") + dumpFile;
        }
    }

    /** The dump: how big, what its SHA-256 was - so it can be told apart later. */
    record Dump(long bytes, String sha256, boolean kept) {
    }

    /** One secret: where it came from, what it is, and every place it was found. */
    record SecretResult(String source, boolean binary, List<HeapDumpScanner.Finding> findings) {
        boolean found() {
            return !findings.isEmpty();
        }
    }

    /** Nothing named was found and nothing was discovered. */
    boolean clean() {
        return secretsClean() && (discovery == null || discovery.clean());
    }

    /** None of the named secrets was found - what {@code verdict} has always meant. */
    boolean secretsClean() {
        return secrets.stream().noneMatch(SecretResult::found);
    }

    private List<Discovery.Found> discovered() {
        return discovery == null ? List.of() : discovery.found();
    }

    private List<Discovery.Detector> discoveredDetectors() {
        return discovered().stream().map(Discovery.Found::detector).distinct().toList();
    }

    private static String ruleId(Discovery.Detector detector) {
        return "SECLUME-HEAP-DISCOVER-" + detector.id().toUpperCase(Locale.ROOT);
    }

    /** One logical result per secret, independent of unstable heap addresses. */
    String sarif() {
        StringBuilder out = new StringBuilder("""
                {
                  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                  "version": "2.1.0",
                  "runs": [{
                    "tool": {"driver": {"name": "seclume-heapcheck", "rules": [{
                      "id": "SECLUME-HEAP-001",
                      "shortDescription": {"text": "Credential found in a JVM heap dump"},
                      "help": {"text": "Keep credentials in native memory throughout their lifecycle. Repeat the check after login, rotation and under load."},
                      "defaultConfiguration": {"level": "error"}
                    }""");
        for (Discovery.Detector detector : discoveredDetectors()) {
            out.append(", {\"id\": ").append(quote(ruleId(detector)))
                    .append(", \"shortDescription\": {\"text\": ")
                    .append(quote("Credential of a known shape found in a JVM heap dump: "
                            + detector.name()))
                    .append("}, \"help\": {\"text\": ").append(quote(detector.advice()))
                    .append("}, \"defaultConfiguration\": {\"level\": \"error\"}}");
        }
        out.append("""
                ]}},
                    "invocations": [{"executionSuccessful": true}],
                    "results": [
                """);
        boolean first = true;
        for (SecretResult secret : secrets) {
            if (!secret.found()) continue;
            if (!first) out.append(",\n");
            first = false;
            out.append("      {\"ruleId\": \"SECLUME-HEAP-001\", \"level\": \"error\",")
                    .append("\"message\": {\"text\": ")
                    .append(quote("Credential from " + secret.source() + " was found in the heap dump."
                            + heldText(holders(secret))))
                    .append("}, \"locations\": [{\"logicalLocations\": [{\"fullyQualifiedName\": ")
                    .append(quote(secret.source())).append("}]}]}");
        }
        // One result per distinct value: another address in the heap is not
        // a finding of its own, a second token is.
        for (Discovery.Found found : discovered()) {
            if (!first) out.append(",\n");
            first = false;
            out.append("      {\"ruleId\": ").append(quote(ruleId(found.detector())))
                    .append(", \"level\": \"error\", \"message\": {\"text\": ")
                    .append(quote("A " + found.detector().name() + " (value #" + found.value()
                            + ") was found " + found.count() + " time(s) in the heap dump."
                            + heldText(holders(found))))
                    .append("}, \"locations\": [{\"logicalLocations\": [{\"fullyQualifiedName\": ")
                    .append(quote("heap dump/" + found.detector().id() + "/#" + found.value()))
                    .append("}]}]}");
        }
        return out.append("\n    ]\n  }]\n}\n").toString();
    }

    // ---- JSON ------------------------------------------------------------------------

    String json() {
        StringBuilder out = new StringBuilder(1024);
        out.append("{\n");
        field(out, 1, "tool", "seclume-heapcheck " + toolVersion()).append(",\n");
        field(out, 1, "checkedAt", checkedAt.toString()).append(",\n");
        field(out, 1, "host", host).append(",\n");
        field(out, 1, "verdict", secretsClean() ? "NOT_FOUND" : "FOUND").append(",\n");
        indent(out, 1).append("\"target\": {\n");
        if (target.pid() != null) {
            field(out, 2, "pid", target.pid()).append(",\n");
            field(out, 2, "javaVersion", target.jvm().version()).append(",\n");
            field(out, 2, "javaVendor", target.jvm().vendor()).append(",\n");
            field(out, 2, "main", target.jvm().main()).append('\n');
        } else {
            field(out, 2, "dumpFile", target.dumpFile()).append('\n');
        }
        indent(out, 1).append("},\n");
        indent(out, 1).append("\"dump\": {\n");
        indent(out, 2).append("\"bytes\": ").append(dump.bytes()).append(",\n");
        field(out, 2, "sha256", dump.sha256()).append(",\n");
        indent(out, 2).append("\"kept\": ").append(dump.kept()).append('\n');
        indent(out, 1).append("},\n");
        indent(out, 1).append("\"method\": {\n");
        field(out, 2, "raw", "every byte of the dump file").append(",\n");
        field(out, 2, "structured", "every byte[] and char[] in the heap").append(",\n");
        field(out, 2, "textEncodings", "UTF-8, UTF-16BE, UTF-16LE, Base64").append(",\n");
        field(out, 2, "binaryEncodings", "bytes, Base64").append('\n');
        indent(out, 1).append("},\n");
        indent(out, 1).append("\"secrets\": [");
        for (int i = 0; i < secrets.size(); i++) {
            SecretResult secret = secrets.get(i);
            out.append(i == 0 ? "\n" : ",\n");
            indent(out, 2).append("{\n");
            field(out, 3, "source", secret.source()).append(",\n");
            field(out, 3, "kind", secret.binary() ? "binary" : "text").append(",\n");
            field(out, 3, "result", secret.found() ? "FOUND" : "NOT_FOUND").append(",\n");
            indent(out, 3).append("\"findings\": [");
            for (int j = 0; j < secret.findings().size(); j++) {
                HeapDumpScanner.Finding finding = secret.findings().get(j);
                out.append(j == 0 ? "\n" : ",\n");
                indent(out, 4).append("{\"where\": ").append(quote(finding.source()))
                        .append(", \"encoding\": ").append(quote(finding.encoding()))
                        .append(", \"position\": ").append(finding.position())
                        .append(", \"length\": ").append(finding.length());
                String holder = "raw file".equals(finding.source())
                        ? holderAt(finding.position()) : null;
                if (holder != null) {
                    out.append(", \"heldBy\": ").append(quote(holder));
                }
                out.append('}');
            }
            out.append(secret.findings().isEmpty() ? "]\n" : "\n" + "      ]\n");
            indent(out, 2).append('}');
        }
        out.append(secrets.isEmpty() ? "]" : "\n  ]");
        if (discovery != null) {
            out.append(",\n");
            discoveryJson(out);
        }
        out.append("\n}\n");
        return out.toString();
    }

    /**
     * {@code discovery}, with a verdict of its own: {@code verdict} keeps
     * meaning what it always meant - the named secrets - for whatever already
     * reads it, {@code compare.py} among them.
     */
    private void discoveryJson(StringBuilder out) {
        indent(out, 1).append("\"discovery\": {\n");
        field(out, 2, "verdict", discovery.clean() ? "NOT_FOUND" : "FOUND").append(",\n");
        List<String> ran = Discovery.ids().stream()
                .filter(id -> !discovery.ignored().contains(id)).toList();
        indent(out, 2).append("\"detectors\": ").append(list(ran)).append(",\n");
        indent(out, 2).append("\"ignored\": ")
                .append(list(discovery.ignored().stream().sorted().toList())).append(",\n");
        indent(out, 2).append("\"found\": [");
        List<Discovery.Found> found = discovery.found();
        for (int i = 0; i < found.size(); i++) {
            Discovery.Found entry = found.get(i);
            out.append(i == 0 ? "\n" : ",\n");
            indent(out, 3).append("{\n");
            field(out, 4, "detector", entry.detector().id()).append(",\n");
            field(out, 4, "name", entry.detector().name()).append(",\n");
            indent(out, 4).append("\"value\": ").append(entry.value()).append(",\n");
            indent(out, 4).append("\"occurrences\": ").append(entry.count()).append(",\n");
            indent(out, 4).append("\"findings\": [");
            for (int j = 0; j < entry.occurrences().size(); j++) {
                Discovery.Occurrence at = entry.occurrences().get(j);
                out.append(j == 0 ? "\n" : ",\n");
                indent(out, 5).append("{\"where\": \"raw file\", \"encoding\": ")
                        .append(quote(at.encoding())).append(", \"position\": ")
                        .append(at.position()).append(", \"length\": ").append(at.length());
                if (holderAt(at.position()) != null) {
                    out.append(", \"heldBy\": ").append(quote(holderAt(at.position())));
                }
                out.append('}');
            }
            out.append(entry.occurrences().isEmpty() ? "]\n" : "\n");
            if (!entry.occurrences().isEmpty()) {
                indent(out, 4).append("]\n");
            }
            indent(out, 3).append('}');
        }
        out.append(found.isEmpty() ? "]" : "\n    ]");
        if (!discovery.uncounted().isEmpty()) {
            out.append(",\n");
            indent(out, 2).append("\"moreValuesThanKept\": {");
            List<String> ids = discovery.uncounted().keySet().stream().sorted().toList();
            for (int i = 0; i < ids.size(); i++) {
                out.append(i == 0 ? "" : ", ").append(quote(ids.get(i))).append(": ")
                        .append(discovery.uncounted().get(ids.get(i)));
            }
            out.append('}');
        }
        out.append('\n');
        indent(out, 1).append('}');
    }

    private static String list(List<String> values) {
        StringBuilder out = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            out.append(i == 0 ? "" : ", ").append(quote(values.get(i)));
        }
        return out.append(']').toString();
    }

    private static StringBuilder field(StringBuilder out, int depth, String name, String value) {
        return indent(out, depth).append(quote(name)).append(": ").append(quote(value));
    }

    private static StringBuilder indent(StringBuilder out, int depth) {
        return out.append("  ".repeat(depth));
    }

    static String quote(String text) {
        StringBuilder out = new StringBuilder(text.length() + 2).append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append('"').toString();
    }

    // ---- Markdown --------------------------------------------------------------------

    String markdown() {
        StringBuilder out = new StringBuilder(2048);
        out.append("# Heap check: ").append(clean() ? "no secret found" : "SECRET FOUND")
                .append("\n\n");
        out.append("| | |\n|---|---|\n");
        if (!secrets.isEmpty()) {
            row(out, "Result", secretsClean()
                    ? "None of the " + secrets.size() + " secret(s) is in the heap."
                    : secrets.stream().filter(SecretResult::found).count() + " of "
                            + secrets.size() + " secret(s) are in the heap.");
        }
        if (discovery != null) {
            row(out, "Discovery", discovery.clean()
                    ? "Nothing of a known credential shape is in the heap."
                    : discovery.found().size() + " credential(s) of a known shape, found "
                            + "without being named.");
        }
        row(out, "Examined", target.describe());
        if (target.pid() != null) {
            row(out, "JVM", target.jvm().version() + " (" + target.jvm().vendor() + ")");
            row(out, "Runs", target.jvm().main().isEmpty() ? "-" : "`" + target.jvm().main() + "`");
        }
        row(out, "Checked at", checkedAt.toString());
        row(out, "On host", host);
        row(out, "Dump", dump.bytes() + " bytes, SHA-256 `" + dump.sha256() + "`"
                + (dump.kept() ? ", kept" : ", deleted after the check"));
        row(out, "Tool", "seclume-heapcheck " + toolVersion());
        out.append('\n');

        if (!secrets.isEmpty()) {
            secretsMarkdown(out);
        }
        if (discovery != null) {
            discoveryMarkdown(out);
        }
        methodMarkdown(out);
        return out.toString();
    }

    private void secretsMarkdown(StringBuilder out) {
        out.append("## Secrets\n\n");
        out.append("| Source | Kind | Result | Findings |\n|---|---|---|---|\n");
        for (SecretResult secret : secrets) {
            out.append("| `").append(cell(secret.source())).append("` | ")
                    .append(secret.binary() ? "binary" : "text").append(" | ")
                    .append(secret.found() ? "**FOUND**" : "not found").append(" | ")
                    .append(secret.findings().size()).append(" |\n");
        }
        out.append('\n');
        for (SecretResult secret : secrets) {
            if (!secret.found()) {
                continue;
            }
            out.append("### `").append(cell(secret.source())).append("`\n\n");
            out.append("| Where | Encoding | Position | Length | Held by |\n"
                    + "|---|---|---|---|---|\n");
            for (HeapDumpScanner.Finding finding : secret.findings()) {
                String holder = "raw file".equals(finding.source())
                        ? holderAt(finding.position()) : null;
                out.append("| ").append(cell(finding.source())).append(" | ")
                        .append(finding.encoding()).append(" | ").append(finding.position())
                        .append(" | ").append(finding.length()).append(" | ")
                        .append(holder == null ? "-" : "`" + cell(holder) + "`").append(" |\n");
            }
            out.append('\n');
        }
    }

    private void discoveryMarkdown(StringBuilder out) {
        out.append("## Found without being named\n\n");
        if (discovery.clean()) {
            out.append("No credential of a known shape is in the dump.\n\n");
        } else {
            out.append("| Detector | Value | Occurrences | First at | Held by |\n"
                    + "|---|---|---|---|---|\n");
            for (Discovery.Found found : discovery.found()) {
                Discovery.Occurrence at = found.occurrences().isEmpty() ? null
                        : found.occurrences().get(0);
                List<String> holders = holders(found);
                out.append("| ").append(cell(found.detector().name())).append(" (`")
                        .append(found.detector().id()).append("`) | #").append(found.value())
                        .append(" | ").append(found.count()).append(" | ")
                        .append(at == null ? "-" : at.encoding() + " at " + at.position())
                        .append(" | ").append(holders.isEmpty() ? "-"
                                : "`" + cell(String.join("`, `", holders)) + "`")
                        .append(" |\n");
            }
            out.append('\n');
            for (Discovery.Detector detector : discoveredDetectors()) {
                out.append("- **").append(detector.name()).append("**: ")
                        .append(detector.advice()).append('\n');
            }
            out.append('\n');
        }
        if (!discovery.uncounted().isEmpty()) {
            out.append("More distinct values than the report keeps apart: ")
                    .append(new java.util.TreeMap<>(discovery.uncounted())).append(".\n\n");
        }
        if (!discovery.ignored().isEmpty()) {
            out.append("Left out on request: ")
                    .append(String.join(", ", discovery.ignored().stream().sorted().toList()))
                    .append(".\n\n");
        }
        out.append("Values are numbered in the order they were met; the numbers mean nothing "
                + "outside this report. A match has the shape of a credential - it can be a "
                + "test key, an expired token or an example a library carries. A credential "
                + "without a recognisable shape, such as a plain password, is not found this "
                + "way: name it with `--secret-file`.\n\n");
    }

    private void methodMarkdown(StringBuilder out) {
        out.append("## Method\n\n");
        out.append("- The dump was searched twice: **raw**, over every byte of the file (what "
                + "`strings | grep` finds, including memory no object owns any more), and "
                + "**structured**, over every `byte[]` and `char[]` in the heap (what a heap " // seclume-allow: report text naming array types
                + "analyser finds).\n");
        if (!secrets.isEmpty()) {
            out.append("- Text secrets were looked for as UTF-8, UTF-16BE, UTF-16LE and "
                    + "Base64; binary ones as they are and as Base64.\n");
        }
        if (discovery != null) {
            out.append("- For the discovery, every run of printable text in the file - as "
                    + "single bytes and as UTF-16 in both byte orders - was held against "
                    + Discovery.ids().size() + " credential shapes (`--list-detectors`).\n");
        }
        if (target.pid() != null) {
            out.append("- The dump included unreachable objects (`live=false`): what an "
                    + "attacker gets from the file, whether or not it was still in use.\n");
        }
        out.append("- This report names secrets only by the file they were read from, and "
                + "discovered ones by a number. It holds neither a secret nor a hash of one.\n\n");

        out.append("## What it shows\n\n");
        out.append("The state of the heap at the moment of the dump. A secret can reach "
                + "the heap later, and one that was there can have been overwritten "
                + "already; a check at the moments that matter - after the login, under "
                + "load, after a rotation - says more than one check.\n\n");
        out.append("It is evidence for controls on authentication data at rest - for "
                + "example PCI DSS v4.0 requirement 8.3.2 (authentication factors "
                + "unreadable in storage) and the ICT security requirements of DORA "
                + "article 9 - for the heap dumps this process writes: on "
                + "`OutOfMemoryError`, for a support case, in a crash.\n");
    }

    private static void row(StringBuilder out, String name, String value) {
        out.append("| ").append(name).append(" | ").append(cell(value)).append(" |\n");
    }

    private static String cell(String text) {
        return text.replace("|", "\\|").replace("\n", " ");
    }
}
