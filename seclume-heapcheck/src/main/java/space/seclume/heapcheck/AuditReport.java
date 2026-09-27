package space.seclume.heapcheck;

import java.time.Instant;
import java.util.List;
import java.util.Locale;

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
 */
record AuditReport(Instant checkedAt, String host, Target target, Dump dump,
                   List<SecretResult> secrets) {

    /** The version of this tool, as the jar says, or "development". */
    static String toolVersion() {
        String version = AuditReport.class.getPackage().getImplementationVersion();
        return version == null ? "development" : version;
    }

    /** A process that was dumped for the check, or a dump that was given. */
    record Target(String pid, ProcessHeap.Jvm jvm, String dumpFile) {
        String describe() {
            return pid != null ? "process " + pid : "heap dump " + dumpFile;
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

    boolean clean() {
        return secrets.stream().noneMatch(SecretResult::found);
    }

    // ---- JSON ------------------------------------------------------------------------

    String json() {
        StringBuilder out = new StringBuilder(1024);
        out.append("{\n");
        field(out, 1, "tool", "seclume-heapcheck " + toolVersion()).append(",\n");
        field(out, 1, "checkedAt", checkedAt.toString()).append(",\n");
        field(out, 1, "host", host).append(",\n");
        field(out, 1, "verdict", clean() ? "NOT_FOUND" : "FOUND").append(",\n");
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
                        .append(", \"length\": ").append(finding.length()).append('}');
            }
            out.append(secret.findings().isEmpty() ? "]\n" : "\n" + "      ]\n");
            indent(out, 2).append('}');
        }
        out.append(secrets.isEmpty() ? "]\n" : "\n  ]\n");
        out.append("}\n");
        return out.toString();
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
        row(out, "Result", clean()
                ? "None of the " + secrets.size() + " secret(s) is in the heap."
                : secrets.stream().filter(SecretResult::found).count() + " of "
                        + secrets.size() + " secret(s) are in the heap.");
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
            out.append("| Where | Encoding | Position | Length |\n|---|---|---|---|\n");
            for (HeapDumpScanner.Finding finding : secret.findings()) {
                out.append("| ").append(cell(finding.source())).append(" | ")
                        .append(finding.encoding()).append(" | ").append(finding.position())
                        .append(" | ").append(finding.length()).append(" |\n");
            }
            out.append('\n');
        }

        out.append("## Method\n\n");
        out.append("- The dump was searched twice: **raw**, over every byte of the file (what "
                + "`strings | grep` finds, including memory no object owns any more), and "
                + "**structured**, over every `byte[]` and `char[]` in the heap (what a heap " // seclume-allow: report text naming array types
                + "analyser finds).\n");
        out.append("- Text secrets were looked for as UTF-8, UTF-16BE, UTF-16LE and Base64; "
                + "binary ones as they are and as Base64.\n");
        if (target.pid() != null) {
            out.append("- The dump included unreachable objects (`live=false`): what an "
                    + "attacker gets from the file, whether or not it was still in use.\n");
        }
        out.append("- This report names secrets only by the file they were read from. It "
                + "holds neither a secret nor a hash of one.\n\n");

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
        return out.toString();
    }

    private static void row(StringBuilder out, String name, String value) {
        out.append("| ").append(name).append(" | ").append(cell(value)).append(" |\n");
    }

    private static String cell(String text) {
        return text.replace("|", "\\|").replace("\n", " ");
    }
}
