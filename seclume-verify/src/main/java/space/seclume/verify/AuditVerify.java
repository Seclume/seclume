package space.seclume.verify;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import space.seclume.audit.AccessLogVerifier;

/**
 * {@code --audit-verify <log.jsonl>... [public-key]}: an access log checked -
 * chain and, with the key (DER or PEM {@code PUBLIC KEY}), signatures. More
 * than one log file is one log in their order: a rotated file and the one it
 * continues. Exit 0 when it holds, 1 when it does not, 2 when it cannot be
 * read.
 */
final class AuditVerify {

    private AuditVerify() {
    }

    static int run(List<String> arguments, PrintStream out, PrintStream err) {
        if (arguments.isEmpty()) {
            err.println("usage: java -jar seclume-verify.jar --audit-verify <log.jsonl>... "
                    + "[public-key.pem|.der]");
            return 2;
        }
        try {
            int logs = arguments.size();
            byte[] key = null;
            if (logs > 1 && isKey(Path.of(arguments.get(logs - 1)))) {
                key = publicKey(Path.of(arguments.get(logs - 1)));
                logs--;
            }
            List<Path> files = arguments.subList(0, logs).stream().map(Path::of).toList();
            AccessLogVerifier.Result result = AccessLogVerifier.verify(files, key);
            out.println(result.holds() ? "the access log holds" : "the access log does NOT hold");
            out.println("  entries      " + result.entries() + (result.first() > 1
                    ? " (from entry " + result.first() + ")" : ""));
            if (result.first() > 1) {
                // A rotated log and one whose first entries were cut off look
                // the same: the chain cannot say which, the file before can.
                out.println("  the first " + (result.first() - 1) + " entries are not here: a "
                        + "rotated log - or one cut at the start. Give the file before it too, "
                        + "in order: --audit-verify old.jsonl " + files.get(0).getFileName());
            }
            if (key == null) {
                out.println("  signatures   not checked - no public key given");
            } else {
                out.println("  checkpoints  " + result.checkpoints() + " signed and holding, the last at entry "
                        + result.signedUpTo() + "; " + result.unsigned() + " entries after it");
            }
            out.println("  head         " + result.head()
                    + "  (compare with the head a copy elsewhere - an exporter, a SIEM - last received)");
            for (String problem : result.problems()) {
                out.println("  " + problem);
            }
            return result.holds() ? 0 : 1;
        } catch (IOException | IllegalArgumentException e) {
            err.println("the access log cannot be checked: " + e.getMessage());
            return 2;
        }
    }

    /** Whether {@code file} is a public key, not a log: it does not begin as an entry does. */
    private static boolean isKey(Path file) throws IOException {
        try (java.io.InputStream in = Files.newInputStream(file)) {
            int first = in.read();
            return first >= 0 && first != '{';
        }
    }

    /** DER, or PEM between {@code -----BEGIN PUBLIC KEY-----} lines. A public key is no secret. */
    static byte[] publicKey(Path file) throws IOException {
        // seclume-allow: a public key, not a secret
        byte[] bytes = Files.readAllBytes(file);
        String text = new String(bytes, StandardCharsets.US_ASCII); // seclume-allow: a public key
        int begin = text.indexOf("-----BEGIN PUBLIC KEY-----");
        if (begin < 0) {
            return bytes;
        }
        int end = text.indexOf("-----END PUBLIC KEY-----", begin);
        if (end < 0) {
            throw new IllegalArgumentException(file + ": a PEM public key without its END line");
        }
        String body = text.substring(begin + "-----BEGIN PUBLIC KEY-----".length(), end).replaceAll("\\s", "");
        // seclume-allow: a public key, not a secret
        return java.util.Base64.getDecoder().decode(body);
    }
}
