package space.seclume.audit;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Checks an access log: every line an entry, every entry's hash its own, every
 * {@code prev} the hash before it, the numbers without a gap, every checkpoint
 * signed by the expected key over the head it names.
 *
 * <p>Without the public key the chain is checked and the signatures are not -
 * which shows that the file is consistent, not that nobody rewrote it whole.
 */
public final class AccessLogVerifier {

    /**
     * What a check found.
     *
     * @param first       the first entry's number: 1, or later for a log that continues a
     *                    rotated one - whose first entries are then checked only against
     *                    the file that came before
     * @param entries     lines read
     * @param checkpoints checkpoints whose signature was checked and held
     * @param signedUpTo  the {@code seq} of the last checkpoint that held, 0 when none
     * @param head        the last entry's hash - to compare with a copy kept elsewhere
     * @param problems    each with its line number, in the order found; empty when the log holds
     */
    public record Result(long first, long entries, long checkpoints, long signedUpTo, String head,
            List<String> problems) {

        /** Whether nothing was found wrong. */
        public boolean holds() {
            return problems.isEmpty();
        }

        /** Entries after the last held checkpoint - written, but not yet vouched for. */
        public long unsigned() {
            return signedUpTo == 0 ? entries : first + entries - 1 - signedUpTo;
        }
    }

    private AccessLogVerifier() {
    }

    /**
     * Checks {@code file}; signatures against {@code publicKey} (DER
     * {@code SubjectPublicKeyInfo}), or not at all when it is {@code null}.
     */
    public static Result verify(Path file, byte[] publicKey) throws IOException {
        // seclume-allow: an access log holds facts, never a secret
        String text = Files.readString(file, StandardCharsets.ISO_8859_1);
        return verify(text, publicKey);
    }

    static Result verify(String text, byte[] publicKey) {
        List<String> problems = new ArrayList<>();
        PublicKey key = null;
        String expectedKey = null;
        if (publicKey != null) {
            try {
                key = publicKey(publicKey);
                expectedKey = AccessLog.fingerprint(publicKey);
            } catch (GeneralSecurityException e) {
                problems.add("the public key cannot be read: " + e.getMessage());
                return new Result(0, 0, 0, 0, AccessLog.ZERO, List.copyOf(problems));
            }
        }
        String prev = AccessLog.ZERO;
        long expectedSeq = 0;
        long entries = 0;
        long checkpoints = 0;
        long signedUpTo = 0;
        long first = 0;
        String[] lines = text.split("\n", -1);
        if (lines.length > 0 && !lines[lines.length - 1].isEmpty()) {
            problems.add("line " + lines.length + ": torn - the file does not end with a line break");
        }
        for (int i = 0; i < lines.length - 1; i++) {
            String line = lines[i];
            int number = i + 1;
            Map<String, String> fields = fields(line);
            if (fields == null) {
                problems.add("line " + number + ": not an access log entry");
                continue;
            }
            entries++;
            long seq;
            try {
                seq = Long.parseLong(fields.getOrDefault("seq", ""));
            } catch (NumberFormatException e) {
                problems.add("line " + number + ": no sequence number");
                continue;
            }
            if (i == 0) {
                first = seq;
                if (seq != 1) {
                    // A rotated log starts later; its first prev is the last of the one before.
                    expectedSeq = seq - 1;
                    prev = fields.getOrDefault("prev", AccessLog.ZERO);
                }
            }
            if (seq != expectedSeq + 1) {
                problems.add("line " + number + ": entry " + seq + " follows entry " + expectedSeq);
            }
            expectedSeq = seq;
            int hashAt = line.lastIndexOf(",\"hash\":\"");
            String hash = fields.get("hash");
            if (hashAt < 0 || hash == null || !line.endsWith("\"}")
                    || !line.substring(hashAt).equals(",\"hash\":\"" + hash + "\"}")) {
                problems.add("line " + number + ": the hash is not the last field");
                continue;
            }
            String computed = AccessLog.sha256(line.substring(0, hashAt) + "}");
            if (!computed.equals(hash)) {
                problems.add("line " + number + ": entry " + seq + " was changed - its hash does not match");
            }
            if (!prev.equals(fields.get("prev"))) {
                problems.add("line " + number + ": entry " + seq
                        + " does not follow the entry before it - one was removed or slipped in");
            }
            if ("checkpoint".equals(fields.get("event"))) {
                String head = fields.get("head");
                if (!prev.equals(head)) {
                    problems.add("line " + number + ": checkpoint " + seq + " names a head that is not "
                            + "the entry before it");
                } else if (key != null) {
                    String problem = signature(fields, seq, head, key, expectedKey);
                    if (problem == null) {
                        checkpoints++;
                        signedUpTo = seq;
                    } else {
                        problems.add("line " + number + ": checkpoint " + seq + " " + problem);
                    }
                }
            }
            prev = hash;
        }
        return new Result(first, entries, checkpoints, signedUpTo, prev, List.copyOf(problems));
    }

    private static String signature(Map<String, String> fields, long seq, String head, PublicKey key,
            String expectedKey) {
        if (!expectedKey.equals(fields.get("key"))) {
            return "is signed by another key (" + fields.get("key") + ")";
        }
        String algorithm = fields.getOrDefault("algorithm", "");
        if (!List.of("SHA256withECDSA", "SHA256withRSA", "Ed25519").contains(algorithm)) {
            return "names an algorithm this does not check: " + algorithm;
        }
        byte[] signature = unhex(fields.getOrDefault("signature", ""));
        if (signature == null) {
            return "has no readable signature";
        }
        try (Arena arena = Arena.ofConfined()) {
            byte[] message = AccessLog.signedMessage(arena, seq, head).toArray(ValueLayout.JAVA_BYTE);
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(key);
            verifier.update(message);
            return verifier.verify(signature) ? null : "has a signature that does not hold";
        } catch (GeneralSecurityException e) {
            return "has a signature that cannot be checked: " + e.getMessage();
        }
    }

    /** A DER public key, by its own algorithm. */
    static PublicKey publicKey(byte[] der) throws GeneralSecurityException {
        GeneralSecurityException last = null;
        for (String type : new String[] {"EC", "RSA", "Ed25519"}) {
            try {
                return KeyFactory.getInstance(type).generatePublic(new X509EncodedKeySpec(der));
            } catch (GeneralSecurityException e) {
                last = e;
            }
        }
        throw last;
    }

    private static byte[] unhex(String hex) {
        if (hex.isEmpty() || hex.length() % 2 != 0 || hex.length() > 4096) {
            return null;
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(2 * i), 16);
            int lo = Character.digit(hex.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) {
                return null;
            }
            out[i] = (byte) (hi << 4 | lo);
        }
        return out;
    }

    /**
     * A flat JSON object of strings and integers - what an entry is - as its
     * fields in order, numbers as their digits; {@code null} for anything else.
     */
    static Map<String, String> fields(String line) {
        Map<String, String> fields = new LinkedHashMap<>();
        int[] at = {0};
        if (!next(line, at, '{')) {
            return null;
        }
        if (peek(line, at) == '}') {
            at[0]++;
            return at[0] == line.length() ? fields : null;
        }
        while (true) {
            String key = string(line, at);
            if (key == null || !next(line, at, ':')) {
                return null;
            }
            String value;
            if (peek(line, at) == '"') {
                value = string(line, at);
            } else {
                int start = at[0];
                if (peek(line, at) == '-') {
                    at[0]++;
                }
                int digits = at[0];
                while (peek(line, at) >= '0' && peek(line, at) <= '9') {
                    at[0]++;
                }
                value = at[0] > digits && at[0] - start < 20 ? line.substring(start, at[0]) : null;
            }
            if (value == null || fields.put(key, value) != null) {
                return null;
            }
            char c = peek(line, at);
            at[0]++;
            if (c == '}') {
                return at[0] == line.length() ? fields : null;
            }
            if (c != ',') {
                return null;
            }
        }
    }

    private static boolean next(String line, int[] at, char c) {
        if (peek(line, at) != c) {
            return false;
        }
        at[0]++;
        return true;
    }

    private static char peek(String line, int[] at) {
        return at[0] < line.length() ? line.charAt(at[0]) : '\0';
    }

    private static String string(String line, int[] at) {
        if (!next(line, at, '"')) {
            return null;
        }
        StringBuilder out = new StringBuilder();
        while (at[0] < line.length()) {
            char c = line.charAt(at[0]++);
            if (c == '"') {
                return out.toString();
            }
            if (c < 0x20 || c > 0x7e) {
                return null;
            }
            if (c != '\\') {
                out.append(c);
                continue;
            }
            char e = peek(line, at);
            at[0]++;
            if (e == '"' || e == '\\') {
                out.append(e);
            } else if (e == 'u' && at[0] + 4 <= line.length()) {
                int code = 0;
                for (int i = 0; i < 4; i++) {
                    int d = Character.digit(line.charAt(at[0]++), 16);
                    if (d < 0) {
                        return null;
                    }
                    code = code * 16 + d;
                }
                out.append((char) code);
            } else {
                return null;
            }
        }
        return null;
    }
}
