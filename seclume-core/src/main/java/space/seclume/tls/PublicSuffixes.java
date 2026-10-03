package space.seclume.tls;

import java.io.IOException;
import java.io.InputStream;
import java.net.IDN;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/** ICANN public suffix boundaries for certificate wildcards. */
final class PublicSuffixes {
    /** The pinned list is about 330 KiB; refuse unexpectedly large replacement resources. */
    private static final int MAX_LIST_BYTES = 1024 * 1024;

    private PublicSuffixes() {
    }

    /** Unknown one-label suffixes are public too, as required by the PSL default rule. */
    static boolean isPublicSuffix(String domain) {
        final String ascii;
        try {
            ascii = canonical(domain);
        } catch (IllegalArgumentException invalid) {
            return true; // An invalid wildcard base cannot establish a registrable domain.
        }
        if (ascii.isEmpty() || ascii.startsWith(".") || ascii.endsWith(".") || ascii.contains("..")) {
            return true;
        }
        Rules rules = Holder.RULES;
        if (rules == null) {
            return true; // Missing or unreadable data must never widen certificate acceptance.
        }
        // Exceptions prevail over every other rule, including rules on a descendant.
        for (String suffix = ascii; ; ) {
            if (rules.exceptions.contains(suffix)) {
                return false;
            }
            int dot = suffix.indexOf('.');
            if (dot < 0) {
                break;
            }
            suffix = suffix.substring(dot + 1);
        }
        int dot = ascii.indexOf('.');
        return dot < 0 || rules.exact.contains(ascii)
                || rules.wildcards.contains(ascii.substring(dot + 1));
    }

    private static String canonical(String domain) {
        return IDN.toASCII(domain, IDN.USE_STD3_ASCII_RULES | IDN.ALLOW_UNASSIGNED)
                .toLowerCase(Locale.ROOT);
    }

    /** Loaded only when a wildcard is checked; no DNS or runtime network access. */
    private static final class Holder {
        private static final Rules RULES = load();
    }

    private record Rules(Set<String> exact, Set<String> wildcards, Set<String> exceptions) {
    }

    private static Rules load() {
        InputStream stream = PublicSuffixes.class.getResourceAsStream("public_suffix_list.dat");
        if (stream == null) {
            return null;
        }
        Set<String> exact = new HashSet<>();
        Set<String> wildcards = new HashSet<>();
        Set<String> exceptions = new HashSet<>();
        boolean inIcann = false;
        boolean complete = false;
        try (stream) {
            byte[] bytes = stream.readNBytes(MAX_LIST_BYTES + 1);
            if (bytes.length > MAX_LIST_BYTES) {
                return null;
            }
            // Only the fixed public resource is decoded. Invalid UTF-8 cannot silently lose rules.
            String data = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
            for (var lines = data.lines().iterator(); lines.hasNext(); ) {
                String rule = lines.next().strip();
                if (rule.equals("// ===BEGIN ICANN DOMAINS===")) {
                    inIcann = true;
                    continue;
                }
                if (rule.equals("// ===END ICANN DOMAINS===")) {
                    complete = inIcann;
                    break;
                }
                if (!inIcann || rule.isEmpty() || rule.startsWith("//")) {
                    continue;
                }
                // The PSL format permits a comment after whitespace following a rule.
                for (int i = 0; i < rule.length(); i++) {
                    if (Character.isWhitespace(rule.charAt(i))) {
                        rule = rule.substring(0, i);
                        break;
                    }
                }
                if (rule.startsWith("!")) {
                    exceptions.add(canonical(rule.substring(1)));
                } else if (rule.startsWith("*.")) {
                    wildcards.add(canonical(rule.substring(2)));
                } else {
                    exact.add(canonical(rule));
                }
            }
        } catch (IOException | IllegalArgumentException unreadable) {
            return null;
        }
        if (!complete || exact.isEmpty()) {
            return null;
        }
        return new Rules(Set.copyOf(exact), Set.copyOf(wildcards), Set.copyOf(exceptions));
    }
}
