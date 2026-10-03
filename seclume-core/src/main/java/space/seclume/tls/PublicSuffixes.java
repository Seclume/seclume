package space.seclume.tls;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/** Public suffix boundaries for certificate wildcards, including private hosting domains. */
final class PublicSuffixes {
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
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            for (String line; (line = reader.readLine()) != null; ) {
                String rule = line.strip();
                if (rule.isEmpty() || rule.startsWith("//")) {
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
        if (exact.isEmpty()) {
            return null;
        }
        return new Rules(Set.copyOf(exact), Set.copyOf(wildcards), Set.copyOf(exceptions));
    }
}
