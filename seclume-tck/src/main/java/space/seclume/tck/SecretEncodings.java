package space.seclume.tck;

import java.nio.charset.StandardCharsets;
import java.util.Base64; // seclume-allow: the searcher encodes the pattern it hunts for
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The byte patterns a secret can lie in, in a heap dump or any file - one list
 * for every searcher, so that the search and the check after a redaction look
 * for the same things.
 *
 * <p>The searcher holds what it hunts for: this runs in the process that
 * searches, never in the one examined.
 *
 * <p>Besides the secret as it is: its Base64 not only on its own but inside a
 * longer Base64 text, where it begins at any of three places in a group of
 * three bytes - {@code Authorization: Basic base64(user:password)} has the
 * password at whatever offset {@code user:} leaves it, and its Base64 there is
 * nothing like the password's own. That stretch is looked for: the groups
 * made of the secret's bytes alone, standard and URL-safe, when they are long
 * enough not to turn up anywhere by chance. And percent-encoded, as
 * {@code URLEncoder} and as RFC 3986 strictly write it, hex digits in either
 * case, and JSON-escaped.
 */
public final class SecretEncodings {

    /** Base64 shorter than this is looked for only whole: a few characters are found anywhere. */
    static final int SHORTEST_EMBEDDED = 8;

    private SecretEncodings() {
    }

    /** A secret that is text: label to pattern, the plain encodings first. */
    public static Map<String, byte[]> ofText(String secret) {
        Map<String, byte[]> patterns = new LinkedHashMap<>();
        byte[] utf8 = secret.getBytes(StandardCharsets.UTF_8); // seclume-allow: the searcher needs the pattern it hunts for
        patterns.put("UTF-8", utf8);
        patterns.put("UTF-16BE", secret.getBytes(StandardCharsets.UTF_16BE)); // seclume-allow: the searcher needs the pattern it hunts for
        patterns.put("UTF-16LE", secret.getBytes(StandardCharsets.UTF_16LE)); // seclume-allow: the searcher needs the pattern it hunts for
        if (secret.chars().allMatch(c -> c <= 0xff) && secret.chars().anyMatch(c -> c > 0x7f)) {
            // A compact String's own bytes: "Grüße" is 47 72 FC DF 65 there.
            patterns.put("ISO-8859-1", secret.getBytes(StandardCharsets.ISO_8859_1)); // seclume-allow: the searcher needs the pattern it hunts for
        }
        base64(utf8, patterns);
        String percent = percent(utf8, false);
        String form = percent(utf8, true);
        for (String encoded : new String[] {percent, form}) {
            if (!encoded.equals(secret)) {
                put(patterns, "percent-encoded", encoded);
                put(patterns, "percent-encoded", lowerHex(encoded));
            }
        }
        String json = json(secret);
        if (!json.equals(secret)) {
            patterns.put("JSON-escaped", json.getBytes(StandardCharsets.UTF_8)); // seclume-allow: the searcher needs the pattern it hunts for
        }
        return patterns;
    }

    /** A secret that is bytes - a key: as it is, and its Base64 alone and inside a longer one. */
    public static Map<String, byte[]> ofBytes(byte[] secret) {
        Map<String, byte[]> patterns = new LinkedHashMap<>();
        patterns.put("bytes", secret.clone());
        base64(secret, patterns);
        return patterns;
    }

    private static void base64(byte[] secret, Map<String, byte[]> patterns) {
        patterns.put("Base64", Base64.getEncoder().encode(secret)); // seclume-allow: the searcher needs the pattern it hunts for
        for (int offset = 0; offset < 3; offset++) {
            byte[] shifted = new byte[offset + secret.length];
            System.arraycopy(secret, 0, shifted, offset, secret.length);
            String encoded = Base64.getEncoder().encodeToString(shifted); // seclume-allow: the searcher needs the pattern it hunts for
            int from = (offset + 2) / 3 * 4;                  // the first group of the secret's bytes alone
            int to = (offset + secret.length) / 3 * 4;        // after the last whole one
            if (to - from < SHORTEST_EMBEDDED) {
                continue;
            }
            String middle = encoded.substring(from, to);
            put(patterns, "Base64 inside", middle);
            put(patterns, "Base64 inside", middle.replace('+', '-').replace('/', '_'));
        }
    }

    private static void put(Map<String, byte[]> patterns, String label, String ascii) {
        byte[] bytes = ascii.getBytes(StandardCharsets.US_ASCII); // seclume-allow: the searcher needs the pattern it hunts for
        for (byte[] known : patterns.values()) {
            if (java.util.Arrays.equals(known, bytes)) {
                return;
            }
        }
        String name = label;
        for (int n = 2; patterns.containsKey(name); n++) {
            name = label + " " + n;
        }
        patterns.put(name, bytes);
    }

    /** RFC 3986's unreserved characters kept, or - {@code form} - {@code URLEncoder}'s way. */
    static String percent(byte[] utf8, boolean form) {
        StringBuilder out = new StringBuilder(); // seclume-allow: the searcher needs the pattern it hunts for
        for (byte value : utf8) {
            int b = value & 0xff;
            boolean kept = (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
                    || b == '-' || b == '.' || b == '_' || (form ? b == '*' : b == '~');
            if (kept) {
                out.append((char) b);
            } else if (form && b == ' ') {
                out.append('+');
            } else {
                out.append('%').append(Character.toUpperCase(Character.forDigit(b >> 4, 16)))
                        .append(Character.toUpperCase(Character.forDigit(b & 0xf, 16)));
            }
        }
        return out.toString();
    }

    private static String lowerHex(String percent) {
        StringBuilder out = new StringBuilder(percent); // seclume-allow: the searcher needs the pattern it hunts for
        for (int i = 0; i + 2 < out.length(); i++) {
            if (out.charAt(i) == '%') {
                out.setCharAt(i + 1, Character.toLowerCase(out.charAt(i + 1)));
                out.setCharAt(i + 2, Character.toLowerCase(out.charAt(i + 2)));
                i += 2;
            }
        }
        return out.toString();
    }

    private static String json(String text) {
        StringBuilder out = new StringBuilder(); // seclume-allow: the searcher needs the pattern it hunts for
        for (char c : text.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> out.append(c);
            }
        }
        return out.toString();
    }
}
