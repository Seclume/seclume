package space.seclume;

import java.util.Arrays;

/**
 * Java source as the source checks read it: code, not lines.
 *
 * <p>Comments and literals - strings, characters, text blocks - are taken out
 * across line breaks; white space is folded to one space and dropped around
 * {@code . ( ) [ ]}; {@code java.lang.} is dropped, so that
 * {@code new java.lang.String (} reads as {@code new String(}. Every
 * character of the result knows the line it came from.
 *
 * <p>A line is allowed - left out of a check - when a comment on it carries
 * {@code seclume-allow:}, or when the line before carries one and is either
 * nothing but that comment or a statement that goes on (it does not end in
 * {@code ;}, <code>{</code> or <code>}</code>). A marker inside a string literal
 * allows nothing.
 */
final class SourceScan {

    static final String ALLOW_MARKER = "seclume-allow:";

    /** The folded code; {@link #line(int)} for where a character came from. */
    final String code;
    private final int[] lines;
    private final boolean[] allowed;

    private SourceScan(String code, int[] lines, boolean[] allowed) {
        this.code = code;
        this.lines = lines;
        this.allowed = allowed;
    }

    /** The 1-based line of the character at {@code index} of {@link #code}. */
    int line(int index) {
        return lines[Math.min(index, lines.length - 1)];
    }

    /** Whether {@code line} (1-based) is left out of the checks. */
    boolean allowed(int line) {
        return line < allowed.length && allowed[line];
    }

    static SourceScan of(String source) {
        int lineCount = 2;
        for (int i = 0; i < source.length(); i++) {
            if (source.charAt(i) == '\n') {
                lineCount++;
            }
        }
        boolean[] markerInComment = new boolean[lineCount + 1];
        boolean[] hasCode = new boolean[lineCount + 1];
        char[] lastCode = new char[lineCount + 1];
        StringBuilder raw = new StringBuilder(source.length());
        int[] rawLines = new int[source.length() + 1];
        int line = 1;
        int i = 0;
        int n = source.length();
        while (i < n) {
            char c = source.charAt(i);
            char next = i + 1 < n ? source.charAt(i + 1) : '\0';
            if (c == '/' && next == '/') {
                int end = source.indexOf('\n', i);
                end = end < 0 ? n : end;
                if (source.substring(i, end).contains(ALLOW_MARKER)) {
                    markerInComment[line] = true;
                }
                i = end;
                append(raw, rawLines, ' ', line);
            } else if (c == '/' && next == '*') {
                int end = source.indexOf("*/", i + 2);
                end = end < 0 ? n : end + 2;
                for (int j = i; j < end; j++) {
                    if (source.startsWith(ALLOW_MARKER, j)) {
                        markerInComment[line] = true;
                    }
                    if (source.charAt(j) == '\n') {
                        line++;
                    }
                }
                i = end;
                append(raw, rawLines, ' ', line);
            } else if (c == '"' && source.startsWith("\"\"\"", i)) {
                int end = source.indexOf("\"\"\"", i + 3);
                end = end < 0 ? n : end + 3;
                hasCode[line] = true;
                for (int j = i; j < end; j++) {
                    if (source.charAt(j) == '\n') {
                        line++;
                    }
                }
                append(raw, rawLines, '"', line);
                append(raw, rawLines, '"', line);
                i = end;
            } else if (c == '"' || c == '\'') {
                int j = i + 1;
                while (j < n && source.charAt(j) != c && source.charAt(j) != '\n') {
                    j += source.charAt(j) == '\\' ? 2 : 1;
                }
                hasCode[line] = true;
                lastCode[line] = c;
                append(raw, rawLines, c, line);
                append(raw, rawLines, c, line);
                i = Math.min(n, j + 1);
            } else {
                if (c == '\n') {
                    line++;
                } else if (!Character.isWhitespace(c)) {
                    hasCode[line] = true;
                    lastCode[line] = c;
                }
                append(raw, rawLines, Character.isWhitespace(c) ? ' ' : c, line);
                i++;
            }
        }
        // Folded: one space at most, none around punctuation, no java.lang.
        StringBuilder out = new StringBuilder(raw.length());
        int[] outLines = new int[raw.length() + 1];
        for (int k = 0; k < raw.length(); k++) {
            char c = raw.charAt(k);
            if (c == ' ') {
                char before = out.length() == 0 ? ' ' : out.charAt(out.length() - 1);
                int ahead = k + 1;
                while (ahead < raw.length() && raw.charAt(ahead) == ' ') {
                    ahead++;
                }
                char after = ahead < raw.length() ? raw.charAt(ahead) : ' ';
                if (before == ' ' || punctuation(before) || punctuation(after)) {
                    continue;
                }
            }
            outLines[out.length()] = rawLines[k];
            out.append(c);
        }
        String folded = out.toString();
        int[] foldedLines = Arrays.copyOf(outLines, Math.max(1, folded.length()));
        int at;
        while ((at = folded.indexOf("java.lang.")) >= 0) {
            int cut = "java.lang.".length();
            folded = folded.substring(0, at) + folded.substring(at + cut);
            System.arraycopy(foldedLines, at + cut, foldedLines, at, foldedLines.length - at - cut);
        }
        boolean[] allowed = new boolean[lineCount + 1];
        for (int l = 1; l <= lineCount; l++) {
            boolean goesOn = lastCode[l - 1] != ';' && lastCode[l - 1] != '{'
                    && lastCode[l - 1] != '}';
            allowed[l] = markerInComment[l]
                    || (l > 1 && markerInComment[l - 1] && (!hasCode[l - 1] || goesOn));
        }
        return new SourceScan(folded, foldedLines, allowed);
    }

    private static boolean punctuation(char c) {
        return c == '.' || c == '(' || c == ')' || c == '[' || c == ']';
    }

    private static void append(StringBuilder raw, int[] lines, char c, int line) {
        lines[raw.length()] = line;
        raw.append(c);
    }
}
