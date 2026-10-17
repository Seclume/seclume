package space.seclume.nats;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

import java.lang.foreign.MemorySegment;

/**
 * Locates {@code -----BEGIN ...-----} / {@code -----END ...-----} blocks and
 * bare tokens in a native {@link MemorySegment} without turning any part of the
 * buffer into a {@code String} or a {@code byte[]}.
 */
final class PemSpan {

    private static final String BEGIN = "-----BEGIN ";
    private static final String END = "-----END ";
    private static final String SEED_SUFFIX = "NKEY SEED-----";

    private PemSpan() {
    }

    /**
     * Finds the body inside {@code -----BEGIN <label>-----} and
     * {@code -----END <label>-----}, or returns {@code null} when absent.
     */
    static int[] findBlock(MemorySegment data, int length, String label) {
        String header = BEGIN + label + "-----";
        int startHeader = indexOfAscii(data, 0, length, header);
        if (startHeader < 0) {
            return null;
        }
        int contentStart = skipLine(data, startHeader + header.length(), length);
        String footer = END + label + "-----";
        int startFooter = indexOfAscii(data, contentStart, length, footer);
        if (startFooter < 0) {
            throw new IllegalArgumentException("unclosed " + header + " block");
        }
        return firstToken(data, contentStart, startFooter);
    }

    /**
     * Finds the body inside any {@code -----BEGIN <role> NKEY SEED-----} block
     * (for example {@code USER NKEY SEED}, {@code ACCOUNT NKEY SEED}, or
     * {@code NATS USER NKEY SEED}), or returns {@code null} when absent.
     */
    static int[] findSeedBlock(MemorySegment data, int length) {
        int searchFrom = 0;
        while (searchFrom < length) {
            int begin = indexOfAscii(data, searchFrom, length, BEGIN);
            if (begin < 0) {
                return null;
            }
            int lineEnd = endOfLine(data, begin, length);
            int suffix = indexOfAscii(data, begin + BEGIN.length(), lineEnd, SEED_SUFFIX);
            if (suffix >= 0) {
                int contentStart = skipLine(data, lineEnd, length);
                int endHeader = indexOfAscii(data, contentStart, length, END);
                if (endHeader < 0) {
                    throw new IllegalArgumentException("unclosed NKEY SEED block");
                }
                return firstToken(data, contentStart, endHeader);
            }
            searchFrom = skipLine(data, lineEnd, length);
        }
        return null;
    }

    /**
     * Returns the {@code [start, end)} of the first non-whitespace, non-comment
     * line in {@code [from, to)}, or {@code null} when none is present.
     */
    static int[] firstToken(MemorySegment data, int from, int to) {
        int i = from;
        while (i < to) {
            int lineEnd = endOfLine(data, i, to);
            int start = i;
            while (start < lineEnd && NKeyOff.isWhitespace(data.get(JAVA_BYTE, start))) {
                start++;
            }
            if (start < lineEnd && data.get(JAVA_BYTE, start) != '#'
                    && !(start + 1 < lineEnd
                        && data.get(JAVA_BYTE, start) == '-'
                        && data.get(JAVA_BYTE, start + 1) == '-')) {
                int end = lineEnd;
                while (end > start && NKeyOff.isWhitespace(data.get(JAVA_BYTE, end - 1))) {
                    end--;
                }
                return new int[] {start, end};
            }
            i = skipLine(data, lineEnd, to);
        }
        return null;
    }

    private static int endOfLine(MemorySegment data, int from, int to) {
        int i = from;
        while (i < to) {
            byte b = data.get(JAVA_BYTE, i);
            if (b == '\n' || b == '\r') {
                break;
            }
            i++;
        }
        return i;
    }

    private static int skipLine(MemorySegment data, int from, int to) {
        int i = endOfLine(data, from, to);
        while (i < to) {
            byte b = data.get(JAVA_BYTE, i);
            if (b != '\n' && b != '\r') {
                break;
            }
            i++;
        }
        return i;
    }

    private static int indexOfAscii(MemorySegment data, int from, int to, String needle) {
        int nLen = needle.length();
        if (from < 0 || to - from < nLen) {
            return -1;
        }
        outer:
        for (int i = from; i <= to - nLen; i++) {
            for (int j = 0; j < nLen; j++) {
                int b = data.get(JAVA_BYTE, i + j) & 0xff;
                int c = needle.charAt(j);
                if (toUpperAscii(b) != toUpperAscii(c)) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static int toUpperAscii(int c) {
        return (c >= 'a' && c <= 'z') ? (c - 32) : c;
    }
}
