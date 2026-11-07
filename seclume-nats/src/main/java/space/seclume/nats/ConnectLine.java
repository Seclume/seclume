package space.seclume.nats;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

/** Where in the client's {@code CONNECT {...}} line the credential goes, and how it is written there. */
final class ConnectLine {

    private ConnectLine() {
    }

    /**
     * Where {@code placeholder} is the value of {@code "pass"} (or, for a
     * token, {@code "auth_token"}) in this CONNECT line, or -1. Only there:
     * the placeholder is on the client's heap and not a secret, and as the
     * connection's {@code "name"} - which the server logs and shows in its
     * monitoring - or as any other value it stays the placeholder. JSON
     * escapes a quote inside a string, so {@code ,"pass":"} can only be a key
     * and the start of its value.
     */
    static int credentialSlot(byte[] line, NatsSettings.AuthMode mode, String placeholder) {
        String key = mode == NatsSettings.AuthMode.TOKEN ? "auth_token" : "pass";
        byte[] needle = ("\"" + key + "\":\"" + placeholder + "\"") // seclume-allow: the key and the placeholder - not a secret
                .getBytes(StandardCharsets.US_ASCII);
        for (int from = 0; ; ) {
            int found = indexOf(line, needle, from);
            if (found < 0) {
                return -1;
            }
            if (found > 0 && (line[found - 1] == '{' || line[found - 1] == ',')) {
                return found + key.length() + 4;                 // "key":"
            }
            from = found + 1;
        }
    }

    private static int indexOf(byte[] haystack, byte[] needle, int from) {
        outer:
        for (int i = from; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /**
     * Computes the JSON-escaped UTF-8 byte length of {@code secret} in native
     * memory without creating any heap objects.
     */
    static int jsonEscapedLength(MemorySegment secret, int length) {
        int total = 0;
        for (int i = 0; i < length; i++) {
            int b = secret.get(JAVA_BYTE, i) & 0xff;
            if (b == '"' || b == '\\' || b == '/' || b == '\b' || b == '\f'
                    || b == '\n' || b == '\r' || b == '\t') {
                total += 2;
            } else if (b < 0x20) {
                total += 6;
            } else {
                total += 1;
            }
        }
        return total;
    }

    /** Writes the JSON-escaped bytes of {@code secret} into {@code out} at {@code offset}. */
    static int writeJsonEscaped(MemorySegment secret, int length,
                                MemorySegment out, int offset) {
        int p = offset;
        for (int i = 0; i < length; i++) {
            int b = secret.get(JAVA_BYTE, i) & 0xff;
            switch (b) {
                case '"' -> {
                    out.set(JAVA_BYTE, p++, (byte) '\\');
                    out.set(JAVA_BYTE, p++, (byte) '"');
                }
                case '\\' -> {
                    out.set(JAVA_BYTE, p++, (byte) '\\');
                    out.set(JAVA_BYTE, p++, (byte) '\\');
                }
                case '/' -> {
                    out.set(JAVA_BYTE, p++, (byte) '\\');
                    out.set(JAVA_BYTE, p++, (byte) '/');
                }
                case '\b' -> {
                    out.set(JAVA_BYTE, p++, (byte) '\\');
                    out.set(JAVA_BYTE, p++, (byte) 'b');
                }
                case '\f' -> {
                    out.set(JAVA_BYTE, p++, (byte) '\\');
                    out.set(JAVA_BYTE, p++, (byte) 'f');
                }
                case '\n' -> {
                    out.set(JAVA_BYTE, p++, (byte) '\\');
                    out.set(JAVA_BYTE, p++, (byte) 'n');
                }
                case '\r' -> {
                    out.set(JAVA_BYTE, p++, (byte) '\\');
                    out.set(JAVA_BYTE, p++, (byte) 'r');
                }
                case '\t' -> {
                    out.set(JAVA_BYTE, p++, (byte) '\\');
                    out.set(JAVA_BYTE, p++, (byte) 't');
                }
                default -> {
                    if (b < 0x20) {
                        out.set(JAVA_BYTE, p++, (byte) '\\');
                        out.set(JAVA_BYTE, p++, (byte) 'u');
                        out.set(JAVA_BYTE, p++, (byte) '0');
                        out.set(JAVA_BYTE, p++, (byte) '0');
                        out.set(JAVA_BYTE, p++, hexDigit((b >>> 4) & 0x0f));
                        out.set(JAVA_BYTE, p++, hexDigit(b & 0x0f));
                    } else {
                        out.set(JAVA_BYTE, p++, (byte) b);
                    }
                }
            }
        }
        return p;
    }

    private static byte hexDigit(int nibble) {
        return (byte) (nibble < 10 ? ('0' + nibble) : ('a' + (nibble - 10)));
    }
}
