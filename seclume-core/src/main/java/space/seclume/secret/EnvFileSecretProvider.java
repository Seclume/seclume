package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import space.seclume.internal.OffHeapIo;

/**
 * A key from a {@code .env}-style <b>file</b>.
 *
 * <p>Explicitly not the process environment: {@code System.getenv()} serves
 * from a {@code Map<String,String>} the JVM builds at startup and never
 * releases - the string exists there before a single line of library code runs,
 * and cannot be removed afterwards.
 *
 * <p>The file is read as a whole into an off-heap segment and searched there;
 * it never becomes a String. Recognised are lines of the form
 * {@code KEY=VALUE}, optionally with an {@code export } prefix and with single
 * or double quotes around the value. Comment lines start with {@code #}.
 */
public final class EnvFileSecretProvider implements SecretProvider {

    /** Upper bound for the file; a .env larger than this is not a .env. */
    private static final int MAX_FILE_BYTES = 1 << 20;

    private final Path path;
    private final byte[] key;
    private final int maxLength;

    /**
     * @param key the entry name, for example {@code DB_PASSWORD}. The name is
     *        not a secret and may therefore arrive as a {@code String}.
     */
    public EnvFileSecretProvider(Path path, String key, int maxLength) {
        if (key.isBlank()) {
            throw new IllegalArgumentException("key must not be blank");
        }
        if (maxLength <= 0) {
            throw new IllegalArgumentException("maxLength must be positive");
        }
        this.path = path;
        // seclume-allow: the entry name is configuration, not a secret
        this.key = key.getBytes(StandardCharsets.US_ASCII);
        this.maxLength = maxLength;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        OffHeapIo.requireNative(target);
        try (Arena arena = Arena.ofConfined()) {
            long size;
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
                size = channel.size();
                if (size == 0) {
                    throw new SecretUnavailableException(path + " is empty - the file has "
                            + "to hold lines of the form NAME=secret");
                }
                if (size > MAX_FILE_BYTES) {
                    throw new SecretUnavailableException(
                            path + " is larger than " + MAX_FILE_BYTES + " bytes");
                }
                MemorySegment file = arena.allocate(size);
                try {
                    int read = OffHeapIo.readFully(channel, file);
                    return extract(file, read, target);
                } finally {
                    // The file holds the secret in the clear.
                    file.fill((byte) 0);
                }
            }
        } catch (IOException e) {
            throw new SecretUnavailableException("cannot read " + path, e);
        }
    }

    private int extract(MemorySegment file, int length, MemorySegment target) {
        int position = 0;
        while (position < length) {
            int lineEnd = position;
            while (lineEnd < length && byteAt(file, lineEnd) != '\n') {
                lineEnd++;
            }
            int end = lineEnd;
            if (end > position && byteAt(file, end - 1) == '\r') {
                end--;
            }
            int matched = matchLine(file, position, end, target);
            if (matched >= 0) {
                return matched;
            }
            position = lineEnd + 1;
        }
        throw new SecretUnavailableException(
                "no entry named " + keyName() + " in " + path);
    }

    /** @return the length of the value written, or -1 if the line does not match */
    private int matchLine(MemorySegment file, int start, int end, MemorySegment target) {
        int position = skipSpaces(file, start, end);
        if (position >= end || byteAt(file, position) == '#') {
            return -1;
        }
        // An optional "export ".
        if (end - position > 7 && matches(file, position, "export ")) {
            position = skipSpaces(file, position + 7, end);
        }
        for (byte expected : key) {
            if (position >= end || byteAt(file, position) != expected) {
                return -1;
            }
            position++;
        }
        position = skipSpaces(file, position, end);
        if (position >= end || byteAt(file, position) != '=') {
            return -1;
        }
        position = skipSpaces(file, position + 1, end);

        int valueEnd = end;
        byte quote = position < end ? byteAt(file, position) : 0;
        if (quote == '"' || quote == '\'') {
            position++;
            valueEnd = position;
            while (valueEnd < end && byteAt(file, valueEnd) != quote) {
                valueEnd++;
            }
        } else {
            // Without quotes, trailing spaces do not count.
            while (valueEnd > position && isSpace(byteAt(file, valueEnd - 1))) {
                valueEnd--;
            }
        }

        int valueLength = valueEnd - position;
        if (valueLength <= 0) {
            throw new SecretUnavailableException(
                    "entry " + keyName() + " in " + path + " has an empty value");
        }
        if (valueLength > target.byteSize()) {
            throw new SecretUnavailableException(
                    "entry " + keyName() + " in " + path
                    + " is longer than the configured " + maxLength + " bytes");
        }
        MemorySegment.copy(file, position, target, 0, valueLength);
        return valueLength;
    }

    /** The entry name for messages - not a secret. */
    private String keyName() {
        return new String(key, StandardCharsets.US_ASCII); // seclume-allow: the entry name is configuration, not a secret
    }

    private static boolean matches(MemorySegment file, int position, String literal) {
        for (int i = 0; i < literal.length(); i++) {
            if (byteAt(file, position + i) != (byte) literal.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    private static int skipSpaces(MemorySegment file, int position, int end) {
        int i = position;
        while (i < end && isSpace(byteAt(file, i))) {
            i++;
        }
        return i;
    }

    private static boolean isSpace(byte value) {
        return value == ' ' || value == '\t';
    }

    private static byte byteAt(MemorySegment file, long offset) {
        return file.get(ValueLayout.JAVA_BYTE, offset);
    }

    @Override
    public int maxSecretLength() {
        return maxLength;
    }

    @Override
    public String toString() {
        return "EnvFileSecretProvider[path=" + path + ", key=" + keyName() + "]";
    }
}
