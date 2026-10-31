package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;

import space.seclume.crypto.ConstantTime;
import space.seclume.crypto.Digest;
import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Shamir;
import space.seclume.internal.Entropy;

/**
 * Shares of a secret, any {@code k} of {@code n} of which give it back - the
 * format, the split into files, and the combination with its check.
 *
 * <h2>The format</h2>
 *
 * <p>One share is one line of ASCII:
 *
 * <pre>
 *   seclume-share-1.&lt;split&gt;.&lt;k&gt;.&lt;x&gt;.&lt;y&gt;.&lt;crc&gt;
 * </pre>
 *
 * <ul>
 *   <li>{@code split} - 16 hex digits, drawn at random for each split: shares
 *       of different splits are told apart before they are combined into
 *       nonsense;</li>
 *   <li>{@code k} - how many shares it takes, {@code x} - this share's number,
 *       1 to 255, both decimal;</li>
 *   <li>{@code y} - the share's bytes, hex: the secret's length plus 16;</li>
 *   <li>{@code crc} - CRC-32 of everything before its dot, 8 hex digits, so that
 *       a share typed in by hand with one wrong digit is refused for what it is,
 *       not combined.</li>
 * </ul>
 *
 * <p>What is shared is not the secret alone but the secret followed by 16 bytes
 * of {@code SHA-256("seclume-share-1" || split || secret)}. Combined from fewer
 * than {@code k} shares, or from a damaged one that slipped past the CRC, the
 * value comes out wrong - and the check says so, instead of a wrong key opening
 * nothing much later. The check is only ever seen by whoever already holds
 * {@code k} shares, that is: the secret.
 *
 * <h2>Off the heap</h2>
 *
 * <p>A share is a secret: with {@code k - 1} others it is the whole thing. It
 * is read by a {@link SecretProvider}, parsed where it lies in native memory,
 * and its bytes go into a segment that is zeroed afterwards; the combined
 * secret is written into the caller's target and nowhere else. On the way out,
 * {@link #split} writes each share from native memory into its own file.
 */
public final class ShamirShares {

    /** The secret's length is bounded so that a share stays a line someone can handle. */
    public static final int MAX_SECRET = 1024;

    static final int CHECK = 16;
    private static final String MAGIC = "seclume-share-1";
    private static final int CRC_DIGITS = 8;

    private ShamirShares() {
    }

    /** What a share says about itself; its bytes stay in {@code y}, native. */
    record Share(long split, int threshold, int x, MemorySegment y, int length) {
    }

    /** The longest share for a secret of {@code secretLength} bytes, newline included. */
    static int textLength(int secretLength) {
        return MAGIC.length() + 1 + 16 + 1 + 3 + 1 + 3 + 1
                + 2 * (secretLength + CHECK) + 1 + CRC_DIGITS + 1;
    }

    /**
     * Splits the secret {@code source} gives into {@code shares} files in
     * {@code directory} - {@code share-1-of-5.txt} and so on, readable by the
     * owner only where the file system knows that - any {@code threshold} of
     * which give it back. Existing files are not overwritten. Give each file
     * to a different person, and delete it here.
     */
    public static List<Path> split(SecretProvider source, int threshold, int shares,
            Path directory) throws IOException {
        long split;
        List<Path> written = new ArrayList<>();
        try (Arena arena = Arena.ofConfined();
             SecretScope secret = SecretScope.fromProvider(source)) {
            int length = secret.length();
            if (length < 1 || length > MAX_SECRET) {
                throw new SecretUnavailableException("a secret of 1 to " + MAX_SECRET
                        + " bytes can be split, not " + length);
            }
            MemorySegment id = arena.allocate(8);
            Entropy.fill(id);
            split = id.get(ValueLayout.JAVA_LONG_UNALIGNED.withOrder(java.nio.ByteOrder.BIG_ENDIAN), 0);
            int payload = length + CHECK;
            MemorySegment plain = arena.allocate(payload);
            MemorySegment[] ys = new MemorySegment[shares];
            MemorySegment text = arena.allocate(textLength(length));
            try {
                MemorySegment.copy(secret.segment(), 0, plain, 0, length);
                check(split, plain, length, plain, length);
                for (int i = 0; i < shares; i++) {
                    ys[i] = arena.allocate(payload);
                }
                Shamir.split(plain, 0, payload, threshold, shares, ys, 0);
                Files.createDirectories(directory);
                for (int i = 0; i < shares; i++) {
                    int n = encode(split, threshold, i + 1, ys[i], payload, text);
                    Path file = directory.resolve("share-" + (i + 1) + "-of-" + shares + ".txt");
                    write(file, text, n);
                    written.add(file);
                }
            } finally {
                plain.fill((byte) 0);
                text.fill((byte) 0);
                for (MemorySegment y : ys) {
                    if (y != null) {
                        y.fill((byte) 0);
                    }
                }
            }
        }
        return written;
    }

    private static void write(Path file, MemorySegment text, int length) throws IOException {
        if (Files.exists(file)) {
            throw new FileAlreadyExistsException(file.toString(), null,
                    "a share is never overwritten");
        }
        try {
            Files.createFile(file, PosixFilePermissions.asFileAttribute(
                    PosixFilePermissions.fromString("rw-------")));
        } catch (UnsupportedOperationException e) {
            Files.createFile(file);
        }
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
            ByteBuffer view = text.asSlice(0, length).asByteBuffer();
            while (view.hasRemaining()) {
                channel.write(view);
            }
        }
    }

    /**
     * Writes the check of the secret in {@code secret[0..length)} to
     * {@code out} at {@code outOffset}: the first 16 bytes of
     * {@code SHA-256(MAGIC || split || secret)}.
     */
    static void check(long split, MemorySegment secret, int length, MemorySegment out,
            long outOffset) {
        try (Arena arena = Arena.ofConfined(); Digest digest = HashAlgorithm.SHA_256.newDigest()) {
            MemorySegment prefix = arena.allocate(MAGIC.length() + 8L);
            for (int i = 0; i < MAGIC.length(); i++) {
                prefix.set(ValueLayout.JAVA_BYTE, i, (byte) MAGIC.charAt(i));
            }
            prefix.set(ValueLayout.JAVA_LONG_UNALIGNED.withOrder(java.nio.ByteOrder.BIG_ENDIAN),
                    MAGIC.length(), split);
            MemorySegment hash = arena.allocate(32);
            digest.update(prefix, 0, prefix.byteSize());
            digest.update(secret, 0, length);
            digest.digest(hash, 0);
            MemorySegment.copy(hash, 0, out, outOffset, CHECK);
            hash.fill((byte) 0);
        }
    }

    /** Writes one share's line into {@code text}; returns its length. */
    static int encode(long split, int threshold, int x, MemorySegment y, int length,
            MemorySegment text) {
        int p = 0;
        for (int i = 0; i < MAGIC.length(); i++) {
            text.set(ValueLayout.JAVA_BYTE, p++, (byte) MAGIC.charAt(i));
        }
        text.set(ValueLayout.JAVA_BYTE, p++, (byte) '.');
        for (int shift = 60; shift >= 0; shift -= 4) {
            text.set(ValueLayout.JAVA_BYTE, p++, hexDigit((int) (split >>> shift) & 0xf));
        }
        text.set(ValueLayout.JAVA_BYTE, p++, (byte) '.');
        p = decimal(threshold, text, p);
        text.set(ValueLayout.JAVA_BYTE, p++, (byte) '.');
        p = decimal(x, text, p);
        text.set(ValueLayout.JAVA_BYTE, p++, (byte) '.');
        for (int i = 0; i < length; i++) {
            int b = y.get(ValueLayout.JAVA_BYTE, i) & 0xff;
            text.set(ValueLayout.JAVA_BYTE, p++, hexDigit(b >>> 4));
            text.set(ValueLayout.JAVA_BYTE, p++, hexDigit(b & 0xf));
        }
        int crc = crc32(text, p);
        text.set(ValueLayout.JAVA_BYTE, p++, (byte) '.');
        for (int shift = 28; shift >= 0; shift -= 4) {
            text.set(ValueLayout.JAVA_BYTE, p++, hexDigit((crc >>> shift) & 0xf));
        }
        text.set(ValueLayout.JAVA_BYTE, p++, (byte) '\n');
        return p;
    }

    /**
     * Reads one share from {@code text[0..length)}, a trailing line break
     * allowed; its bytes go into {@code y}, which must hold
     * {@link #MAX_SECRET} + 16. Anything malformed is a
     * {@link SecretUnavailableException} that says what, never which digits.
     */
    static Share parse(MemorySegment text, int length, MemorySegment y) {
        while (length > 0) {
            byte last = text.get(ValueLayout.JAVA_BYTE, length - 1);
            if (last != '\n' && last != '\r' && last != ' ') {
                break;
            }
            length--;
        }
        if (length < MAGIC.length() + 1 + CRC_DIGITS + 1) {
            throw refused("too short to be a share");
        }
        for (int i = 0; i < MAGIC.length(); i++) {
            if (text.get(ValueLayout.JAVA_BYTE, i) != MAGIC.charAt(i)) {
                throw refused("not a seclume share (it starts with something other than "
                        + MAGIC + ")");
            }
        }
        int crcDot = length - CRC_DIGITS - 1;
        if (text.get(ValueLayout.JAVA_BYTE, crcDot) != '.') {
            throw refused("its checksum is missing");
        }
        long crc = hex(text, crcDot + 1, CRC_DIGITS);
        if (crc < 0 || (int) crc != crc32(text, crcDot)) {
            throw refused("its checksum does not match - a digit is wrong or missing");
        }
        int p = MAGIC.length();
        p = expect(text, p, crcDot, '.');
        long split = 0;
        for (int i = 0; i < 16; i++) {
            int d = p < crcDot ? hexValue(text.get(ValueLayout.JAVA_BYTE, p)) : -1;
            if (d < 0) {
                throw refused("its split identifier is not 16 hex digits");
            }
            split = (split << 4) | d;
            p++;
        }
        p = expect(text, p, crcDot, '.');
        int[] parsed = new int[1];
        p = decimal(text, p, crcDot, parsed, "its threshold");
        int threshold = parsed[0];
        p = expect(text, p, crcDot, '.');
        p = decimal(text, p, crcDot, parsed, "its number");
        int x = parsed[0];
        p = expect(text, p, crcDot, '.');
        if (threshold < 2 || threshold > Shamir.MAX_SHARES) {
            throw refused("its threshold is " + threshold + ", not 2 to " + Shamir.MAX_SHARES);
        }
        if (x < 1 || x > Shamir.MAX_SHARES) {
            throw refused("its number is " + x + ", not 1 to " + Shamir.MAX_SHARES);
        }
        int digits = crcDot - p;
        if (digits < 2 * (CHECK + 1) || digits % 2 != 0 || digits / 2 > MAX_SECRET + CHECK) {
            throw refused("its value is " + digits + " hex digits, not an even number from "
                    + 2 * (CHECK + 1) + " to " + 2 * (MAX_SECRET + CHECK));
        }
        if (y.byteSize() < digits / 2) {
            throw refused("its value does not fit");
        }
        for (int i = 0; i < digits / 2; i++) {
            int hi = hexValue(text.get(ValueLayout.JAVA_BYTE, p + 2L * i));
            int lo = hexValue(text.get(ValueLayout.JAVA_BYTE, p + 2L * i + 1));
            if ((hi | lo) < 0) {
                throw refused("its value is not hex");
            }
            y.set(ValueLayout.JAVA_BYTE, i, (byte) (hi << 4 | lo));
        }
        return new Share(split, threshold, x, y, digits / 2);
    }

    /**
     * Combines {@code shares} - exactly as many as their threshold, of one
     * split, with distinct numbers - and writes the secret into {@code target}.
     * Returns its length. A combination that does not pass the check is refused.
     */
    static int combine(List<Share> shares, MemorySegment target) {
        Share first = shares.get(0);
        if (shares.size() != first.threshold()) {
            throw refused(first.threshold() + " shares are needed, " + shares.size()
                    + " were given");
        }
        int[] xs = new int[shares.size()];
        MemorySegment[] ys = new MemorySegment[shares.size()];
        for (int i = 0; i < shares.size(); i++) {
            Share share = shares.get(i);
            if (share.split() != first.split()) {
                throw refused("share " + share.x() + " belongs to another split than share "
                        + first.x());
            }
            if (share.threshold() != first.threshold() || share.length() != first.length()) {
                throw refused("share " + share.x() + " does not match share " + first.x()
                        + " in threshold or length");
            }
            for (int j = 0; j < i; j++) {
                if (xs[j] == share.x()) {
                    throw refused("share " + share.x() + " is there twice");
                }
            }
            xs[i] = share.x();
            ys[i] = share.y();
        }
        int length = first.length() - CHECK;
        if (length > target.byteSize()) {
            throw refused("the secret is " + length + " bytes and does not fit into the "
                    + target.byteSize() + " bytes provided");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment plain = arena.allocate(first.length());
            MemorySegment expected = arena.allocate(CHECK);
            try {
                Shamir.combine(xs, ys, 0, first.length(), plain, 0);
                check(first.split(), plain, length, expected, 0);
                if (!ConstantTime.equals(expected, 0, plain, length, CHECK)) {
                    throw refused("the shares do not give back what was split - one of them "
                            + "is damaged or does not belong to the others");
                }
                MemorySegment.copy(plain, 0, target, 0, length);
                return length;
            } finally {
                plain.fill((byte) 0);
                expected.fill((byte) 0);
            }
        }
    }

    private static SecretUnavailableException refused(String why) {
        return new SecretUnavailableException("a Shamir share is refused: " + why);
    }

    private static int expect(MemorySegment text, int p, int end, char c) {
        if (p >= end || text.get(ValueLayout.JAVA_BYTE, p) != c) {
            throw refused("its fields are not separated by '" + c + "' where they should be");
        }
        return p + 1;
    }

    private static int decimal(MemorySegment text, int p, int end, int[] out, String what) {
        int value = 0;
        int digits = 0;
        while (p < end && digits < 4) {
            byte c = text.get(ValueLayout.JAVA_BYTE, p);
            if (c < '0' || c > '9') {
                break;
            }
            value = value * 10 + (c - '0');
            digits++;
            p++;
        }
        if (digits == 0 || digits > 3) {
            throw refused(what + " is not a number of one to three digits");
        }
        out[0] = value;
        return p;
    }

    private static int decimal(int value, MemorySegment text, int p) {
        if (value >= 100) {
            text.set(ValueLayout.JAVA_BYTE, p++, (byte) ('0' + value / 100));
        }
        if (value >= 10) {
            text.set(ValueLayout.JAVA_BYTE, p++, (byte) ('0' + value / 10 % 10));
        }
        text.set(ValueLayout.JAVA_BYTE, p++, (byte) ('0' + value % 10));
        return p;
    }

    private static long hex(MemorySegment text, int p, int digits) {
        long value = 0;
        for (int i = 0; i < digits; i++) {
            int d = hexValue(text.get(ValueLayout.JAVA_BYTE, p + i));
            if (d < 0) {
                return -1;
            }
            value = (value << 4) | d;
        }
        return value;
    }

    /** Lower-case hex out; branch-free on the value. */
    private static byte hexDigit(int nibble) {
        // '0' + n for n < 10, 'a' + n - 10 otherwise: add 39 when n > 9.
        int over = (9 - nibble) >> 31;
        return (byte) ('0' + nibble + (over & 39));
    }

    /**
     * Either case in; -1 for anything else. Without branches on the digit: a
     * share's digits are secret, and how long reading them takes should not
     * say which they are.
     */
    static int hexValue(byte b) {
        int c = b & 0xff;
        int digit = c - '0';
        int letter = (c | 0x20) - 'a' + 10;
        int isDigit = ~((digit | (9 - digit)) >> 31);
        int isLetter = ~(((letter - 10) | (15 - letter)) >> 31);
        return (digit & isDigit) | (letter & isLetter) | ~(isDigit | isLetter);
    }

    /** CRC-32 (IEEE) of {@code text[0..length)}. */
    static int crc32(MemorySegment text, int length) {
        int crc = 0xffffffff;
        for (int i = 0; i < length; i++) {
            crc ^= text.get(ValueLayout.JAVA_BYTE, i) & 0xff;
            for (int bit = 0; bit < 8; bit++) {
                crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
            }
        }
        return ~crc;
    }
}
