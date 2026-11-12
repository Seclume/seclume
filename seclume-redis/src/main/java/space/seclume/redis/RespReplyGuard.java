package space.seclume.redis;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * Keeps the password out of what the client reads: a server that does not
 * know a command says so with its arguments - Redis 5 and what copies it
 * answer Lettuce's {@code HELLO 3 AUTH user password} with
 *
 * <pre>-ERR unknown command `HELLO`, with args beginning with: `3`, `AUTH`, `user`, `password`,</pre>
 *
 * <p>and the client makes a {@code String} of that line: an exception's
 * message, a line of its debug log. The password was written from native
 * memory and comes back on the heap. So the answers are followed from the
 * connection's first byte, as the commands are in {@link RespPasswordRewriter},
 * and for the answers that follow a password written in, an error's text is
 * searched for it before the client sees it: the password, or the beginning
 * of it where the server cut its line short, becomes {@code *}.
 *
 * <p><b>Only errors, only then.</b> A value an application reads is never
 * touched: only an error - {@code -...}, or RESP3's {@code !...} - among the
 * {@value #REPLIES} answers after a password went out. An error is held back
 * until its line is whole, so that a password split over two reads is found;
 * one longer than {@value #MAX_HELD} bytes goes through as it is.
 *
 * <p>An answer that cannot be followed - a type RESP does not have, a length
 * that is none - and nothing is looked at any more, as with the commands.
 */
final class RespReplyGuard {

    /** Answers after a password that are looked at: the handshake's, with room. */
    static final int REPLIES = 16;
    /** An error is held back until it is whole - up to this many bytes. */
    static final int MAX_HELD = 1 << 16;
    /** A beginning of the password this long is one, wherever it stands. */
    private static final int PREFIX = 4;

    /** Bytes that can be read and written in place - a Netty buffer, an array. */
    interface Bytes {
        int length();

        byte get(int index);

        void set(int index, byte value);
    }

    private enum Phase { TYPE, LINE, LINE_LF, LENGTH, LENGTH_LF, BLOB, BLOB_CR, BLOB_LF, LOST }

    private final SecretProvider[] secrets;
    private Phase phase = Phase.TYPE;
    /** Values still to come of the answer being read; 0 between answers. */
    private long pending;
    /** What a length belongs to: a blob's bytes, or the elements of an aggregate. */
    private boolean blob;
    private int perElement;
    private long number;
    private int digits;
    private boolean negative;
    private long left;
    /** Answers still to look at; set when a password is written. */
    private volatile int armed;

    RespReplyGuard(SecretProvider... secrets) {
        this.secrets = secrets.clone();
    }

    /** A password has just been written: the next answers are looked at. */
    void arm() {
        armed = REPLIES;
    }

    boolean armed() {
        return armed > 0;
    }

    /**
     * Follows {@code in} and masks what has to be. Returns how many bytes may
     * go on to the client; the rest is the beginning of an error whose end
     * has not come yet, to be given again in front of what comes next.
     */
    int scan(Bytes in) {
        int length = in.length();
        int i = 0;
        while (i < length) {
            if (phase == Phase.LOST) {
                return length;
            }
            if (phase == Phase.BLOB) {
                long skipped = Math.min(left, length - i);
                i += (int) skipped;
                left -= skipped;
                if (left == 0) {
                    phase = Phase.BLOB_CR;
                }
                continue;
            }
            if (phase == Phase.TYPE && armed > 0) {
                byte type = in.get(i);
                if ((type == '-' && lineErrorIsCut(in, i)) || (type == '!' && blobErrorIsCut(in, i))) {
                    return i;
                }
            }
            step(in.get(i++));
        }
        return length;
    }

    /**
     * A {@code -error} line at {@code at}: masked if it is whole. True if its
     * end is still to come and it is to be held back for it.
     */
    private boolean lineErrorIsCut(Bytes in, int at) {
        int end = crlf(in, at + 1);
        if (end < 0) {
            return in.length() - at < MAX_HELD;
        }
        mask(in, at + 1, end, secrets);
        return false;
    }

    /** A {@code !<length>} error at {@code at}, the same way. */
    private boolean blobErrorIsCut(Bytes in, int at) {
        int headerEnd = crlf(in, at + 1);
        if (headerEnd < 0) {
            return in.length() - at < 32;                 // a length is not longer
        }
        long size = 0;
        for (int i = at + 1; i < headerEnd; i++) {
            byte b = in.get(i);
            if (b < '0' || b > '9' || size > MAX_HELD) {
                return false;                             // no length, or too long: followed as it is
            }
            size = size * 10 + (b - '0');
        }
        long whole = (headerEnd + 2L - at) + size + 2;
        if (headerEnd == at + 1 || whole > MAX_HELD) {
            return false;
        }
        if (in.length() - at < whole) {
            return true;
        }
        mask(in, headerEnd + 2, (int) (headerEnd + 2 + size), secrets);
        return false;
    }

    private static int crlf(Bytes in, int from) {
        for (int i = from; i + 1 < in.length(); i++) {
            if (in.get(i) == '\r' && in.get(i + 1) == '\n') {
                return i;
            }
        }
        return -1;
    }

    private void step(byte b) {
        switch (phase) {
            case TYPE -> type(b);
            case LINE -> {
                if (b == '\r') {
                    phase = Phase.LINE_LF;
                }
            }
            case LINE_LF -> {
                if (b != '\n') {
                    phase = Phase.LOST;
                    return;
                }
                valueRead();
            }
            case LENGTH -> {
                if (b == '-' && digits == 0 && !negative) {
                    negative = true;
                } else if (b >= '0' && b <= '9' && digits < 18) {
                    number = number * 10 + (b - '0');
                    digits++;
                } else if (b == '\r' && digits > 0) {
                    phase = Phase.LENGTH_LF;
                } else {
                    phase = Phase.LOST;                   // "$?" - a streamed string - among them
                }
            }
            case LENGTH_LF -> {
                if (b != '\n') {
                    phase = Phase.LOST;
                    return;
                }
                if (blob) {
                    if (negative) {
                        valueRead();                      // RESP2's null
                    } else {
                        left = number;
                        phase = left == 0 ? Phase.BLOB_CR : Phase.BLOB;
                    }
                } else {
                    if (!negative) {
                        pending += number * perElement;
                    }
                    valueRead();
                }
            }
            case BLOB -> {
                if (--left == 0) {
                    phase = Phase.BLOB_CR;
                }
            }
            case BLOB_CR -> phase = b == '\r' ? Phase.BLOB_LF : Phase.LOST;
            case BLOB_LF -> {
                if (b != '\n') {
                    phase = Phase.LOST;
                    return;
                }
                valueRead();
            }
            case LOST -> {
                // nothing can be told any more
            }
        }
    }

    private void type(byte b) {
        if (pending == 0) {
            pending = 1;
        }
        switch (b) {
            case '+', '-', ':', '_', '#', ',', '(' -> {
                pending--;
                phase = Phase.LINE;
            }
            case '$', '=', '!' -> {
                pending--;
                length(true, 0);
            }
            case '*', '~', '>' -> {
                pending--;
                length(false, 1);
            }
            case '%' -> {
                pending--;
                length(false, 2);
            }
            // An attribute's pairs come before the value they belong to, which still counts.
            case '|' -> length(false, 2);
            default -> phase = Phase.LOST;
        }
    }

    private void length(boolean ofBlob, int elements) {
        blob = ofBlob;
        perElement = elements;
        number = 0;
        digits = 0;
        negative = false;
        phase = Phase.LENGTH;
    }

    /** A value, or an aggregate's header, is through: perhaps the whole answer is. */
    private void valueRead() {
        phase = Phase.TYPE;
        if (pending == 0 && armed > 0) {
            armed--;
        }
    }

    /**
     * {@code *} over every place in {@code in} from {@code from} to {@code to}
     * where one of the secrets stands: all of it, its first {@value #PREFIX}
     * bytes or more, or any beginning of it after a quote that only quotes
     * and commas follow to the end - a quoted argument where a server cut its
     * line short, as Redis does at 128 bytes. If a secret
     * cannot be read, nothing can be compared: everything after the error's
     * first word is masked.
     */
    static void mask(Bytes in, int from, int to, SecretProvider... secrets) {
        for (SecretProvider provider : secrets) {
            if (provider == null) {
                continue;
            }
            try (SecretScope secret = SecretScope.fromProvider(provider)) {
                mask(in, from, to, secret.segment(), secret.length());
            } catch (RuntimeException unreadable) {
                int word = from;
                while (word < to && in.get(word) != ' ') {
                    word++;
                }
                for (int i = word + 1; i < to; i++) {
                    in.set(i, (byte) '*');
                }
                return;
            }
        }
    }

    private static void mask(Bytes in, int from, int to, MemorySegment secret, int length) {
        if (length == 0) {
            return;
        }
        for (int i = from; i < to; i++) {
            int same = 0;
            while (same < length && i + same < to
                    && in.get(i + same) == secret.get(ValueLayout.JAVA_BYTE, same)) {
                same++;
            }
            if (same == length || same >= PREFIX
                    || (same > 0 && i > from && quote(in.get(i - 1)) && onlyClosing(in, i + same, to))) {
                for (int j = i; j < i + same; j++) {
                    in.set(j, (byte) '*');
                }
                i += same - 1;
            }
        }
    }

    private static boolean quote(byte b) {
        return b == '`' || b == '\'' || b == '"';
    }

    /** Whether nothing but what closes a quoted argument follows to the end. */
    private static boolean onlyClosing(Bytes in, int from, int to) {
        for (int i = from; i < to; i++) {
            byte b = in.get(i);
            if (!quote(b) && b != ',' && b != ' ') {
                return false;
            }
        }
        return true;
    }
}
