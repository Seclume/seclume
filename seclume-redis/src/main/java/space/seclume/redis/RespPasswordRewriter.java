package space.seclume.redis;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat; // seclume-allow: a random placeholder - public

import space.seclume.internal.SeclumeSslEngine;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * Finds the placeholder a Redis client was given for its password, where the
 * client writes it - the password argument of {@code AUTH [user] password} or
 * of {@code HELLO protover AUTH user password}, a RESP bulk string of its own:
 * {@code $<length>\r\n<placeholder>} - and replaces it with
 * {@code $<length>\r\n<password>}, both written in native memory from the
 * password read for this one command. Every other byte goes through as the
 * client wrote it.
 *
 * <p><b>Only there.</b> The placeholder is random per client, but it is not a
 * secret: the client holds it as its password, on the heap, and a heap dump
 * gives it away. Replaced wherever it stood as a bulk string, a placeholder
 * that came back as data - a value an application caches, a session field -
 * would have been sent to the server with the password in its place, for
 * whoever reads that value next. So the rewriter follows the RESP commands the
 * client writes, from the connection's first byte, and only the password slot
 * of an {@code AUTH} or {@code HELLO ... AUTH} is a place for the password.
 * Anything it cannot follow - an inline command, a malformed length - and it
 * stops replacing for the rest of the connection: the placeholder then reaches
 * the server as it is, and the login fails rather than the password going
 * somewhere it should not.
 *
 * <p>Every byte the connection writes has to pass {@link #next} or
 * {@link #observe}, in order - one rewriter per connection.
 */
final class RespPasswordRewriter implements SeclumeSslEngine.Outgoing {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int MAX_DIGITS = 10;

    private record Binding(byte[] placeholder, SecretProvider secret) {
    }

    private final Binding[] bindings;
    /** The server, for the event that says the password was written in. */
    private final String where;

    RespPasswordRewriter(String placeholder, SecretProvider secret) {
        this(placeholder, secret, null, null, "");
    }

    RespPasswordRewriter(String placeholder, SecretProvider secret, String where) {
        this(placeholder, secret, null, null, where);
    }

    RespPasswordRewriter(String placeholder, SecretProvider secret, String sentinelPlaceholder,
                         SecretProvider sentinelSecret, String where) {
        // seclume-allow: the placeholder, not the password
        Binding main = new Binding(placeholder.getBytes(StandardCharsets.US_ASCII), secret);
        if (sentinelPlaceholder != null && sentinelSecret != null) {
            // seclume-allow: the placeholder, not the password
            Binding sentinel = new Binding(sentinelPlaceholder.getBytes(StandardCharsets.US_ASCII),
                    sentinelSecret);
            this.bindings = new Binding[] {main, sentinel};
        } else {
            this.bindings = new Binding[] {main};
        }
        this.where = where;
    }

    /** A new random placeholder. */
    static String newPlaceholder() {
        byte[] random = new byte[16];
        RANDOM.nextBytes(random);
        return "seclume-redis-" + HexFormat.of().formatHex(random); // seclume-allow: a random placeholder - public
    }

    /** Whether {@code plain} holds any of our placeholders anywhere from its position. */
    boolean contains(ByteBuffer plain) {
        int from = plain.position();
        int to = plain.limit();
        for (Binding binding : bindings) {
            if (indexOf(plain, from, to, binding.placeholder) >= 0) {
                return true;
            }
        }
        return false;
    }

    // ---- following the commands --------------------------------------------

    private enum State { COMMAND, ARRAY_LENGTH, ARRAY_LF, BULK, BULK_LENGTH, BULK_LF, DATA,
        DATA_CR, DATA_LF, LOST }

    private State state = State.COMMAND;
    private long number;
    private int digits;
    /** Elements of the current command, and which one is being read. */
    private long elements;
    private long index;
    /** Bytes of the current bulk string still to come. */
    private long left;
    /** The first bytes of the command name and of its third element, upper case. */
    private final byte[] name = new byte[6];
    private int nameLength;
    private final byte[] third = new byte[5];
    private int thirdLength;

    /** Follows bytes that are written as they are - a write without the placeholder. */
    void observe(ByteBuffer plain) {
        for (int i = plain.position(); i < plain.limit(); i++) {
            step(plain.get(i));
        }
    }

    @Override
    public Step next(ByteBuffer plain) throws IOException {
        int from = plain.position();
        int to = Math.min(plain.limit(), from + SeclumeSslEngine.MAX_PLAINTEXT);
        for (int i = from; i < to; i++) {
            if (state == State.BULK && passwordSlot()) {
                if (i > from) {
                    return Step.unchanged(i - from);      // up to the password's header
                }
                Step replaced = replace(plain, i);
                if (replaced != null) {
                    return replaced;
                }
            }
            step(plain.get(i));
        }
        return Step.unchanged(to - from);
    }

    /** The password argument comes next: AUTH [user] password, HELLO v AUTH user password. */
    private boolean passwordSlot() {
        if (is(name, nameLength, "AUTH")) {
            return (elements == 2 && index == 1) || (elements == 3 && index == 2);
        }
        return is(name, nameLength, "HELLO") && elements >= 5 && index == 4
                && is(third, thirdLength, "AUTH");
    }

    /**
     * The placeholder as the bulk string at {@code at}, whole in this buffer,
     * replaced - or null, and the bytes are followed as any others.
     */
    private Step replace(ByteBuffer plain, int at) {
        for (Binding binding : bindings) {
            byte[] placeholder = binding.placeholder;
            byte[] header = ("$" + placeholder.length + "\r\n")
                    .getBytes(StandardCharsets.US_ASCII); // seclume-allow: a length, no secret
            int total = header.length + placeholder.length;
            if (plain.limit() - at < total || !matches(plain, at, header)
                    || !matches(plain, at + header.length, placeholder)) {
                continue;
            }
            space.seclume.jfr.Observed.secretUse("redis", where, "AUTH");
            Step step = Step.replace(total, bulk(binding.secret));
            // What follows is the CRLF the client wrote after the placeholder.
            state = State.DATA_CR;
            return step;
        }
        return null;
    }

    private void step(byte b) {
        switch (state) {
            case COMMAND -> {
                if (b != '*') {
                    state = State.LOST;
                    return;
                }
                number = 0;
                digits = 0;
                state = State.ARRAY_LENGTH;
            }
            case ARRAY_LENGTH, BULK_LENGTH -> {
                if (b >= '0' && b <= '9' && digits < MAX_DIGITS) {
                    number = number * 10 + (b - '0');
                    digits++;
                } else if (b == '\r' && digits > 0) {
                    state = state == State.ARRAY_LENGTH ? State.ARRAY_LF : State.BULK_LF;
                } else {
                    state = State.LOST;
                }
            }
            case ARRAY_LF -> {
                if (b != '\n') {
                    state = State.LOST;
                    return;
                }
                elements = number;
                index = 0;
                nameLength = 0;
                thirdLength = 0;
                state = elements == 0 ? State.COMMAND : State.BULK;
            }
            case BULK -> {
                if (b != '$') {
                    state = State.LOST;
                    return;
                }
                number = 0;
                digits = 0;
                state = State.BULK_LENGTH;
            }
            case BULK_LF -> {
                if (b != '\n') {
                    state = State.LOST;
                    return;
                }
                left = number;
                state = left == 0 ? State.DATA_CR : State.DATA;
            }
            case DATA -> {
                remember(b);
                if (--left == 0) {
                    state = State.DATA_CR;
                }
            }
            case DATA_CR -> state = b == '\r' ? State.DATA_LF : State.LOST;
            case DATA_LF -> {
                if (b != '\n') {
                    state = State.LOST;
                    return;
                }
                index++;
                state = index == elements ? State.COMMAND : State.BULK;
            }
            case LOST -> {
                // Nothing can be told any more; nothing is replaced any more.
            }
        }
    }

    /** Keeps the first bytes of the command name and of the third element. */
    private void remember(byte b) {
        byte upper = b >= 'a' && b <= 'z' ? (byte) (b - 32) : b;
        if (index == 0 && nameLength < name.length) {
            name[nameLength++] = upper;
        } else if (index == 2 && thirdLength < third.length) {
            third[thirdLength++] = upper;
        }
    }

    private static boolean is(byte[] kept, int length, String word) {
        if (length != word.length()) {
            return false;
        }
        for (int i = 0; i < length; i++) {
            if (kept[i] != word.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    private static boolean matches(ByteBuffer in, int at, byte[] expected) {
        for (int j = 0; j < expected.length; j++) {
            if (in.get(at + j) != expected[j]) {
                return false;
            }
        }
        return true;
    }

    private static SecretScope bulk(SecretProvider secret) {
        try (SecretScope password = SecretScope.fromProvider(secret)) {
            int length = password.length();
            int digits = 1;
            for (int rest = length / 10; rest > 0; rest /= 10) {
                digits++;
            }
            SecretScope out = SecretScope.allocateShared(1 + digits + 2 + length);
            MemorySegment o = out.segment();
            o.set(ValueLayout.JAVA_BYTE, 0, (byte) '$');
            for (int i = digits, rest = length; i >= 1; i--, rest /= 10) {
                o.set(ValueLayout.JAVA_BYTE, i, (byte) ('0' + rest % 10));
            }
            o.set(ValueLayout.JAVA_BYTE, 1 + digits, (byte) '\r');
            o.set(ValueLayout.JAVA_BYTE, 2 + digits, (byte) '\n');
            MemorySegment.copy(password.segment(), 0, o, 3 + digits, length);
            out.length(3 + digits + length);
            return out;
        }
    }

    private static int indexOf(ByteBuffer in, int from, int to, byte[] placeholder) {
        outer:
        for (int i = from; i <= to - placeholder.length; i++) {
            for (int j = 0; j < placeholder.length; j++) {
                if (in.get(i + j) != placeholder[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
